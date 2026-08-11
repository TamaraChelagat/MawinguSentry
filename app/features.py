"""
Feature engineering for CloudSentry / MawinguSentry.

Mirrors the fit_transform / transform split used in FraudDetectPro's
SafeCreditCardFeatureEngineer, adapted for sequential, per-principal
CloudTrail-style events rather than independent transaction rows.

Key design choice: baselines (known IPs, known regions, typical call
rate) are learned ONLY from events labeled "benign" during fit. This
matters for correctness -- in a real deployment you baseline "normal"
behavior from a trusted history window, not from data that may already
contain attacks. Mixing attack events into the baseline would let an
attacker's own behavior get treated as normal.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

SENSITIVE_EVENTS = {"AttachUserPolicy", "PutBucketAcl", "PutBucketPolicy", "CreateAccessKey"}
RECON_EVENTS = {"ListBuckets", "DescribeInstances", "ListRoles", "DescribeSecurityGroups", "DescribeLogGroups"}
KNOWN_EVENT_NAMES = sorted(
    {
        "ConsoleLogin",
        "DescribeInstances",
        "ListBuckets",
        "GetObject",
        "AssumeRole",
        "DescribeSecurityGroups",
        "ListRoles",
        "GetCallerIdentity",
        "DescribeLogGroups",
        "PutMetricData",
        "AttachUserPolicy",
        "PutBucketAcl",
        "PutBucketPolicy",
        "CreateAccessKey",
    }
)

BURST_WINDOW_SECONDS = 300  # 5 minutes
RAPID_TRAVEL_SECONDS = 600  # 10 minutes -- window for "impossible travel" style flags
OFF_HOURS = set(range(0, 6)) | set(range(22, 24))


class CloudEventFeatureEngineer:
    """Turns raw CloudTrail-style event dicts into a model-ready feature DataFrame."""

    def __init__(self):
        self.principal_baselines: Dict[str, Dict] = {}
        self.is_fitted = False
        self.feature_names: List[str] = []

    # -- public API ----------------------------------------------------------

    def fit_transform(self, events: List[Dict]) -> pd.DataFrame:
        df = self._events_to_df(events)
        self._learn_baselines(df)
        self.is_fitted = True
        features = self._compute_features(df)
        self.feature_names = list(features.columns)
        logger.info(f"Fitted on {len(df)} events, baselines learned for {len(self.principal_baselines)} principals")
        logger.info(f"Feature columns ({len(self.feature_names)}): {self.feature_names}")
        return features

    def transform(self, events: List[Dict]) -> pd.DataFrame:
        if not self.is_fitted:
            raise ValueError("Must call fit_transform before transform")
        df = self._events_to_df(events)
        features = self._compute_features(df)
        # Keep column set identical to what the model was trained on
        for col in self.feature_names:
            if col not in features.columns:
                features[col] = 0
        return features[self.feature_names]

    # -- internals -------------------------------------------------------------

    @staticmethod
    def _events_to_df(events: List[Dict]) -> pd.DataFrame:
        df = pd.DataFrame(events)
        df["_orig_idx"] = range(len(df))
        df["eventTime"] = pd.to_datetime(df["eventTime"])
        df["principal"] = df["userIdentity"].apply(lambda u: u["arn"] if isinstance(u, dict) else u)
        df["ip_prefix"] = df["sourceIPAddress"].apply(lambda ip: ".".join(str(ip).split(".")[:2]))
        df = df.sort_values(["principal", "eventTime"])
        return df

    def _learn_baselines(self, df: pd.DataFrame) -> None:
        """Learn known IPs/regions/typical call rate per principal, from benign events only."""
        benign = df[df.get("label", "benign") == "benign"] if "label" in df.columns else df
        for principal, group in benign.groupby("principal"):
            self.principal_baselines[principal] = {
                "known_ips": set(group["ip_prefix"]),
                "known_regions": set(group["awsRegion"]),
                "known_event_names": set(group["eventName"]),
            }

    def _baseline_for(self, principal: str) -> Dict:
        return self.principal_baselines.get(
            principal, {"known_ips": set(), "known_regions": set(), "known_event_names": set()}
        )

    def _compute_features(self, df: pd.DataFrame) -> pd.DataFrame:
        rows = []
        for principal, group in df.groupby("principal"):
            baseline = self._baseline_for(principal)
            group = group.sort_values("eventTime").reset_index(drop=True)
            prev_time: Optional[datetime] = None
            prev_region: Optional[str] = None
            recent_times: List[datetime] = []

            for _, row in group.iterrows():
                t = row["eventTime"].to_pydatetime()
                if t.tzinfo is None:
                    t = t.replace(tzinfo=timezone.utc)

                seconds_since_last = (t - prev_time).total_seconds() if prev_time else 999_999.0

                # burst detection: count prior events by this principal within the window
                recent_times = [rt for rt in recent_times if (t - rt).total_seconds() <= BURST_WINDOW_SECONDS]
                events_in_window = len(recent_times)
                recent_times.append(t)

                region_changed = prev_region is not None and row["awsRegion"] != prev_region
                rapid_region_change = region_changed and seconds_since_last <= RAPID_TRAVEL_SECONDS
                rapid_ip_change = (
                    row["ip_prefix"] not in baseline["known_ips"] and seconds_since_last <= RAPID_TRAVEL_SECONDS
                )

                rows.append(
                    {
                        "_orig_idx": row["_orig_idx"],
                        "hour_of_day": t.hour,
                        "is_off_hours": int(t.hour in OFF_HOURS),
                        "seconds_since_last_event": min(seconds_since_last, 999_999.0),
                        "events_in_last_5min": events_in_window,
                        "is_new_ip_for_principal": int(row["ip_prefix"] not in baseline["known_ips"]),
                        "is_new_region_for_principal": int(row["awsRegion"] not in baseline["known_regions"]),
                        "is_new_event_type_for_principal": int(row["eventName"] not in baseline["known_event_names"]),
                        "is_sensitive_call": int(row["eventName"] in SENSITIVE_EVENTS),
                        "is_recon_call": int(row["eventName"] in RECON_EVENTS),
                        "rapid_region_change": int(rapid_region_change),
                        # More realistic "impossible travel" signal: source IP changed to one never
                        # seen for this principal, shortly after their last action.
                        "rapid_ip_change": int(rapid_ip_change),
                        **{f"event_is_{name}": int(row["eventName"] == name) for name in KNOWN_EVENT_NAMES},
                    }
                )
                prev_time = t
                prev_region = row["awsRegion"]

        features = pd.DataFrame(rows).sort_values("_orig_idx").drop(columns="_orig_idx").reset_index(drop=True)
        return features


def main():
    """Quick manual sanity check: run features against the reference dataset."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Run feature engineering against a JSONL event file")
    parser.add_argument("--input", type=str, default="data/sample_1k.jsonl")
    args = parser.parse_args()

    events = [json.loads(line) for line in open(args.input)]
    labels = [e.get("label", "benign") for e in events]

    engineer = CloudEventFeatureEngineer()
    features = engineer.fit_transform(events)
    features["label"] = labels

    logger.info(f"Feature matrix shape: {features.shape}")
    logger.info("Mean feature values, benign vs malicious:")
    summary_cols = [
        "is_sensitive_call",
        "is_recon_call",
        "is_new_region_for_principal",
        "rapid_region_change",
        "events_in_last_5min",
    ]
    print(features.groupby("label")[summary_cols].mean())


if __name__ == "__main__":
    main()
