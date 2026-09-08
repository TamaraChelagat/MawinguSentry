"""
Explainability layer for MawinguSentry.

Two deliberately separate things, because they answer different questions:

1. SHAP feature attributions (from the ensemble's XGBoost base model) --
   explain WHICH features pushed a specific event's score up or down.
   This explains one base model's view, not the full stacked meta-learner
   (attributing a stacked ensemble's prediction back through a meta-learner
   to base features is possible but adds real complexity for limited
   portfolio value) -- worth being upfront about that scope, not claiming
   more precision than this actually provides.

2. A rule-based MITRE ATT&CK tag -- maps known suspicious indicators
   (specific sensitive API calls, an IP address never seen before combined
   with a short time gap, a recon-call-shaped burst) to the technique they
   most resemble. This is independent of the ML model's score: the model
   decides malicious/benign; this tagger explains WHICH known pattern (if
   any) the event resembles. An event CAN be flagged malicious with no
   MITRE tag -- that means the model caught something that doesn't match
   one of the five known patterns this project defines, which is worth an
   analyst's attention, not a bug in the tagger.
"""

from typing import Dict, List, Optional, Tuple

import shap

# Direct event-name rules for scenarios where the action itself is the signal
MITRE_EVENT_RULES = {
    "AttachUserPolicy": ("T1098", "Account Manipulation"),
    "PutBucketAcl": ("T1530", "Data from Cloud Storage"),
    "PutBucketPolicy": ("T1530", "Data from Cloud Storage"),
    "CreateAccessKey": ("T1552", "Unsecured Credentials"),
}


def tag_mitre_technique(event: Dict, feature_row: Dict) -> Tuple[Optional[str], Optional[str]]:
    """Rule-based MITRE tag. Returns (technique_id, technique_name), or (None, None) if no
    known pattern matches -- that's a valid, meaningful outcome, not a failure."""
    event_name = event.get("eventName")
    if event_name in MITRE_EVENT_RULES:
        return MITRE_EVENT_RULES[event_name]
    if feature_row.get("rapid_ip_change") == 1:
        return "T1078", "Valid Accounts"
    if feature_row.get("is_recon_call") == 1 and feature_row.get("events_in_last_5min", 0) >= 3:
        return "T1580", "Cloud Infrastructure Discovery"
    return None, None


class ThreatExplainer:
    """Wraps a trained CloudThreatPipeline to explain individual predictions."""

    def __init__(self, pipeline):
        self.pipeline = pipeline
        self._explainer = shap.TreeExplainer(pipeline.ensemble.models["xgb"])
        self._feature_names = pipeline.feature_engineer.feature_names

    def explain(self, context_events: List[Dict], target_index: int = -1, top_n: int = 5) -> Dict:
        """Explain one event using its own recent history for context.

        `context_events` should be the target event plus its principal's recent prior events, in
        chronological order (target_index defaults to the last item). This isn't optional
        convenience -- features like "events in the last 5 minutes" or "seconds since this
        principal's last action" are only meaningful when computed alongside real history. Passing
        a single event with no context silently produces different (and wrong) feature values than
        the model was trained on, since every contextual feature falls back to "first event ever"
        defaults with no error raised anywhere. This was found and fixed during development --
        see docs/EXPLAIN_DESIGN.md.
        """
        if not context_events:
            raise ValueError("context_events must contain at least the target event")

        feature_df = self.pipeline.feature_engineer.transform(context_events)
        x = feature_df.values.astype(float)
        target_row_idx = target_index if target_index >= 0 else len(context_events) + target_index

        shap_values = self._explainer.shap_values(x)
        values = shap_values[target_row_idx]

        contributions = list(zip(self._feature_names, values, x[target_row_idx]))
        contributions.sort(key=lambda c: abs(c[1]), reverse=True)
        top_contributions = [
            {"feature": name, "shap_value": float(val), "feature_value": float(feat_val)}
            for name, val, feat_val in contributions[:top_n]
        ]

        feature_row = feature_df.iloc[target_row_idx].to_dict()
        target_event = context_events[target_row_idx]
        mitre_technique, mitre_name = tag_mitre_technique(target_event, feature_row)

        score = float(self.pipeline.predict_proba(context_events)[target_row_idx])

        return {
            "score": score,
            "predicted_label": "malicious" if score > self.pipeline.optimal_threshold else "benign",
            "top_contributing_features": top_contributions,
            "mitre_technique": mitre_technique,
            "mitre_name": mitre_name,
            "context_events_used": len(context_events),
        }
