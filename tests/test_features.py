"""Tests for CloudEventFeatureEngineer.

Includes a regression test for an index-alignment bug found during
development: feature rows were silently mismatched to the wrong events
after an internal groupby/sort, so e.g. a PutBucketAcl event could end
up tagged is_sensitive_call=0. That bug produced no errors or warnings
-- it just fed wrong labels to whatever trained on it. This test file
exists specifically so that class of bug can't reappear unnoticed.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.features import CloudEventFeatureEngineer, SENSITIVE_EVENTS, RECON_EVENTS  # noqa: E402
from app.data_generator import CloudTrailEventGenerator  # noqa: E402


def _sample_events(n=200, seed=11):
    gen = CloudTrailEventGenerator(attack_ratio=0.15, seed=seed, time_spread_days=14)
    return gen.generate_batch(size=n)


def test_fit_transform_shape():
    events = _sample_events()
    engineer = CloudEventFeatureEngineer()
    features = engineer.fit_transform(events)
    assert len(features) == len(events)
    assert engineer.is_fitted


def test_feature_rows_align_with_source_events():
    """Regression test: every row in the output must describe the event at the same position in the input."""
    events = _sample_events()
    engineer = CloudEventFeatureEngineer()
    features = engineer.fit_transform(events)

    for i, event in enumerate(events):
        expected_sensitive = int(event["eventName"] in SENSITIVE_EVENTS)
        expected_recon = int(event["eventName"] in RECON_EVENTS)
        assert features.iloc[i]["is_sensitive_call"] == expected_sensitive, f"misaligned at row {i}"
        assert features.iloc[i]["is_recon_call"] == expected_recon, f"misaligned at row {i}"


def test_privilege_escalation_events_are_flagged_sensitive():
    events = _sample_events(n=500, seed=3)
    engineer = CloudEventFeatureEngineer()
    features = engineer.fit_transform(events)

    priv_esc_positions = [i for i, e in enumerate(events) if e.get("scenario_id") == "privilege_escalation"]
    assert len(priv_esc_positions) > 0, "test batch didn't include a privilege_escalation event, adjust seed/n"
    for i in priv_esc_positions:
        assert features.iloc[i]["is_sensitive_call"] == 1


def test_unusual_geo_login_flags_rapid_ip_change():
    events = _sample_events(n=500, seed=3)
    engineer = CloudEventFeatureEngineer()
    features = engineer.fit_transform(events)

    geo_positions = [i for i, e in enumerate(events) if e.get("scenario_id") == "unusual_geo_login"]
    assert len(geo_positions) > 0, "test batch didn't include an unusual_geo_login event, adjust seed/n"
    for i in geo_positions:
        assert features.iloc[i]["rapid_ip_change"] == 1


def test_transform_matches_fit_transform_columns():
    events = _sample_events()
    engineer = CloudEventFeatureEngineer()
    train_features = engineer.fit_transform(events)

    new_events = _sample_events(n=50, seed=99)
    test_features = engineer.transform(new_events)

    assert list(test_features.columns) == list(train_features.columns)
    assert len(test_features) == len(new_events)


def test_baselines_only_learned_from_benign_events():
    """A principal's known IPs/regions should never include an IP or region that only appears in a malicious event."""
    events = _sample_events(n=500, seed=3)
    engineer = CloudEventFeatureEngineer()
    engineer.fit_transform(events)

    malicious_only_ips = set()
    benign_ips = set()
    for e in events:
        principal = e["userIdentity"]["arn"]
        ip_prefix = ".".join(e["sourceIPAddress"].split(".")[:2])
        if e["label"] == "malicious":
            malicious_only_ips.add((principal, ip_prefix))
        else:
            benign_ips.add((principal, ip_prefix))
    malicious_only_ips -= benign_ips

    for principal, ip_prefix in malicious_only_ips:
        baseline = engineer.principal_baselines.get(principal, {"known_ips": set()})
        assert ip_prefix not in baseline["known_ips"], f"attack IP leaked into baseline for {principal}"


if __name__ == "__main__":
    # Quick manual run without pytest, prints a readable summary
    events = _sample_events(n=1000, seed=2026)
    engineer = CloudEventFeatureEngineer()
    features = engineer.fit_transform(events)
    print(json.dumps({"events": len(events), "features_shape": list(features.shape)}, indent=2))
