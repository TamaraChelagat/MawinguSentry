"""Smoke tests for the synthetic CloudTrail event generator."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.data_generator import CloudTrailEventGenerator, SCENARIOS


def test_benign_event_shape():
    gen = CloudTrailEventGenerator(seed=1)
    event = gen.generate_benign_event()
    assert event["label"] == "benign"
    assert "eventName" in event
    assert "sourceIPAddress" in event


def test_all_scenarios_generate_and_are_tagged():
    gen = CloudTrailEventGenerator(seed=1)
    for scenario in SCENARIOS:
        events = gen.generate_attack_sequence(scenario_id=scenario.scenario_id)
        assert len(events) >= 1
        malicious_events = [e for e in events if e["label"] == "malicious"]
        assert len(malicious_events) >= 1
        for e in malicious_events:
            assert e["mitre_technique"] == scenario.mitre_technique
            assert e["scenario_id"] == scenario.scenario_id


def test_batch_respects_labels():
    gen = CloudTrailEventGenerator(attack_ratio=0.2, seed=7)
    batch = gen.generate_batch(size=30)
    assert len(batch) >= 30
    labels = {e["label"] for e in batch}
    assert labels <= {"benign", "malicious"}
