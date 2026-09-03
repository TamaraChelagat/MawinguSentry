"""Tests for CloudThreatPipeline. Uses small synthetic batches so the full
train/evaluate cycle runs in well under a second -- fine for CI."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.data_generator import CloudTrailEventGenerator  # noqa: E402
from app.model import CloudThreatPipeline, ConservativeSampler  # noqa: E402
import numpy as np  # noqa: E402


def _sample_events(n=300, attack_ratio=0.15, seed=5):
    gen = CloudTrailEventGenerator(attack_ratio=attack_ratio, seed=seed, time_spread_days=10)
    return gen.generate_batch(size=n)


def test_pipeline_trains_and_reports_metrics():
    events = _sample_events()
    pipeline = CloudThreatPipeline()
    metrics = pipeline.fit(events)

    assert pipeline.is_trained
    assert 0.0 <= metrics["roc_auc"] <= 1.0
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert "recall_by_scenario" in metrics


def test_pipeline_predicts_on_new_events():
    train_events = _sample_events(seed=5)
    pipeline = CloudThreatPipeline()
    pipeline.fit(train_events)

    new_events = _sample_events(n=50, seed=99)
    scores = pipeline.predict_proba(new_events)
    predictions = pipeline.predict(new_events)

    assert len(scores) == len(new_events)
    assert len(predictions) == len(new_events)
    assert set(np.unique(predictions)).issubset({0, 1})
    assert all(0.0 <= s <= 1.0 for s in scores)


def test_sensitive_action_scenarios_are_reliably_caught():
    """Single-event attack scenarios (not the multi-event recon burst) should
    have strong recall -- this is the honest, expected strength of a
    per-event classifier."""
    events = _sample_events(n=800, attack_ratio=0.15, seed=3)
    pipeline = CloudThreatPipeline()
    metrics = pipeline.fit(events)

    for scenario in ["privilege_escalation", "public_bucket_exposure", "cred_exfil_key_creation"]:
        if scenario not in metrics["recall_by_scenario"]:
            continue  # scenario didn't land in this particular test split, skip rather than fail
        caught, total = map(int, metrics["recall_by_scenario"][scenario].split("/"))
        if total > 0:
            assert caught / total >= 0.7, f"{scenario} recall unexpectedly low: {caught}/{total}"


def test_conservative_sampler_moves_toward_target_ratio_without_downsampling():
    rng = np.random.default_rng(0)
    X = rng.random((500, 5))
    y = np.zeros(500, dtype=int)
    y[:40] = 1  # 8% positive

    sampler = ConservativeSampler(target_malicious_ratio=0.3, random_state=0)
    X_res, y_res = sampler.fit_resample(X, y)

    assert int(np.sum(y_res == 1)) >= 40  # never fewer positives than we started with
    assert np.mean(y_res) > np.mean(y)  # ratio moved toward the target
    assert np.mean(y_res) <= 0.35  # and didn't overshoot into full balancing


def test_save_and_load_roundtrip(tmp_path):
    events = _sample_events()
    pipeline = CloudThreatPipeline()
    pipeline.fit(events)

    filepath = str(tmp_path / "test_pipeline.pkl")
    pipeline.save(filepath)
    loaded = CloudThreatPipeline.load(filepath)

    new_events = _sample_events(n=20, seed=42)
    original_scores = pipeline.predict_proba(new_events)
    loaded_scores = loaded.predict_proba(new_events)

    assert np.allclose(original_scores, loaded_scores)
