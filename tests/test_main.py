"""Tests for the MawinguSentry FastAPI service.

Important ordering note: MODEL_PATH and DATABASE_URL are read from the
environment at import time in app/main.py, so they must be set BEFORE
`from app.main import app` runs. That's why the model is trained and the
env vars are set here at module level, before any imports of app.main --
not inside a fixture, which would run too late.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_tmp_dir = tempfile.mkdtemp()
os.environ["MODEL_PATH"] = os.path.join(_tmp_dir, "test_model.pkl")
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(_tmp_dir, 'test.db')}"

from app.model import train_and_save  # noqa: E402
from app.data_generator import CloudTrailEventGenerator  # noqa: E402

train_and_save(n_generate=400, attack_ratio=0.15, seed=7, out_path=os.environ["MODEL_PATH"])

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402


def _sample_events(n=20, attack_ratio=0.3, seed=99):
    gen = CloudTrailEventGenerator(attack_ratio=attack_ratio, seed=seed, time_spread_days=5)
    return gen.generate_batch(size=n)


def test_health_reports_model_loaded():
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "model_loaded": True}


def test_predict_returns_one_prediction_per_event():
    with TestClient(app) as client:
        events = _sample_events(n=20)
        r = client.post("/predict", json={"events": events})
        assert r.status_code == 200
        body = r.json()
        assert len(body["predictions"]) == len(events)
        for p in body["predictions"]:
            assert p["predicted_label"] in ("benign", "malicious")
            assert 0.0 <= p["score"] <= 1.0


def test_predict_rejects_empty_event_list():
    with TestClient(app) as client:
        r = client.post("/predict", json={"events": []})
        assert r.status_code == 400


def test_predict_creates_alerts_visible_via_alerts_endpoint():
    with TestClient(app) as client:
        events = _sample_events(n=30, attack_ratio=0.4, seed=123)
        predict_response = client.post("/predict", json={"events": events})
        alerts_created = predict_response.json()["alerts_created"]

        r = client.get("/alerts", params={"limit": 100})
        assert r.status_code == 200
        alerts = r.json()
        assert len(alerts) >= alerts_created  # >= because earlier tests may have added alerts too
        if alerts_created > 0:
            sample = alerts[0]
            assert "score" in sample and "predicted_label" in sample


def test_alerts_min_score_filter():
    with TestClient(app) as client:
        client.post("/predict", json={"events": _sample_events(n=30, attack_ratio=0.4, seed=321)})

        r = client.get("/alerts", params={"min_score": 0.9, "limit": 100})
        assert r.status_code == 200
        for alert in r.json():
            assert alert["score"] >= 0.9


def test_stats_reflects_processed_events():
    with TestClient(app) as client:
        events = _sample_events(n=25, attack_ratio=0.4, seed=55)
        predict_response = client.post("/predict", json={"events": events})
        alerts_created = predict_response.json()["alerts_created"]

        r = client.get("/stats")
        assert r.status_code == 200
        stats = r.json()
        assert stats["total_events_processed"] >= alerts_created
        assert 0.0 <= stats["malicious_rate"] <= 1.0
