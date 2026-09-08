"""
FastAPI service for MawinguSentry.

Endpoints:
  GET  /health   -- service + model status
  POST /predict  -- score a batch of CloudTrail-style events, persist alerts
  GET  /alerts   -- query stored alerts
  GET  /stats    -- aggregate statistics

The model is loaded once at startup from MODEL_PATH (default
models/cloud_threat_pipeline.pkl). If the file doesn't exist, the API
still starts (so /health and /alerts work), but /predict returns 503
rather than crashing the whole service -- a missing model artifact
shouldn't take down alert history or health checks.
"""

import logging
import os
from contextlib import asynccontextmanager
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.database import get_alerts, get_db, get_stats, init_db, save_alert
from app.explain import ThreatExplainer
from app.model import CloudThreatPipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

MODEL_PATH = os.environ.get("MODEL_PATH", "models/cloud_threat_pipeline.pkl")

_pipeline: Optional[CloudThreatPipeline] = None
_explainer: Optional[ThreatExplainer] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    global _pipeline, _explainer
    if os.path.exists(MODEL_PATH):
        _pipeline = CloudThreatPipeline.load(MODEL_PATH)
        _explainer = ThreatExplainer(_pipeline)
        logger.info(f"Model loaded from {MODEL_PATH}")
    else:
        logger.warning(f"No model found at {MODEL_PATH} -- /predict will return 503 until one is trained")
    yield
    # no teardown needed


app = FastAPI(title="MawinguSentry API", version="0.1", lifespan=lifespan)


def get_pipeline() -> CloudThreatPipeline:
    if _pipeline is None:
        raise HTTPException(
            status_code=503,
            detail=f"Model not loaded. Train one with `python scripts/train_model.py` (expected at {MODEL_PATH}).",
        )
    return _pipeline


def get_explainer() -> ThreatExplainer:
    if _explainer is None:
        raise HTTPException(status_code=503, detail="Model not loaded, so no explainer is available either.")
    return _explainer


# -- request/response models -------------------------------------------------


class PredictRequest(BaseModel):
    events: List[Dict]


class EventPrediction(BaseModel):
    event_id: Optional[str] = None
    event_name: Optional[str] = None
    score: float
    predicted_label: str


class PredictResponse(BaseModel):
    predictions: List[EventPrediction]
    threshold_used: float
    alerts_created: int


class AlertResponse(BaseModel):
    id: int
    event_id: Optional[str]
    event_name: Optional[str]
    principal: Optional[str]
    score: float
    predicted_label: str
    mitre_technique: Optional[str]
    mitre_name: Optional[str]
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class StatsResponse(BaseModel):
    total_events_processed: int
    malicious_count: int
    benign_count: int
    malicious_rate: float
    average_score: float
    alerts_by_mitre_technique: Dict[str, int]


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool


class ExplainRequest(BaseModel):
    context_events: List[Dict]
    target_index: int = -1


class FeatureContribution(BaseModel):
    feature: str
    shap_value: float
    feature_value: float


class ExplainResponse(BaseModel):
    score: float
    predicted_label: str
    top_contributing_features: List[FeatureContribution]
    mitre_technique: Optional[str]
    mitre_name: Optional[str]
    context_events_used: int


# -- endpoints -----------------------------------------------------------------


@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(status="ok", model_loaded=_pipeline is not None)


@app.post("/predict", response_model=PredictResponse)
def predict(
    request: PredictRequest, db: Session = Depends(get_db), pipeline: CloudThreatPipeline = Depends(get_pipeline)
):
    if not request.events:
        raise HTTPException(status_code=400, detail="events list is empty")

    scores = pipeline.predict_proba(request.events)
    threshold = pipeline.optimal_threshold

    predictions = []
    alerts_created = 0
    for event, score in zip(request.events, scores):
        label = "malicious" if score > threshold else "benign"
        predictions.append(
            EventPrediction(
                event_id=event.get("eventID"),
                event_name=event.get("eventName"),
                score=float(score),
                predicted_label=label,
            )
        )
        if label == "malicious":
            save_alert(db, event, score, label, threshold)
            alerts_created += 1

    return PredictResponse(predictions=predictions, threshold_used=threshold, alerts_created=alerts_created)


@app.get("/alerts", response_model=List[AlertResponse])
def list_alerts(
    limit: int = 50,
    offset: int = 0,
    min_score: Optional[float] = None,
    predicted_label: Optional[str] = None,
    db: Session = Depends(get_db),
):
    alerts = get_alerts(db, limit=limit, offset=offset, min_score=min_score, predicted_label=predicted_label)
    return [
        AlertResponse(
            id=a.id,
            event_id=a.event_id,
            event_name=a.event_name,
            principal=a.principal,
            score=a.score,
            predicted_label=a.predicted_label,
            mitre_technique=a.mitre_technique,
            mitre_name=a.mitre_name,
            created_at=a.created_at.isoformat(),
        )
        for a in alerts
    ]


@app.get("/stats", response_model=StatsResponse)
def stats(db: Session = Depends(get_db)):
    return StatsResponse(**get_stats(db))


@app.post("/explain", response_model=ExplainResponse)
def explain(request: ExplainRequest, explainer: ThreatExplainer = Depends(get_explainer)):
    if not request.context_events:
        raise HTTPException(status_code=400, detail="context_events must not be empty")
    try:
        result = explainer.explain(request.context_events, target_index=request.target_index)
    except IndexError:
        raise HTTPException(status_code=400, detail="target_index is out of range for the given context_events")
    return ExplainResponse(**result)
