"""
Database module for MawinguSentry.

Uses SQLAlchemy with SQLite by default (zero setup, works in CI and local
dev out of the box) and Postgres in production via the DATABASE_URL env
var. This is a deliberate departure from FraudDetectPro's Firestore-based
storage: Firestore ties the project to a single cloud vendor's managed
service, while SQLAlchemy + Postgres is the more standard, portable choice
for a project that's specifically about cloud infrastructure security --
and it's also what the project ROADMAP committed to.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import Column, DateTime, Float, Integer, String, create_engine, desc, func
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./mawingusentry.db")

# SQLite needs this connect_arg for multithreaded FastAPI use; Postgres doesn't.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, index=True)
    event_name = Column(String, index=True)
    principal = Column(String, index=True)
    aws_region = Column(String)
    source_ip = Column(String)
    score = Column(Float, index=True)
    predicted_label = Column(String, index=True)  # "malicious" or "benign"
    scenario_id = Column(String, nullable=True)  # only present for synthetic/labeled data
    mitre_technique = Column(String, nullable=True)
    mitre_name = Column(String, nullable=True)
    threshold_used = Column(Float)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


def init_db():
    Base.metadata.create_all(bind=engine)
    logger.info(f"Database initialized: {DATABASE_URL.split('://')[0]}")


def get_db():
    """FastAPI dependency: yields a session, closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def save_alert(db, event: Dict, score: float, predicted_label: str, threshold: float) -> Alert:
    user_identity = event.get("userIdentity", {})
    principal = user_identity.get("arn") if isinstance(user_identity, dict) else user_identity

    alert = Alert(
        event_id=event.get("eventID"),
        event_name=event.get("eventName"),
        principal=principal,
        aws_region=event.get("awsRegion"),
        source_ip=event.get("sourceIPAddress"),
        score=float(score),
        predicted_label=predicted_label,
        scenario_id=event.get("scenario_id"),
        mitre_technique=event.get("mitre_technique"),
        mitre_name=event.get("mitre_name"),
        threshold_used=float(threshold),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def get_alerts(
    db,
    limit: int = 50,
    offset: int = 0,
    min_score: Optional[float] = None,
    predicted_label: Optional[str] = None,
) -> List[Alert]:
    query = db.query(Alert)
    if min_score is not None:
        query = query.filter(Alert.score >= min_score)
    if predicted_label is not None:
        query = query.filter(Alert.predicted_label == predicted_label)
    return query.order_by(desc(Alert.created_at)).offset(offset).limit(limit).all()


def get_stats(db) -> Dict:
    total = db.query(func.count(Alert.id)).scalar() or 0
    malicious = db.query(func.count(Alert.id)).filter(Alert.predicted_label == "malicious").scalar() or 0
    avg_score = db.query(func.avg(Alert.score)).scalar() or 0.0

    by_technique = (
        db.query(Alert.mitre_technique, func.count(Alert.id))
        .filter(Alert.predicted_label == "malicious", Alert.mitre_technique.isnot(None))
        .group_by(Alert.mitre_technique)
        .all()
    )

    return {
        "total_events_processed": total,
        "malicious_count": malicious,
        "benign_count": total - malicious,
        "malicious_rate": (malicious / total) if total > 0 else 0.0,
        "average_score": float(avg_score),
        "alerts_by_mitre_technique": {technique: count for technique, count in by_technique},
    }
