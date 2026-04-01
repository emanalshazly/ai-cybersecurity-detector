"""
Persistent alert storage using SQLite via SQLAlchemy.
Stores all detected threats, analyst investigations, and feedback.
"""

import json
from datetime import datetime
from enum import Enum
from typing import Optional, List

from sqlalchemy import (
    create_engine, Column, String, Float, DateTime, Boolean, Text, Integer,
    Enum as SAEnum, event as sa_event
)
from sqlalchemy.orm import DeclarativeBase, Session

from config import get_config


class AlertStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class Base(DeclarativeBase):
    pass


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    severity = Column(String, nullable=False)          # CRITICAL / HIGH / MEDIUM / LOW
    anomaly_score = Column(Float, nullable=True)
    source_ip = Column(String, nullable=True)
    source = Column(String, nullable=True)             # Which ingestor/detector produced this
    detector = Column(String, nullable=True)           # e.g., "IsolationForest", "SignatureDetector"
    rule_name = Column(String, nullable=True)          # For signature-based detections
    event_details = Column(Text, nullable=True)        # JSON-encoded raw event
    analysis = Column(Text, nullable=True)             # Claude's investigation narrative
    recommended_actions = Column(Text, nullable=True)  # JSON list of recommended actions
    status = Column(SAEnum(AlertStatus), default=AlertStatus.NEW, nullable=False)
    is_false_positive = Column(Boolean, default=False, nullable=False)
    analyst_notes = Column(Text, nullable=True)        # Human analyst feedback
    resolved_at = Column(DateTime, nullable=True)
    mitre_tactic = Column(String, nullable=True)       # e.g., "Credential Access"
    mitre_technique = Column(String, nullable=True)    # e.g., "T1110"
    campaign_id = Column(String, nullable=True)        # FK to campaign tracker

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "severity": self.severity,
            "anomaly_score": self.anomaly_score,
            "source_ip": self.source_ip,
            "source": self.source,
            "detector": self.detector,
            "rule_name": self.rule_name,
            "event_details": json.loads(self.event_details) if self.event_details else None,
            "analysis": self.analysis,
            "recommended_actions": json.loads(self.recommended_actions) if self.recommended_actions else [],
            "status": self.status.value if self.status else None,
            "is_false_positive": self.is_false_positive,
            "analyst_notes": self.analyst_notes,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "campaign_id": self.campaign_id,
        }


class AlertStore:
    def __init__(self, db_path: Optional[str] = None):
        cfg = get_config()
        db_url = f"sqlite:///{db_path or cfg.db_path}"
        self.engine = create_engine(db_url, echo=False)
        Base.metadata.create_all(self.engine)

    def save_alert(self, alert: Alert) -> None:
        with Session(self.engine) as session:
            session.merge(alert)
            session.commit()

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        with Session(self.engine) as session:
            return session.get(Alert, alert_id)

    def get_recent_alerts_for_ip(self, source_ip: str, limit: int = 20) -> List[dict]:
        with Session(self.engine) as session:
            alerts = (
                session.query(Alert)
                .filter(Alert.source_ip == source_ip)
                .order_by(Alert.timestamp.desc())
                .limit(limit)
                .all()
            )
            return [a.to_dict() for a in alerts]

    def get_recent_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[dict]:
        with Session(self.engine) as session:
            q = session.query(Alert).order_by(Alert.timestamp.desc())
            if severity:
                q = q.filter(Alert.severity == severity)
            return [a.to_dict() for a in q.limit(limit).all()]

    def get_stats(self) -> dict:
        with Session(self.engine) as session:
            total = session.query(Alert).count()
            by_severity = {}
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                by_severity[sev] = session.query(Alert).filter(Alert.severity == sev).count()
            false_positives = session.query(Alert).filter(Alert.is_false_positive == True).count()
            return {
                "total": total,
                "by_severity": by_severity,
                "false_positives": false_positives,
                "fp_rate": round(false_positives / total, 3) if total > 0 else 0,
            }

    def mark_false_positive(self, alert_id: str, notes: str = "") -> None:
        with Session(self.engine) as session:
            alert = session.get(Alert, alert_id)
            if alert:
                alert.is_false_positive = True
                alert.status = AlertStatus.FALSE_POSITIVE
                alert.analyst_notes = notes
                session.commit()

    def update_analysis(self, alert_id: str, analysis: str, recommended_actions: List[str]) -> None:
        with Session(self.engine) as session:
            alert = session.get(Alert, alert_id)
            if alert:
                alert.analysis = analysis
                alert.recommended_actions = json.dumps(recommended_actions)
                alert.status = AlertStatus.INVESTIGATING
                session.commit()

    def update_mitre(self, alert_id: str, tactic: str, technique: str) -> None:
        with Session(self.engine) as session:
            alert = session.get(Alert, alert_id)
            if alert:
                alert.mitre_tactic = tactic
                alert.mitre_technique = technique
                session.commit()

    def update_campaign(self, alert_id: str, campaign_id: str) -> None:
        with Session(self.engine) as session:
            alert = session.get(Alert, alert_id)
            if alert:
                alert.campaign_id = campaign_id
                session.commit()

    def get_labeled_training_data(self) -> List[dict]:
        """Return alerts that have been labeled as TP or FP, with event_details for retraining."""
        with Session(self.engine) as session:
            alerts = (
                session.query(Alert)
                .filter(Alert.status.in_([AlertStatus.FALSE_POSITIVE, AlertStatus.CONFIRMED]))
                .filter(Alert.event_details.isnot(None))
                .all()
            )
            result = []
            for a in alerts:
                try:
                    event = json.loads(a.event_details)
                    result.append({
                        "alert_id": a.id,
                        "is_false_positive": a.is_false_positive,
                        "event": event,
                    })
                except Exception:
                    pass
            return result

    def get_alerts_in_range(self, start: datetime, end: datetime) -> List[dict]:
        with Session(self.engine) as session:
            alerts = (
                session.query(Alert)
                .filter(Alert.timestamp >= start, Alert.timestamp <= end)
                .order_by(Alert.timestamp.desc())
                .all()
            )
            return [a.to_dict() for a in alerts]
