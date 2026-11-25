"""ThreatIncident model representing escalated security incidents."""

import json
from datetime import datetime, timezone
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class ThreatIncident(db.Model):
    """Represents a detected threat or service-disruption incident."""

    __tablename__ = "threat_incidents"

    id = db.Column(db.Integer, primary_key=True)
    incident_code = db.Column(db.String(32), unique=True, nullable=False, index=True)
    title = db.Column(db.String(160), nullable=False)
    source_ip = db.Column(db.String(64), nullable=False, index=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(32), nullable=False, default="New", index=True)
    detection_reason = db.Column(db.Text, nullable=False)
    risk_breakdown_json = db.Column(db.Text, nullable=False, default="{}")
    recommended_response = db.Column(db.String(255), nullable=False)
    response_action = db.Column(db.String(255), nullable=False, default="Monitored")
    immune_signature = db.Column(db.String(128), nullable=False, index=True)
    occurrence_count = db.Column(db.Integer, nullable=False, default=1)
    event_id = db.Column(db.Integer, db.ForeignKey("security_events.id"), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    resolved_at = db.Column(db.DateTime(timezone=True), nullable=True)

    trigger_event = db.relationship("SecurityEvent", back_populates="incidents")
    history_entries = db.relationship(
        "IncidentHistory",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentHistory.timestamp.asc()",
    )
    blocks = db.relationship("BlockedSource", back_populates="incident", lazy="dynamic")
    recoveries = db.relationship("RecoveryAction", back_populates="incident", lazy="dynamic")

    def risk_breakdown(self):
        try:
            return json.loads(self.risk_breakdown_json or "{}")
        except (ValueError, TypeError):
            return {}

    def to_dict(self, include_history=False):
        data = {
            "id": self.id,
            "incident_code": self.incident_code,
            "title": self.title,
            "source_ip": self.source_ip,
            "event_type": self.event_type,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "status": self.status,
            "detection_reason": self.detection_reason,
            "risk_breakdown": self.risk_breakdown(),
            "recommended_response": self.recommended_response,
            "response_action": self.response_action,
            "immune_signature": self.immune_signature,
            "occurrence_count": self.occurrence_count,
            "event_id": self.event_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }
        if include_history:
            data["history"] = [entry.to_dict() for entry in self.history_entries]
        return data
