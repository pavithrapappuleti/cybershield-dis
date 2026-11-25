"""IncidentHistory model storing chronological lifecycle logs."""

from datetime import datetime, timezone
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class IncidentHistory(db.Model):
    """Audit trail entry for every phase of an incident's lifecycle."""

    __tablename__ = "incident_history"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("threat_incidents.id"), nullable=False, index=True)
    event_stage = db.Column(db.String(64), nullable=False)
    actor = db.Column(db.String(64), nullable=False, default="CyberShield Engine")
    action = db.Column(db.String(255), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, index=True)

    incident = db.relationship("ThreatIncident", back_populates="history_entries")

    def to_dict(self):
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "event_stage": self.event_stage,
            "actor": self.actor,
            "action": self.action,
            "notes": self.notes,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
