"""RecoveryAction model tracking self-recovery simulations and outcomes."""

from datetime import datetime, timezone
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class RecoveryAction(db.Model):
    """Records simulated failures and autonomous/manual recovery actions."""

    __tablename__ = "recovery_actions"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("threat_incidents.id"), nullable=True, index=True)
    failure_type = db.Column(db.String(64), nullable=False, index=True)
    action_taken = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="Completed", index=True)
    duration_ms = db.Column(db.Integer, nullable=False, default=150)
    health_before = db.Column(db.String(32), nullable=False, default="Critical")
    health_after = db.Column(db.String(32), nullable=False, default="Healthy")
    details = db.Column(db.Text, nullable=False, default="")
    is_simulated = db.Column(db.Boolean, nullable=False, default=True)
    failure_detected_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, index=True)

    incident = db.relationship("ThreatIncident", back_populates="recoveries")

    def to_dict(self):
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "failure_type": self.failure_type,
            "action_taken": self.action_taken,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "health_before": self.health_before,
            "health_after": self.health_after,
            "details": self.details,
            "is_simulated": self.is_simulated,
            "failure_detected_at": self.failure_detected_at.isoformat() if self.failure_detected_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
