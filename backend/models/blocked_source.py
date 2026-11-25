"""BlockedSource model for simulated IP isolation records."""

from datetime import datetime, timezone
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class BlockedSource(db.Model):
    """Tracks temporarily blocked simulated/test source IP addresses."""

    __tablename__ = "blocked_sources"

    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(64), nullable=False, index=True)
    reason = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="High")
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    pending_approval = db.Column(db.Boolean, nullable=False, default=False, index=True)
    is_simulated = db.Column(db.Boolean, nullable=False, default=True)
    approval_mode = db.Column(db.String(32), nullable=False, default="automated")
    blocked_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    unblocked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    unblocked_by = db.Column(db.String(64), nullable=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("threat_incidents.id"), nullable=True)

    incident = db.relationship("ThreatIncident", back_populates="blocks")

    def to_dict(self):
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "reason": self.reason,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "is_active": self.is_active,
            "pending_approval": self.pending_approval,
            "is_simulated": self.is_simulated,
            "approval_mode": self.approval_mode,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "unblocked_at": self.unblocked_at.isoformat() if self.unblocked_at else None,
            "unblocked_by": self.unblocked_by,
            "incident_id": self.incident_id,
        }
