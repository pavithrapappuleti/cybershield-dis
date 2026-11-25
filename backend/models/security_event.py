"""SecurityEvent model storing raw and analyzed telemetry events."""

from datetime import datetime, timezone
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class SecurityEvent(db.Model):
    """Represents a monitored request or security telemetry event."""

    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(64), nullable=False, index=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    endpoint = db.Column(db.String(160), nullable=False, default="/api/health")
    method = db.Column(db.String(16), nullable=False, default="GET")
    status_code = db.Column(db.Integer, nullable=False, default=200)
    request_count = db.Column(db.Integer, nullable=False, default=1)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    severity = db.Column(db.String(20), nullable=False, default="Low", index=True)
    is_threat = db.Column(db.Boolean, nullable=False, default=False, index=True)
    detection_reason = db.Column(db.Text, nullable=False, default="Normal baseline activity")
    payload_summary = db.Column(db.Text, nullable=True)
    is_simulated = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, index=True)

    incidents = db.relationship("ThreatIncident", back_populates="trigger_event", lazy="dynamic")

    def to_dict(self):
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "event_type": self.event_type,
            "endpoint": self.endpoint,
            "method": self.method,
            "status_code": self.status_code,
            "request_count": self.request_count,
            "failed_login_count": self.failed_login_count,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "is_threat": self.is_threat,
            "detection_reason": self.detection_reason,
            "payload_summary": self.payload_summary,
            "is_simulated": self.is_simulated,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
