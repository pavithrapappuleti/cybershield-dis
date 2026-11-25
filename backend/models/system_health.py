"""SystemHealth model recording real Flask telemetry and simulated service state."""

import json
from datetime import datetime, timezone
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class SystemHealth(db.Model):
    """Time-series snapshot of application health and simulated service state."""

    __tablename__ = "system_health"

    id = db.Column(db.Integer, primary_key=True)
    overall_status = db.Column(db.String(20), nullable=False, default="Healthy", index=True)
    api_status = db.Column(db.String(20), nullable=False, default="Operational")
    database_status = db.Column(db.String(20), nullable=False, default="Operational")
    service_status = db.Column(db.String(20), nullable=False, default="Operational")
    availability_pct = db.Column(db.Float, nullable=False, default=100.0)
    avg_response_ms = db.Column(db.Float, nullable=False, default=12.0)
    error_rate_pct = db.Column(db.Float, nullable=False, default=0.0)
    active_blocks_count = db.Column(db.Integer, nullable=False, default=0)
    open_incidents_count = db.Column(db.Integer, nullable=False, default=0)
    real_request_count = db.Column(db.Integer, nullable=False, default=0)
    real_error_count = db.Column(db.Integer, nullable=False, default=0)
    details_json = db.Column(db.Text, nullable=False, default="{}")
    recorded_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, index=True)

    def details(self):
        try:
            return json.loads(self.details_json or "{}")
        except (ValueError, TypeError):
            return {}

    def to_dict(self):
        return {
            "id": self.id,
            "overall_status": self.overall_status,
            "api_status": self.api_status,
            "database_status": self.database_status,
            "service_status": self.service_status,
            "availability_pct": round(self.availability_pct, 2),
            "avg_response_ms": round(self.avg_response_ms, 2),
            "error_rate_pct": round(self.error_rate_pct, 2),
            "active_blocks_count": self.active_blocks_count,
            "open_incidents_count": self.open_incidents_count,
            "real_request_count": self.real_request_count,
            "real_error_count": self.real_error_count,
            "details": self.details(),
            "recorded_at": self.recorded_at.isoformat() if self.recorded_at else None,
        }
