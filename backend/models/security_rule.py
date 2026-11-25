"""SecurityRule model storing configurable detection & response thresholds."""

from datetime import datetime, timezone
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class SecurityRule(db.Model):
    """Configurable rule thresholds for threat detection and automated defense."""

    __tablename__ = "security_rules"

    id = db.Column(db.Integer, primary_key=True)
    rule_key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    threshold_count = db.Column(db.Integer, nullable=False, default=5)
    window_seconds = db.Column(db.Integer, nullable=False, default=300)
    base_risk_weight = db.Column(db.Integer, nullable=False, default=25)
    default_severity = db.Column(db.String(20), nullable=False, default="High")
    auto_block_enabled = db.Column(db.Boolean, nullable=False, default=True)
    requires_human_approval = db.Column(db.Boolean, nullable=False, default=False)
    immune_boost_applied = db.Column(db.Integer, nullable=False, default=0)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    def to_dict(self):
        return {
            "id": self.id,
            "rule_key": self.rule_key,
            "name": self.name,
            "description": self.description,
            "event_type": self.event_type,
            "threshold_count": self.threshold_count,
            "window_seconds": self.window_seconds,
            "base_risk_weight": self.base_risk_weight,
            "default_severity": self.default_severity,
            "auto_block_enabled": self.auto_block_enabled,
            "requires_human_approval": self.requires_human_approval,
            "immune_boost_applied": self.immune_boost_applied,
            "is_active": self.is_active,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
