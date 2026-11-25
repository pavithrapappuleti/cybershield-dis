"""Database initialization and clean Healthy baseline seeding."""

from datetime import datetime, timedelta, timezone
import json

from extensions import db
from models import (
    BlockedSource,
    IncidentHistory,
    RecoveryAction,
    SecurityEvent,
    SecurityRule,
    SystemHealth,
    ThreatIncident,
)
from services.monitoring_service import reset_monitoring_state


DEFAULT_RULES = [
    {
        "rule_key": "RULE_FAILED_LOGIN_BURST",
        "name": "Failed Login Burst Detection",
        "description": "Triggers when repeated failed authentication attempts from one IP exceed threshold within the time window.",
        "event_type": "failed_login_burst",
        "threshold_count": 5,
        "window_seconds": 300,
        "base_risk_weight": 22,
        "default_severity": "High",
        "auto_block_enabled": True,
        "requires_human_approval": False,
    },
    {
        "rule_key": "RULE_SUSPICIOUS_FREQ",
        "name": "Suspicious Request Frequency",
        "description": "Flags high-velocity request bursts exceeding normal baseline API traffic.",
        "event_type": "suspicious_frequency",
        "threshold_count": 40,
        "window_seconds": 120,
        "base_risk_weight": 20,
        "default_severity": "High",
        "auto_block_enabled": True,
        "requires_human_approval": False,
    },
    {
        "rule_key": "RULE_REPEATED_IP",
        "name": "Repeated IP Polling Pattern",
        "description": "Monitors sustained repetitive requests from a single simulated IP address.",
        "event_type": "repeated_ip_requests",
        "threshold_count": 30,
        "window_seconds": 180,
        "base_risk_weight": 16,
        "default_severity": "Medium",
        "auto_block_enabled": False,
        "requires_human_approval": True,
    },
    {
        "rule_key": "RULE_RESTRICTED_ENDPOINT",
        "name": "Restricted Test Endpoint Probe",
        "description": "Detects repeated unauthorized probes against protected administrative or debug test routes.",
        "event_type": "restricted_endpoint_access",
        "threshold_count": 2,
        "window_seconds": 300,
        "base_risk_weight": 24,
        "default_severity": "High",
        "auto_block_enabled": True,
        "requires_human_approval": False,
    },
    {
        "rule_key": "RULE_UNUSUAL_ACTIVITY",
        "name": "Unusual Activity Pattern",
        "description": "Flags anomalous payload or service-disruption patterns for risk assessment.",
        "event_type": "unusual_activity_pattern",
        "threshold_count": 1,
        "window_seconds": 300,
        "base_risk_weight": 20,
        "default_severity": "Medium",
        "auto_block_enabled": False,
        "requires_human_approval": True,
    },
]


def _seed_rules():
    for item in DEFAULT_RULES:
        if not SecurityRule.query.filter_by(rule_key=item["rule_key"]).first():
            db.session.add(SecurityRule(**item))
    db.session.commit()


def _seed_healthy_baseline_history():
    """Seed resolved historical records so charts & memory start rich while overall status stays Healthy."""
    now = datetime.now(timezone.utc)

    # Normal baseline events over the past 4 days
    normal_ips = ["192.0.2.10", "192.0.2.15", "198.51.100.24"]
    for days_ago in range(4, 0, -1):
        ts = now - timedelta(days=days_ago, hours=3)
        db.session.add(
            SecurityEvent(
                source_ip=normal_ips[days_ago % len(normal_ips)],
                event_type="normal_traffic",
                endpoint="/api/dashboard",
                method="GET",
                status_code=200,
                request_count=12 + days_ago,
                failed_login_count=0,
                risk_score=8,
                severity="Low",
                is_threat=False,
                detection_reason="Normal baseline traffic within configured thresholds.",
                payload_summary="GET /api/dashboard (baseline telemetry)",
                is_simulated=True,
                created_at=ts,
            )
        )

    # Three historical RESOLVED incidents across previous days so trends & Immune Memory are populated
    historical_incidents = [
        {
            "days_ago": 3,
            "code": "INC-2026-0001",
            "title": "Historical Brute-Force Probe (Resolved)",
            "ip": "203.0.113.19",
            "event_type": "failed_login_burst",
            "severity": "High",
            "risk_score": 74,
            "reason": "6 failed login attempts from 203.0.113.19 within 300s (archived drill).",
            "response": "Temporarily blocked simulated IP 203.0.113.19 for 15 min (expired)",
            "signature": "failed_login_burst::203.0.113.19",
            "count": 6,
        },
        {
            "days_ago": 2,
            "code": "INC-2026-0002",
            "title": "Historical Traffic Spike Drill (Resolved)",
            "ip": "198.51.100.88",
            "event_type": "suspicious_frequency",
            "severity": "Medium",
            "risk_score": 52,
            "reason": "48 requests in 120s from 198.51.100.88 during baseline calibration.",
            "response": "Rate-monitored and resolved after traffic normalized",
            "signature": "suspicious_frequency::198.51.100.88",
            "count": 48,
        },
        {
            "days_ago": 1,
            "code": "INC-2026-0003",
            "title": "Historical Restricted Endpoint Probe (Resolved)",
            "ip": "203.0.113.77",
            "event_type": "restricted_endpoint_access",
            "severity": "High",
            "risk_score": 68,
            "reason": "3 unauthorized probes to /api/admin/debug-test from 203.0.113.77.",
            "response": "Temporarily isolated simulated IP 203.0.113.77 (resolved)",
            "signature": "restricted_endpoint_access::/api/admin/debug-test",
            "count": 3,
        },
    ]

    for item in historical_incidents:
        ts = now - timedelta(days=item["days_ago"], hours=2)
        ev = SecurityEvent(
            source_ip=item["ip"],
            event_type=item["event_type"],
            endpoint="/api/auth/login" if item["event_type"] == "failed_login_burst" else "/api/admin/debug-test",
            method="POST",
            status_code=401 if item["event_type"] == "failed_login_burst" else 403,
            request_count=item["count"],
            failed_login_count=item["count"] if item["event_type"] == "failed_login_burst" else 0,
            risk_score=item["risk_score"],
            severity=item["severity"],
            is_threat=True,
            detection_reason=item["reason"],
            payload_summary="Historical calibration drill event",
            is_simulated=True,
            created_at=ts,
        )
        db.session.add(ev)
        db.session.flush()

        inc = ThreatIncident(
            incident_code=item["code"],
            title=item["title"],
            source_ip=item["ip"],
            event_type=item["event_type"],
            severity=item["severity"],
            risk_score=item["risk_score"],
            status="Resolved",
            detection_reason=item["reason"],
            risk_breakdown_json=json.dumps(
                {
                    "failed_login_factor": 24 if item["event_type"] == "failed_login_burst" else 0,
                    "request_frequency_factor": 18,
                    "repetition_factor": 10,
                    "activity_type_factor": 22,
                    "immune_memory_boost": 0,
                }
            ),
            recommended_response="Apply temporary simulated IP isolation and log pattern.",
            response_action=item["response"],
            immune_signature=item["signature"],
            occurrence_count=item["count"],
            event_id=ev.id,
            created_at=ts,
            updated_at=ts + timedelta(minutes=10),
            resolved_at=ts + timedelta(minutes=15),
        )
        db.session.add(inc)
        db.session.flush()

        db.session.add_all(
            [
                IncidentHistory(
                    incident_id=inc.id,
                    event_stage="Detection",
                    actor="Rule-Based Threat Detector",
                    action="Historical drill threat detected",
                    notes=item["reason"],
                    timestamp=ts,
                ),
                IncidentHistory(
                    incident_id=inc.id,
                    event_stage="Response",
                    actor="Automated Response Engine",
                    action=item["response"],
                    notes="Simulated containment completed.",
                    timestamp=ts + timedelta(seconds=2),
                ),
                IncidentHistory(
                    incident_id=inc.id,
                    event_stage="StatusUpdate",
                    actor="SOC Administrator",
                    action="Marked Resolved after baseline verification",
                    notes="Archived calibration incident.",
                    timestamp=ts + timedelta(minutes=15),
                ),
            ]
        )

    # One completed historical recovery drill
    db.session.add(
        RecoveryAction(
            failure_type="api_failure",
            action_taken="Completed historical baseline self-recovery verification drill",
            status="Completed",
            duration_ms=142,
            health_before="Critical",
            health_after="Healthy",
            details="Baseline verification completed cleanly prior to live demonstration.",
            is_simulated=True,
            failure_detected_at=now - timedelta(days=1, hours=4),
            created_at=now - timedelta(days=1, hours=4),
        )
    )

    # Healthy SystemHealth time-series points
    for offset in range(6, 0, -1):
        db.session.add(
            SystemHealth(
                overall_status="Healthy",
                api_status="Operational",
                database_status="Operational",
                service_status="Operational",
                availability_pct=100.0,
                avg_response_ms=9.5 + (offset % 3) * 1.4,
                error_rate_pct=0.0,
                active_blocks_count=0,
                open_incidents_count=0,
                real_request_count=10 * (7 - offset),
                real_error_count=0,
                details_json=json.dumps({"note": "Baseline healthy telemetry"}),
                recorded_at=now - timedelta(minutes=offset * 20),
            )
        )

    db.session.commit()


def initialize_database(seed_baseline=True):
    """Create SQLite tables and seed default rules & healthy baseline if empty."""
    db.create_all()
    _seed_rules()
    if seed_baseline and SecurityEvent.query.count() == 0:
        _seed_healthy_baseline_history()
        reset_monitoring_state()


def reset_demo_baseline():
    """Clear current data and re-seed a clean Healthy baseline for live demos."""
    IncidentHistory.query.delete()
    BlockedSource.query.delete()
    RecoveryAction.query.delete()
    ThreatIncident.query.delete()
    SecurityEvent.query.delete()
    SystemHealth.query.delete()
    SecurityRule.query.delete()
    db.session.commit()

    _seed_rules()
    _seed_healthy_baseline_history()
    reset_monitoring_state()
