"""Core REST API routes for Health, Dashboard, Monitoring, Incidents, Rules, Blocking, Recovery & Immune Memory."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request

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
from routes.guards import admin_required
from services.immune_memory import get_immune_memory_summary
from services.monitoring_service import (
    compute_current_health,
    get_auto_heal_config,
    get_monitoring_logs,
    persist_health_snapshot,
    set_auto_heal_config,
)
from services.recovery_engine import execute_recovery
from services.response_engine import approve_pending_block, unblock_simulated_source

api_bp = Blueprint("api", __name__, url_prefix="/api")

VALID_INCIDENT_STATUSES = {"New", "Investigating", "Resolved", "False Positive"}
VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}


@api_bp.route("/health", methods=["GET"])
def health_check():
    """Return real Flask/SQLite health plus simulated service state."""
    health = compute_current_health()
    strict_mode = request.args.get("strict", "false").lower() == "true"
    status_code = 503 if (strict_mode and health["overall_status"] == "Critical") else 200
    return jsonify(
        {
            "status": health["overall_status"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "health": health,
        }
    ), status_code


@api_bp.route("/dashboard", methods=["GET"])
@admin_required
def get_dashboard():
    """Aggregate real database statistics and charts for the Security Overview."""
    health = compute_current_health()

    total_events = SecurityEvent.query.count()
    detected_threats = SecurityEvent.query.filter_by(is_threat=True).count()
    critical_incidents = ThreatIncident.query.filter(
        ThreatIncident.severity == "Critical",
        ThreatIncident.status.in_(["New", "Investigating"]),
    ).count()
    total_critical_all_time = ThreatIncident.query.filter_by(severity="Critical").count()
    active_blocks = BlockedSource.query.filter_by(is_active=True).count()
    pending_approvals = BlockedSource.query.filter_by(pending_approval=True).count()

    # Severity distribution from ThreatIncident (fallback to SecurityEvent threats if none)
    severity_counts = {sev: 0 for sev in ["Low", "Medium", "High", "Critical"]}
    for inc in ThreatIncident.query.all():
        if inc.severity in severity_counts:
            severity_counts[inc.severity] += 1

    # Daily incident trend (last 7 days)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    day_buckets = {}
    for offset in range(6, -1, -1):
        day_str = (now - timedelta(days=offset)).strftime("%Y-%m-%d")
        day_buckets[day_str] = {"date": day_str, "incidents": 0, "events": 0}

    seven_days_ago = now - timedelta(days=7)
    for ev in SecurityEvent.query.all():
        ev_ts = ev.created_at.replace(tzinfo=None) if ev.created_at else None
        if ev_ts and ev_ts >= seven_days_ago:
            d = ev_ts.strftime("%Y-%m-%d")
            if d in day_buckets:
                day_buckets[d]["events"] += 1

    for inc in ThreatIncident.query.all():
        inc_ts = inc.created_at.replace(tzinfo=None) if inc.created_at else None
        if inc_ts and inc_ts >= seven_days_ago:
            d = inc_ts.strftime("%Y-%m-%d")
            if d in day_buckets:
                day_buckets[d]["incidents"] += 1

    # Recent system health history for chart
    health_points = (
        SystemHealth.query.order_by(SystemHealth.recorded_at.desc()).limit(12).all()
    )
    health_series = [h.to_dict() for h in reversed(health_points)]

    recent_events = (
        SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(8).all()
    )
    recent_incidents = (
        ThreatIncident.query.order_by(ThreatIncident.created_at.desc()).limit(5).all()
    )

    return jsonify(
        {
            "system_status": health["overall_status"],
            "summary": {
                "total_security_events": total_events,
                "detected_threats": detected_threats,
                "critical_incidents": critical_incidents,
                "total_critical_all_time": total_critical_all_time,
                "active_simulated_blocks": active_blocks,
                "pending_block_approvals": pending_approvals,
                "service_availability_pct": health["availability_pct"],
                "open_incidents": health["open_incidents_count"],
            },
            "health": health,
            "charts": {
                "severity_distribution": severity_counts,
                "daily_incident_trend": list(day_buckets.values()),
                "system_health_history": health_series,
            },
            "recent_activities": [e.to_dict() for e in recent_events],
            "recent_incidents": [i.to_dict() for i in recent_incidents],
        }
    )


@api_bp.route("/monitoring", methods=["GET"])
@admin_required
def get_monitoring():
    """Return real Flask metrics, simulated service flags, health history, and monitoring events."""
    refresh = request.args.get("refresh", "false").lower() == "true"
    health = compute_current_health()
    if refresh:
        persist_health_snapshot(health)

    snapshots = SystemHealth.query.order_by(SystemHealth.recorded_at.desc()).limit(15).all()
    recent_events = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(25).all()

    return jsonify(
        {
            "health": health,
            "monitoring_events": get_monitoring_logs(limit=40),
            "recent_telemetry_events": [e.to_dict() for e in recent_events],
            "snapshots": [s.to_dict() for s in reversed(snapshots)],
        }
    )


@api_bp.route("/events", methods=["GET"])
@admin_required
def get_events():
    """List analyzed security & baseline events with optional filters."""
    severity = request.args.get("severity")
    event_type = request.args.get("event_type")
    threats_only = request.args.get("threats_only", "false").lower() == "true"
    limit = min(200, max(1, request.args.get("limit", default=60, type=int)))

    query = SecurityEvent.query
    if severity and severity in VALID_SEVERITIES:
        query = query.filter(SecurityEvent.severity == severity)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if threats_only:
        query = query.filter(SecurityEvent.is_threat.is_(True))

    events = query.order_by(SecurityEvent.created_at.desc()).limit(limit).all()
    return jsonify({"count": len(events), "events": [e.to_dict() for e in events]})


@api_bp.route("/incidents", methods=["GET"])
@admin_required
def get_incidents():
    """List detected threat incidents with search, severity, status, and date filters."""
    search = (request.args.get("search") or "").strip()
    severity = (request.args.get("severity") or "").strip()
    status = (request.args.get("status") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()

    query = ThreatIncident.query

    if severity and severity in VALID_SEVERITIES:
        query = query.filter(ThreatIncident.severity == severity)
    if status and status in VALID_INCIDENT_STATUSES:
        query = query.filter(ThreatIncident.status == status)
    if search:
        like_term = f"%{search}%"
        query = query.filter(
            db.or_(
                ThreatIncident.incident_code.ilike(like_term),
                ThreatIncident.title.ilike(like_term),
                ThreatIncident.source_ip.ilike(like_term),
                ThreatIncident.event_type.ilike(like_term),
                ThreatIncident.detection_reason.ilike(like_term),
            )
        )
    if date_from:
        try:
            start_dt = datetime.fromisoformat(date_from).replace(tzinfo=timezone.utc)
            query = query.filter(ThreatIncident.created_at >= start_dt)
        except ValueError:
            return jsonify({"error": "Invalid date_from format; expected YYYY-MM-DD."}), 400
    if date_to:
        try:
            end_dt = datetime.fromisoformat(date_to).replace(tzinfo=timezone.utc) + timedelta(days=1)
            query = query.filter(ThreatIncident.created_at < end_dt)
        except ValueError:
            return jsonify({"error": "Invalid date_to format; expected YYYY-MM-DD."}), 400

    incidents = query.order_by(ThreatIncident.created_at.desc()).all()
    return jsonify({"count": len(incidents), "incidents": [inc.to_dict() for inc in incidents]})


@api_bp.route("/incidents/<int:incident_id>", methods=["GET"])
@admin_required
def get_incident_detail(incident_id):
    """Retrieve full details and chronological timeline for a single incident."""
    incident = db.session.get(ThreatIncident, incident_id)
    if not incident:
        return jsonify({"error": f"Incident {incident_id} not found."}), 404

    linked_blocks = [b.to_dict() for b in incident.blocks.all()]
    linked_recoveries = [r.to_dict() for r in incident.recoveries.all()]

    return jsonify(
        {
            "incident": incident.to_dict(include_history=True),
            "linked_blocks": linked_blocks,
            "linked_recoveries": linked_recoveries,
        }
    )


@api_bp.route("/incidents/<int:incident_id>", methods=["PATCH"])
@admin_required
def update_incident_status(incident_id):
    """Update incident status (New, Investigating, Resolved, False Positive) and log audit entry."""
    incident = db.session.get(ThreatIncident, incident_id)
    if not incident:
        return jsonify({"error": f"Incident {incident_id} not found."}), 404

    payload = request.get_json(silent=True) or {}
    new_status = payload.get("status")
    notes = (payload.get("notes") or "").strip()
    actor = (payload.get("actor") or "SOC Analyst").strip()[:64]

    if not new_status or new_status not in VALID_INCIDENT_STATUSES:
        return jsonify(
            {
                "error": f"Invalid status. Must be one of: {', '.join(sorted(VALID_INCIDENT_STATUSES))}."
            }
        ), 400

    old_status = incident.status
    incident.status = new_status
    incident.updated_at = datetime.now(timezone.utc)
    if new_status in ("Resolved", "False Positive"):
        incident.resolved_at = datetime.now(timezone.utc)
    else:
        incident.resolved_at = None

    db.session.add(
        IncidentHistory(
            incident_id=incident.id,
            event_stage="StatusUpdate",
            actor=actor,
            action=f"Status changed from {old_status} to {new_status}",
            notes=notes or "Updated via Incident Management console.",
        )
    )
    db.session.commit()
    persist_health_snapshot()

    return jsonify(
        {
            "message": f"Incident {incident.incident_code} updated to {new_status}.",
            "incident": incident.to_dict(include_history=True),
        }
    )


@api_bp.route("/blocked-sources", methods=["GET"])
@admin_required
def get_blocked_sources():
    """Return active, pending-approval, and historical simulated blocks."""
    # Trigger health check so TTL-expired blocks update automatically
    compute_current_health()
    blocks = BlockedSource.query.order_by(BlockedSource.blocked_at.desc()).all()
    return jsonify(
        {
            "active_count": sum(1 for b in blocks if b.is_active),
            "pending_count": sum(1 for b in blocks if b.pending_approval),
            "blocked_sources": [b.to_dict() for b in blocks],
            "safeguard_note": (
                "All containment actions apply strictly to simulated RFC 5737 test IP identities. "
                "No real host firewall or external network rules are modified."
            ),
        }
    )


@api_bp.route("/blocked-sources/<int:block_id>/unblock", methods=["POST"])
@admin_required
def unblock_source(block_id):
    """Manually unblock a simulated IP address."""
    payload = request.get_json(silent=True) or {}
    actor = (payload.get("actor") or "SOC Administrator").strip()[:64]
    block = unblock_simulated_source(block_id, actor=actor)
    if not block:
        return jsonify({"error": f"Blocked source {block_id} not found."}), 404

    persist_health_snapshot()
    return jsonify(
        {
            "message": f"Simulated source {block.source_ip} has been unblocked.",
            "blocked_source": block.to_dict(),
        }
    )


@api_bp.route("/blocked-sources/<int:block_id>/approve", methods=["POST"])
@admin_required
def approve_block(block_id):
    """Approve a pending human-in-the-loop simulated IP block."""
    payload = request.get_json(silent=True) or {}
    actor = (payload.get("actor") or "SOC Administrator").strip()[:64]
    block = approve_pending_block(block_id, actor=actor)
    if not block:
        return jsonify({"error": f"Blocked source {block_id} not found."}), 404

    persist_health_snapshot()
    return jsonify(
        {
            "message": f"Approved temporary simulated block for {block.source_ip}.",
            "blocked_source": block.to_dict(),
        }
    )


@api_bp.route("/recovery", methods=["GET"])
@admin_required
def get_recovery_status():
    """Return current service recovery posture and historical recovery actions."""
    health = compute_current_health()
    actions = RecoveryAction.query.order_by(RecoveryAction.created_at.desc()).limit(30).all()
    completed = sum(1 for a in actions if a.status == "Completed")
    avg_duration = round(sum(a.duration_ms for a in actions) / len(actions), 1) if actions else 0.0

    return jsonify(
        {
            "current_health": health,
            "stats": {
                "total_recoveries": len(actions),
                "completed_recoveries": completed,
                "failed_recoveries": sum(1 for a in actions if a.status == "Failed"),
                "avg_duration_ms": avg_duration,
            },
            "recovery_actions": [a.to_dict() for a in actions],
            "scope_note": (
                "Recovery Engine operates on local simulated service states and verifies local SQLite health; "
                "it never claims to repair external production servers."
            ),
        }
    )


@api_bp.route("/recovery/trigger", methods=["POST"])
@admin_required
def trigger_manual_recovery():
    """Execute self-recovery from the Self-Recovery console."""
    payload = request.get_json(silent=True) or {}
    target_type = payload.get("target_type", "auto")
    allowed = {"auto", "api_failure", "database_failure", "service_failure", "excessive_errors"}
    if target_type not in allowed:
        return jsonify({"error": f"Invalid target_type. Allowed: {', '.join(sorted(allowed))}"}), 400

    result = execute_recovery(target_type=target_type, actor="SOC Administrator (Self-Recovery)")
    return jsonify(
        {
            "message": f"Self-Recovery {result['recovery_action'].status}: {result['recovery_action'].action_taken}",
            "recovery_action": result["recovery_action"].to_dict(),
            "health_before": result["health_before"],
            "health_after": result["health_after"],
            "resolved_incidents_count": result["resolved_incidents_count"],
        }
    )


@api_bp.route("/recovery/settings", methods=["GET", "PATCH"])
@admin_required
def recovery_settings():
    """Get or update Autonomous Self-Healing Watchdog configuration."""
    if request.method == "GET":
        return jsonify({"auto_heal": get_auto_heal_config()})

    payload = request.get_json(silent=True) or {}
    enabled = payload.get("enabled") if "enabled" in payload else None
    delay_seconds = payload.get("delay_seconds") if "delay_seconds" in payload else None

    if delay_seconds is not None and (not isinstance(delay_seconds, int) or delay_seconds < 2 or delay_seconds > 120):
        return jsonify({"error": "delay_seconds must be an integer between 2 and 120."}), 400

    cfg = set_auto_heal_config(enabled=enabled, delay_seconds=delay_seconds)
    return jsonify(
        {
            "message": f"Autonomous Self-Healing {'enabled' if cfg['enabled'] else 'disabled'} (delay {cfg['delay_seconds']}s).",
            "auto_heal": cfg,
        }
    )


@api_bp.route("/rules", methods=["GET"])
@admin_required
def get_rules():
    """Return configurable detection and response rules."""
    rules = SecurityRule.query.order_by(SecurityRule.id.asc()).all()
    return jsonify({"rules": [r.to_dict() for r in rules]})


@api_bp.route("/rules/<int:rule_id>", methods=["PATCH"])
@admin_required
def update_rule(rule_id):
    """Update configurable threshold, auto-block, or human-approval safeguard on a rule."""
    rule = db.session.get(SecurityRule, rule_id)
    if not rule:
        return jsonify({"error": f"Rule {rule_id} not found."}), 404

    payload = request.get_json(silent=True) or {}
    if "threshold_count" in payload:
        val = payload["threshold_count"]
        if not isinstance(val, int) or val < 1 or val > 1000:
            return jsonify({"error": "threshold_count must be an integer between 1 and 1000."}), 400
        rule.threshold_count = val
    if "window_seconds" in payload:
        val = payload["window_seconds"]
        if not isinstance(val, int) or val < 10 or val > 86400:
            return jsonify({"error": "window_seconds must be an integer between 10 and 86400."}), 400
        rule.window_seconds = val
    if "auto_block_enabled" in payload:
        rule.auto_block_enabled = bool(payload["auto_block_enabled"])
    if "requires_human_approval" in payload:
        rule.requires_human_approval = bool(payload["requires_human_approval"])
    if "is_active" in payload:
        rule.is_active = bool(payload["is_active"])

    rule.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"message": f"Rule '{rule.name}' updated.", "rule": rule.to_dict()})


@api_bp.route("/immune-memory", methods=["GET"])
@admin_required
def get_immune_memory():
    """Return Digital Immune Memory historical pattern catalog and adapted rule weights."""
    return jsonify(get_immune_memory_summary())
