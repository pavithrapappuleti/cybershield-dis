"""Safe Automated Threat Response Engine.

Enforces simulated-only temporary IP isolation with configurable human-approval
safeguards. Never executes host OS firewall commands or touches external networks.
"""

from datetime import datetime, timedelta, timezone
from flask import current_app

from extensions import db
from models import BlockedSource, IncidentHistory
from services.monitoring_service import record_monitoring_log


def is_safe_simulated_ip(source_ip):
    """Verify the target IP belongs to safe RFC 5737 TEST-NET simulation ranges."""
    prefixes = current_app.config.get(
        "SIMULATED_IP_PREFIXES", ("192.0.2.", "198.51.100.", "203.0.113.")
    )
    return any(source_ip.startswith(prefix) for prefix in prefixes)


def evaluate_and_apply_response(incident, detection_result, risk_result):
    """Apply safe simulated blocking if thresholds and risk score warrant it."""
    if not detection_result.get("is_threat"):
        return {
            "action_taken": "Logged only (benign or below threshold)",
            "block_applied": False,
            "pending_approval": False,
            "blocked_source": None,
        }

    event_type = detection_result["event_type"]
    if event_type in ("service_failure", "database_failure", "excessive_errors"):
        return {
            "action_taken": "Escalated to Self-Recovery Engine (availability incident)",
            "block_applied": False,
            "pending_approval": False,
            "blocked_source": None,
        }

    rule = detection_result.get("matched_rule")
    risk_score = risk_result["risk_score"]
    severity = risk_result["severity"]
    source_ip = incident.source_ip

    # Only block when score >= 60 (High/Critical) or rule explicitly enables auto-block
    should_block = risk_score >= 60 or (rule and rule.auto_block_enabled and severity in ("High", "Critical"))
    if not should_block:
        action_msg = f"Monitored & flagged ({severity}, score {risk_score}/100); below containment threshold"
        incident.response_action = action_msg
        return {
            "action_taken": action_msg,
            "block_applied": False,
            "pending_approval": False,
            "blocked_source": None,
        }

    # Safety guardrail: refuse real external IPs
    if not is_safe_simulated_ip(source_ip):
        action_msg = (
            f"Safeguard blocked containment: {source_ip} is outside RFC 5737 simulated IP ranges."
        )
        incident.response_action = action_msg
        return {
            "action_taken": action_msg,
            "block_applied": False,
            "pending_approval": False,
            "blocked_source": None,
        }

    requires_approval = bool(
        (rule and rule.requires_human_approval)
        or (
            severity == "Critical"
            and current_app.config.get("REQUIRE_HUMAN_APPROVAL_FOR_CRITICAL", False)
        )
    )

    now = datetime.now(timezone.utc)
    ttl_minutes = current_app.config.get("DEFAULT_BLOCK_MINUTES", 15)
    expires_at = now + timedelta(minutes=ttl_minutes)

    existing = BlockedSource.query.filter_by(source_ip=source_ip, is_active=True).first()
    if existing:
        existing.expires_at = expires_at
        existing.risk_score = max(existing.risk_score, risk_score)
        existing.severity = severity
        existing.reason = detection_result["detection_reason"]
        action_msg = f"Extended temporary simulated block on {source_ip} (+{ttl_minutes}m)"
        incident.response_action = action_msg
        db.session.add(
            IncidentHistory(
                incident_id=incident.id,
                event_stage="Response",
                actor="Automated Response Engine",
                action=action_msg,
                notes="Existing simulated isolation window refreshed.",
            )
        )
        db.session.commit()
        return {
            "action_taken": action_msg,
            "block_applied": True,
            "pending_approval": False,
            "blocked_source": existing,
        }

    block = BlockedSource(
        source_ip=source_ip,
        reason=detection_result["detection_reason"],
        severity=severity,
        risk_score=risk_score,
        is_active=not requires_approval,
        pending_approval=requires_approval,
        is_simulated=True,
        approval_mode="human_approval_required" if requires_approval else "automated_safeguarded",
        blocked_at=now,
        expires_at=expires_at if not requires_approval else None,
        incident_id=incident.id,
    )
    db.session.add(block)

    if requires_approval:
        action_msg = f"Queued simulated IP block for {source_ip} (awaiting human approval)"
    else:
        action_msg = f"Temporarily blocked simulated IP {source_ip} for {ttl_minutes} min"

    incident.response_action = action_msg
    db.session.add(
        IncidentHistory(
            incident_id=incident.id,
            event_stage="Response",
            actor="Automated Response Engine",
            action=action_msg,
            notes=f"Safeguard verified (RFC 5737 test IP). Mode: {block.approval_mode}.",
        )
    )
    db.session.commit()

    record_monitoring_log(
        category="automated_response",
        level="WARNING",
        message=action_msg,
        source="ResponseEngine",
        is_simulated=True,
    )

    return {
        "action_taken": action_msg,
        "block_applied": not requires_approval,
        "pending_approval": requires_approval,
        "blocked_source": block,
    }


def approve_pending_block(block_id, actor="SOC Administrator"):
    """Approve a pending human-in-the-loop simulated IP block."""
    block = db.session.get(BlockedSource, block_id)
    if not block:
        return None
    now = datetime.now(timezone.utc)
    ttl_minutes = current_app.config.get("DEFAULT_BLOCK_MINUTES", 15)
    block.pending_approval = False
    block.is_active = True
    block.blocked_at = now
    block.expires_at = now + timedelta(minutes=ttl_minutes)
    block.approval_mode = f"approved_by:{actor}"

    if block.incident_id:
        db.session.add(
            IncidentHistory(
                incident_id=block.incident_id,
                event_stage="Response",
                actor=actor,
                action=f"Approved temporary simulated block on {block.source_ip}",
                notes=f"Expires at {block.expires_at.isoformat()}",
            )
        )
    db.session.commit()
    return block


def unblock_simulated_source(block_id, actor="SOC Administrator"):
    """Manually release a simulated IP block."""
    block = db.session.get(BlockedSource, block_id)
    if not block:
        return None
    now = datetime.now(timezone.utc)
    block.is_active = False
    block.pending_approval = False
    block.unblocked_at = now
    block.unblocked_by = actor

    if block.incident_id:
        db.session.add(
            IncidentHistory(
                incident_id=block.incident_id,
                event_stage="Response",
                actor=actor,
                action=f"Manually unblocked simulated IP {block.source_ip}",
                notes="Administrator cleared temporary containment.",
            )
        )
    db.session.commit()
    record_monitoring_log(
        category="manual_unblock",
        level="INFO",
        message=f"Simulated IP {block.source_ip} unblocked by {actor}.",
        source="ResponseEngine",
        is_simulated=True,
    )
    return block
