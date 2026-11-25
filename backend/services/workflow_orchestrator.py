"""End-to-End Digital Immune System Workflow Orchestrator.

Executes the complete pipeline:
  Application Monitoring -> Event Collection -> Threat Detection ->
  Risk Assessment -> Decision Engine -> Automated Response ->
  Self-Recovery (when applicable) -> Incident Logging -> Historical Pattern Analysis
"""

from datetime import datetime, timezone
import json

from extensions import db
from models import IncidentHistory, SecurityEvent, ThreatIncident
from services.immune_memory import count_pattern_occurrences, update_immune_memory
from services.monitoring_service import (
    compute_current_health,
    persist_health_snapshot,
    record_monitoring_log,
)
from services.recovery_engine import trigger_simulated_failure
from services.response_engine import evaluate_and_apply_response
from services.risk_analysis import active_risk_analyzer
from services.threat_detection import evaluate_event


def _next_incident_code():
    year = datetime.now(timezone.utc).year
    last = ThreatIncident.query.order_by(ThreatIncident.id.desc()).first()
    next_num = (last.id + 1) if last else 1
    return f"INC-{year}-{next_num:04d}"


def process_security_workflow(
    source_ip,
    event_type,
    endpoint="/api/auth/login",
    method="POST",
    status_code=200,
    request_count=1,
    failed_login_count=0,
    payload_summary=None,
    is_simulated=True,
    title=None,
):
    """Run all stages of the Digital Immune System workflow and return full trace."""
    steps = []

    # 1. Application Monitoring
    pre_health = compute_current_health()
    steps.append(
        {
            "stage": "1. Application Monitoring",
            "status": "completed",
            "summary": (
                f"Baseline health checked: {pre_health['overall_status']} "
                f"(SQLite ping {pre_health['real_metrics']['sqlite_ping_ms']} ms)."
            ),
        }
    )

    # 2. Event Collection (create event shell, finalized after detection & risk)
    event = SecurityEvent(
        source_ip=source_ip,
        event_type=event_type,
        endpoint=endpoint,
        method=method,
        status_code=status_code,
        request_count=request_count,
        failed_login_count=failed_login_count,
        payload_summary=payload_summary or f"{method} {endpoint} (count={request_count})",
        is_simulated=is_simulated,
    )
    steps.append(
        {
            "stage": "2. Event Collection",
            "status": "completed",
            "summary": f"Collected telemetry from {source_ip} on {endpoint} ({event_type}).",
        }
    )

    # 3. Threat Detection
    detection = evaluate_event(
        source_ip=source_ip,
        event_type=event_type,
        endpoint=endpoint,
        method=method,
        status_code=status_code,
        request_count=request_count,
        failed_login_count=failed_login_count,
    )
    steps.append(
        {
            "stage": "3. Threat Detection",
            "status": "threat_detected" if detection["is_threat"] else "benign",
            "summary": detection["detection_reason"],
        }
    )

    # 4. Risk Assessment (use cumulative window totals for burst detections)
    immune_hits = count_pattern_occurrences(detection["immune_signature"])
    if detection["is_threat"]:
        ratio_rep = int((detection["observed_count"] / max(1, detection["threshold"])) * 3) + 1
        repetition_count = max(4, ratio_rep)
    else:
        repetition_count = 1

    effective_failed = (
        detection["observed_count"] if event_type == "failed_login_burst" else failed_login_count
    )
    effective_reqs = (
        detection["observed_count"]
        if event_type in ("suspicious_frequency", "repeated_ip_requests", "failed_login_burst")
        else request_count
    )

    risk = active_risk_analyzer.analyze(
        event_type=event_type,
        failed_login_count=effective_failed,
        request_count=effective_reqs,
        repetition_count=repetition_count,
        immune_history_hits=immune_hits,
        rule=detection.get("matched_rule"),
    )
    event.risk_score = risk["risk_score"]
    event.severity = risk["severity"]
    event.is_threat = detection["is_threat"]
    event.detection_reason = detection["detection_reason"]

    db.session.add(event)
    db.session.flush()

    steps.append(
        {
            "stage": "4. Risk Assessment",
            "status": risk["severity"].lower(),
            "summary": risk["explanation"],
        }
    )

    record_monitoring_log(
        category="security_event",
        level="WARNING" if detection["is_threat"] else "INFO",
        message=f"[{risk['severity']} {risk['risk_score']}/100] {detection['detection_reason']}",
        source="ThreatDetection",
        is_simulated=is_simulated,
    )

    # If benign or single below-threshold anomaly (false alarm prevented), stop cleanly without creating an incident
    if not detection["is_threat"]:
        db.session.commit()
        post_health = compute_current_health()
        persist_health_snapshot(post_health)
        steps.extend(
            [
                {
                    "stage": "5. Decision Engine",
                    "status": "skipped",
                    "summary": "No threat threshold exceeded; classified as normal/low-risk observation.",
                },
                {
                    "stage": "6. Automated Response",
                    "status": "skipped",
                    "summary": "No blocking action taken (false-alarm prevention active).",
                },
                {
                    "stage": "7. Self-Recovery",
                    "status": "not_needed",
                    "summary": "All services operational; no recovery needed.",
                },
                {
                    "stage": "8. Incident Logging",
                    "status": "logged_event_only",
                    "summary": f"Recorded SecurityEvent #{event.id} in SQLite without escalating to incident.",
                },
                {
                    "stage": "9. Historical Pattern Analysis",
                    "status": "completed",
                    "summary": "Baseline telemetry updated.",
                },
            ]
        )
        return {
            "event": event,
            "incident": None,
            "detection": detection,
            "risk": risk,
            "response": {"action_taken": "None required", "block_applied": False, "pending_approval": False},
            "immune_memory": None,
            "health": post_health,
            "workflow_steps": steps,
        }

    # 5. Decision Engine & Incident Creation
    incident_title = title or f"{event_type.replace('_', ' ').title()} from {source_ip}"
    incident = ThreatIncident(
        incident_code=_next_incident_code(),
        title=incident_title,
        source_ip=source_ip,
        event_type=event_type,
        severity=risk["severity"],
        risk_score=risk["risk_score"],
        status="New",
        detection_reason=detection["detection_reason"],
        risk_breakdown_json=json.dumps(risk["breakdown"]),
        recommended_response=risk["recommended_response"],
        response_action="Evaluating automated response...",
        immune_signature=detection["immune_signature"],
        occurrence_count=detection["observed_count"],
        event_id=event.id,
    )
    db.session.add(incident)
    db.session.flush()

    db.session.add_all(
        [
            IncidentHistory(
                incident_id=incident.id,
                event_stage="Monitoring",
                actor="FlaskMonitor",
                action="Telemetry captured",
                notes=f"Endpoint {endpoint} ({method}), HTTP {status_code}.",
            ),
            IncidentHistory(
                incident_id=incident.id,
                event_stage="Detection",
                actor="Rule-Based Threat Detector",
                action=f"Rule matched ({event_type})",
                notes=detection["detection_reason"],
            ),
            IncidentHistory(
                incident_id=incident.id,
                event_stage="RiskAssessment",
                actor=risk["engine_name"],
                action=f"Assigned {risk['severity']} risk ({risk['risk_score']}/100)",
                notes=risk["explanation"],
            ),
        ]
    )
    db.session.commit()

    steps.append(
        {
            "stage": "5. Decision Engine",
            "status": "escalated",
            "summary": f"Escalated to {incident.incident_code} ({risk['severity']}, {risk['risk_score']}/100). Recommended: {risk['recommended_response']}",
        }
    )

    # 6. Automated Response
    response = evaluate_and_apply_response(incident, detection, risk)
    steps.append(
        {
            "stage": "6. Automated Response",
            "status": "completed",
            "summary": response["action_taken"],
        }
    )

    # 7. Self-Recovery / Fault Injection check
    if event_type in ("service_failure", "database_failure", "api_failure", "excessive_errors"):
        fault_kind = "api_failure" if event_type == "service_failure" else event_type
        trigger_simulated_failure(fault_kind, reason=detection["detection_reason"])
        steps.append(
            {
                "stage": "7. Self-Recovery",
                "status": "failure_detected",
                "summary": (
                    f"Simulated {fault_kind.replace('_', ' ')} detected. Ready for autonomous or "
                    "manual Self-Recovery Engine restoration."
                ),
            }
        )
    else:
        steps.append(
            {
                "stage": "7. Self-Recovery",
                "status": "not_needed",
                "summary": "Core application services remain Operational; containment isolated threat source.",
            }
        )

    # 8. Incident Logging
    steps.append(
        {
            "stage": "8. Incident Logging",
            "status": "completed",
            "summary": f"Persisted {incident.incident_code} and chronological audit trail in SQLite.",
        }
    )

    # 9. Historical Pattern Analysis (Digital Immune Memory)
    memory_update = update_immune_memory(incident, detection, response)
    steps.append(
        {
            "stage": "9. Historical Pattern Analysis",
            "status": "completed",
            "summary": memory_update["note"],
        }
    )

    post_health = compute_current_health()
    persist_health_snapshot(post_health)

    return {
        "event": event,
        "incident": incident,
        "detection": detection,
        "risk": risk,
        "response": {
            "action_taken": response["action_taken"],
            "block_applied": response["block_applied"],
            "pending_approval": response["pending_approval"],
            "blocked_source": response["blocked_source"].to_dict() if response["blocked_source"] else None,
        },
        "immune_memory": memory_update,
        "health": post_health,
        "workflow_steps": steps,
    }
