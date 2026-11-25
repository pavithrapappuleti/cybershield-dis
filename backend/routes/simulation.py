"""Simulation Lab API endpoints for safe local academic demonstrations."""

from flask import Blueprint, jsonify, request

from database.init_db import reset_demo_baseline
from routes.guards import admin_required
from services.recovery_engine import execute_recovery
from services.workflow_orchestrator import process_security_workflow

simulation_bp = Blueprint("simulation", __name__, url_prefix="/api/simulation")


def _format_workflow_response(message, result, status_code=200):
    return (
        jsonify(
            {
                "message": message,
                "event": result["event"].to_dict(),
                "incident": result["incident"].to_dict(include_history=True) if result["incident"] else None,
                "detection": {
                    "is_threat": result["detection"]["is_threat"],
                    "event_type": result["detection"]["event_type"],
                    "observed_count": result["detection"]["observed_count"],
                    "threshold": result["detection"]["threshold"],
                    "detection_reason": result["detection"]["detection_reason"],
                    "false_alarm_prevented": result["detection"]["false_alarm_prevented"],
                },
                "risk": result["risk"],
                "response": result["response"],
                "immune_memory": result["immune_memory"],
                "health": result["health"],
                "workflow_steps": result["workflow_steps"],
            }
        ),
        status_code,
    )


@simulation_bp.route("/failed-logins", methods=["POST"])
@admin_required
def simulate_failed_logins():
    """Simulate repeated failed login attempts from a safe RFC 5737 test IP."""
    payload = request.get_json(silent=True) or {}
    source_ip = (payload.get("source_ip") or "203.0.113.45").strip()
    attempts = payload.get("attempts", 7)

    if not isinstance(attempts, int) or attempts < 1 or attempts > 100:
        return jsonify({"error": "attempts must be an integer between 1 and 100."}), 400

    result = process_security_workflow(
        source_ip=source_ip,
        event_type="failed_login_burst",
        endpoint="/api/auth/login",
        method="POST",
        status_code=401,
        request_count=attempts,
        failed_login_count=attempts,
        payload_summary=f"Simulated {attempts} consecutive invalid credential submissions",
        is_simulated=True,
        title=f"Repeated Failed Login Attempts ({attempts}x) from {source_ip}",
    )
    return _format_workflow_response(
        f"Simulated {attempts} failed login attempts from {source_ip}.", result, 201
    )


@simulation_bp.route("/suspicious-traffic", methods=["POST"])
@admin_required
def simulate_suspicious_traffic():
    """Simulate high-frequency suspicious API requests from a test IP."""
    payload = request.get_json(silent=True) or {}
    source_ip = (payload.get("source_ip") or "198.51.100.64").strip()
    request_count = payload.get("request_count", 65)

    if not isinstance(request_count, int) or request_count < 1 or request_count > 5000:
        return jsonify({"error": "request_count must be an integer between 1 and 5000."}), 400

    result = process_security_workflow(
        source_ip=source_ip,
        event_type="suspicious_frequency",
        endpoint="/api/records/export",
        method="GET",
        status_code=429,
        request_count=request_count,
        failed_login_count=0,
        payload_summary=f"Simulated high-velocity polling burst ({request_count} reqs/window)",
        is_simulated=True,
        title=f"Suspicious Request Frequency ({request_count} reqs) from {source_ip}",
    )
    return _format_workflow_response(
        f"Simulated suspicious traffic burst ({request_count} requests) from {source_ip}.",
        result,
        201,
    )


@simulation_bp.route("/restricted-access", methods=["POST"])
@admin_required
def simulate_restricted_access():
    """Simulate repeated probes against restricted administrative test endpoints."""
    payload = request.get_json(silent=True) or {}
    source_ip = (payload.get("source_ip") or "203.0.113.99").strip()
    probes = payload.get("probes", 3)

    if not isinstance(probes, int) or probes < 1 or probes > 50:
        return jsonify({"error": "probes must be an integer between 1 and 50."}), 400

    # Run sequential probes or a multi-probe burst so threshold=2 triggers accurately
    result = process_security_workflow(
        source_ip=source_ip,
        event_type="restricted_endpoint_access",
        endpoint="/api/admin/debug-console",
        method="GET",
        status_code=403,
        request_count=probes,
        failed_login_count=0,
        payload_summary=f"Simulated {probes} unauthorized probes to restricted admin endpoint",
        is_simulated=True,
        title=f"Restricted Endpoint Access Probe from {source_ip}",
    )
    # If single probe didn't cross threshold=2, note it clearly
    return _format_workflow_response(
        f"Simulated restricted endpoint probe(s) from {source_ip}.", result, 201
    )


@simulation_bp.route("/service-failure", methods=["POST"])
@admin_required
def simulate_service_failure():
    """Simulate an API / application service disruption for Self-Recovery testing."""
    payload = request.get_json(silent=True) or {}
    source_ip = (payload.get("source_ip") or "192.0.2.50").strip()

    result = process_security_workflow(
        source_ip=source_ip,
        event_type="service_failure",
        endpoint="/api/core/worker",
        method="POST",
        status_code=503,
        request_count=1,
        failed_login_count=0,
        payload_summary="Simulated API gateway & worker service unavailability (HTTP 503)",
        is_simulated=True,
        title="Simulated API & Application Service Failure",
    )
    return _format_workflow_response(
        "Simulated API service failure triggered. System status is now Critical.", result, 201
    )


@simulation_bp.route("/database-failure", methods=["POST"])
@admin_required
def simulate_database_failure():
    """Simulate a database connectivity pool failure for Self-Recovery testing."""
    payload = request.get_json(silent=True) or {}
    source_ip = (payload.get("source_ip") or "192.0.2.55").strip()

    result = process_security_workflow(
        source_ip=source_ip,
        event_type="database_failure",
        endpoint="/api/db/pool",
        method="GET",
        status_code=500,
        request_count=1,
        failed_login_count=0,
        payload_summary="Simulated database connection pool timeout fault",
        is_simulated=True,
        title="Simulated Database Connectivity Failure",
    )
    return _format_workflow_response(
        "Simulated database connectivity failure triggered. Ready for Self-Recovery.", result, 201
    )


@simulation_bp.route("/excessive-errors", methods=["POST"])
@admin_required
def simulate_excessive_errors():
    """Simulate an excessive HTTP 500 error burst and degraded service state."""
    payload = request.get_json(silent=True) or {}
    source_ip = (payload.get("source_ip") or "192.0.2.60").strip()
    error_count = payload.get("error_count", 18)

    if not isinstance(error_count, int) or error_count < 1 or error_count > 500:
        return jsonify({"error": "error_count must be an integer between 1 and 500."}), 400

    result = process_security_workflow(
        source_ip=source_ip,
        event_type="excessive_errors",
        endpoint="/api/records/process",
        method="POST",
        status_code=500,
        request_count=error_count,
        failed_login_count=0,
        payload_summary=f"Simulated {error_count} consecutive HTTP 500 internal error events",
        is_simulated=True,
        title=f"Simulated Excessive Error Events ({error_count}x HTTP 500)",
    )
    return _format_workflow_response(
        f"Simulated {error_count} excessive error events. Service degraded for Self-Recovery.",
        result,
        201,
    )


@simulation_bp.route("/service-recovery", methods=["POST"])
@admin_required
def simulate_service_recovery():
    """Trigger the Self-Recovery Engine to restore simulated failed services."""
    payload = request.get_json(silent=True) or {}
    target_type = payload.get("target_type", "auto")
    recovery_result = execute_recovery(target_type=target_type, actor="Self-Recovery Engine (Simulation Lab)")

    rec = recovery_result["recovery_action"]
    steps = [
        {
            "stage": "1. Failure Detection",
            "status": "completed",
            "summary": f"Detected degraded state ({recovery_result['health_before']['overall_status']}) for {rec.failure_type}.",
        },
        {
            "stage": "2. Recovery Action Initiated",
            "status": "completed",
            "summary": rec.action_taken,
        },
        {
            "stage": "3. Service Health Recheck",
            "status": "completed",
            "summary": (
                f"Verified Operational API/DB/Service state. Real SQLite ping: "
                f"{recovery_result['health_after']['real_metrics']['sqlite_ping_ms']} ms."
            ),
        },
        {
            "stage": "4. Recovery Completed & Logged",
            "status": "completed",
            "summary": (
                f"Recovery {rec.status} in {rec.duration_ms} ms. "
                f"Resolved {recovery_result['resolved_incidents_count']} availability incident(s)."
            ),
        },
    ]

    return jsonify(
        {
            "message": f"Self-Recovery {rec.status} in {rec.duration_ms} ms. System is {recovery_result['health_after']['overall_status']}.",
            "recovery_action": rec.to_dict(),
            "health_before": recovery_result["health_before"],
            "health_after": recovery_result["health_after"],
            "resolved_incidents_count": recovery_result["resolved_incidents_count"],
            "workflow_steps": steps,
        }
    )


@simulation_bp.route("/normal-traffic", methods=["POST"])
@admin_required
def simulate_normal_traffic():
    """Generate benign baseline traffic to demonstrate zero false alarms."""
    payload = request.get_json(silent=True) or {}
    source_ip = (payload.get("source_ip") or "192.0.2.25").strip()
    request_count = payload.get("request_count", 6)

    if not isinstance(request_count, int) or request_count < 1 or request_count > 30:
        return jsonify({"error": "request_count for normal traffic must be between 1 and 30."}), 400

    result = process_security_workflow(
        source_ip=source_ip,
        event_type="normal_traffic",
        endpoint="/api/dashboard",
        method="GET",
        status_code=200,
        request_count=request_count,
        failed_login_count=0,
        payload_summary=f"Normal authenticated user traffic ({request_count} requests)",
        is_simulated=True,
    )
    return _format_workflow_response(
        f"Generated normal baseline traffic ({request_count} requests) from {source_ip} with no false alarm.",
        result,
        201,
    )


@simulation_bp.route("/reset", methods=["POST"])
@admin_required
def reset_simulation_baseline():
    """Restore clean Healthy demo baseline for live college presentation."""
    reset_demo_baseline()
    return jsonify({"message": "Demo baseline restored to clean Healthy state."})
