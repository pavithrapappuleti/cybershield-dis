"""User Portal Endpoints & Admin Authentication Routes.

End-user endpoints never expose CyberShield threat scores, rule thresholds,
incident codes, or internal detection telemetry. All security analysis happens
silently in the backend and is visible only inside the Admin SOC Console.
"""

from datetime import datetime, timezone
import zlib
from flask import Blueprint, current_app, jsonify, request, session

from models import BlockedSource
from services.monitoring_service import compute_current_health
from services.workflow_orchestrator import process_security_workflow

auth_bp = Blueprint("auth", __name__, url_prefix="/api")


def resolve_monitored_client_ip():
    """Map interactive portal visitors to deterministic RFC 5737 sandbox IPs.

    This preserves safe simulation isolation even when deployed behind a cloud
    reverse proxy (such as Render) while keeping each remote visitor isolated.
    """
    custom_sim_ip = (request.headers.get("X-Simulated-Client-IP") or "").strip()
    if custom_sim_ip:
        return custom_sim_ip

    forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    remote = forwarded or request.remote_addr or "127.0.0.1"
    if remote in ("127.0.0.1", "::1", "localhost"):
        return "192.0.2.100"

    octet = 101 + (zlib.crc32(remote.encode("utf-8")) % 150)
    return f"192.0.2.{octet}"


def _find_active_block(source_ip):
    compute_current_health()
    return BlockedSource.query.filter_by(source_ip=source_ip, is_active=True).first()


@auth_bp.route("/auth/session", methods=["GET"])
def user_session_status():
    """Return current end-user portal session state."""
    user = session.get("portal_user")
    return jsonify({"authenticated": bool(user), "username": user})


@auth_bp.route("/auth/logout", methods=["POST"])
def user_logout():
    """Sign out of the user portal."""
    session.pop("portal_user", None)
    return jsonify({"authenticated": False, "message": "Signed out."})


@auth_bp.route("/auth/login", methods=["POST"])
def monitored_login():
    """End-user login endpoint silently monitored by CyberShield in the backend."""
    source_ip = resolve_monitored_client_ip()
    active_block = _find_active_block(source_ip)
    if active_block:
        # User sees only a standard lockout message; no internal threat telemetry exposed
        return (
            jsonify(
                {
                    "authenticated": False,
                    "locked": True,
                    "error": (
                        "Your access has been temporarily restricted due to multiple failed sign-in attempts. "
                        "Please try again later or contact an administrator."
                    ),
                }
            ),
            403,
        )

    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""

    if not username or not password:
        return jsonify({"authenticated": False, "error": "Username and password are required."}), 400

    users = current_app.config.get("DEMO_AUTH_USERS", {})
    if users.get(username) == password:
        process_security_workflow(
            source_ip=source_ip,
            event_type="normal_traffic",
            endpoint="/api/auth/login",
            method="POST",
            status_code=200,
            request_count=1,
            failed_login_count=0,
            payload_summary=f"Successful user portal login for '{username}'",
            is_simulated=False,
        )
        session["portal_user"] = username
        return (
            jsonify(
                {
                    "authenticated": True,
                    "username": username,
                    "message": f"Welcome back, {username}.",
                }
            ),
            200,
        )

    # Wrong password: run silent backend detection, risk analysis, and auto-response
    result = process_security_workflow(
        source_ip=source_ip,
        event_type="failed_login_burst",
        endpoint="/api/auth/login",
        method="POST",
        status_code=401,
        request_count=1,
        failed_login_count=1,
        payload_summary=f"Invalid portal login attempt for username '{username}'",
        is_simulated=False,
        title=f"User Portal Brute-Force Detection ({source_ip})",
    )

    blocked_now = bool(result["response"].get("block_applied"))
    if blocked_now:
        return (
            jsonify(
                {
                    "authenticated": False,
                    "locked": True,
                    "error": (
                        "Too many failed sign-in attempts. Your access has been temporarily restricted "
                        "for security. Please try again later or contact an administrator."
                    ),
                }
            ),
            403,
        )

    return (
        jsonify(
            {
                "authenticated": False,
                "locked": False,
                "error": "Invalid username or password. Please try again.",
            }
        ),
        401,
    )


@auth_bp.route("/portal/status", methods=["GET"])
def user_portal_status():
    """Minimal user-facing service status (no internal security/threat telemetry)."""
    health = compute_current_health()
    degraded = health["api_status"] != "Operational" or health["database_status"] != "Operational"
    return jsonify(
        {
            "service_available": not degraded,
            "message": (
                "Portal services are temporarily experiencing disruption. Automated recovery is in progress."
                if degraded
                else "All user portal services are operating normally."
            ),
        }
    )


@auth_bp.route("/admin/debug-console", methods=["GET"])
def restricted_test_endpoint():
    """Restricted endpoint silently audited by CyberShield when probed by users."""
    source_ip = resolve_monitored_client_ip()
    active_block = _find_active_block(source_ip)
    if active_block:
        return jsonify({"allowed": False, "error": "Access denied."}), 403

    process_security_workflow(
        source_ip=source_ip,
        event_type="restricted_endpoint_access",
        endpoint="/api/admin/debug-console",
        method="GET",
        status_code=403,
        request_count=1,
        failed_login_count=0,
        payload_summary="Unauthorized probe to restricted administrative endpoint",
        is_simulated=False,
        title=f"Restricted Endpoint Probe from {source_ip}",
    )
    return jsonify({"allowed": False, "error": "Access denied. Administrator privileges required."}), 403


@auth_bp.route("/records/public", methods=["GET"])
def monitored_public_records():
    """User-facing portal data endpoint silently monitored for burst polling and outages."""
    source_ip = resolve_monitored_client_ip()
    active_block = _find_active_block(source_ip)
    if active_block:
        return jsonify({"error": "Too many requests. Please try again later."}), 429

    health = compute_current_health()
    if health["api_status"] == "Failed" or health["database_status"] == "Failed":
        return (
            jsonify(
                {
                    "error": "Service temporarily unavailable while automated recovery runs. Please retry shortly."
                }
            ),
            503,
        )

    process_security_workflow(
        source_ip=source_ip,
        event_type="repeated_ip_requests",
        endpoint="/api/records/public",
        method="GET",
        status_code=200,
        request_count=1,
        failed_login_count=0,
        payload_summary="User portal resource request (/api/records/public)",
        is_simulated=False,
        title=f"High-Frequency Portal Polling ({source_ip})",
    )
    return jsonify(
        {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "modules": [
                {"name": "Observability & Telemetry", "state": "Active"},
                {"name": "Adaptive Threat Defense", "state": "Active"},
                {"name": "Autonomous Self-Healing", "state": "Active"},
            ],
        }
    ), 200


# --- Admin SOC Authentication Endpoints ---


@auth_bp.route("/admin/session", methods=["GET"])
def admin_session_status():
    """Check whether the current session is authenticated as a CyberShield Admin."""
    admin_user = session.get("admin_user")
    return jsonify(
        {
            "authenticated": bool(admin_user) or not current_app.config.get("ADMIN_AUTH_REQUIRED", True),
            "username": admin_user or ("test-admin" if not current_app.config.get("ADMIN_AUTH_REQUIRED", True) else None),
        }
    )


@auth_bp.route("/admin/login", methods=["POST"])
def admin_login():
    """Authenticate an administrator into the CyberShield SOC Console."""
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""

    admin_users = current_app.config.get("ADMIN_AUTH_USERS", {})
    if admin_users.get(username) == password:
        session["admin_user"] = username
        return jsonify({"authenticated": True, "username": username, "message": "Admin session started."}), 200

    return jsonify({"authenticated": False, "error": "Invalid administrator credentials."}), 401


@auth_bp.route("/admin/logout", methods=["POST"])
def admin_logout():
    """Sign out of the Admin SOC Console."""
    session.pop("admin_user", None)
    return jsonify({"authenticated": False, "message": "Admin signed out."}), 200
