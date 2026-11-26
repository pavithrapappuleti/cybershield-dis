"""Application Monitoring Service.

Tracks real Flask process telemetry (uptime, HTTP requests, response latency,
SQLite connectivity check) separately from simulated service states used for
safe academic failure and self-recovery demonstrations.
"""

from collections import deque
from datetime import datetime, timedelta, timezone
import json
import threading
import time
from sqlalchemy import text

from extensions import db
from models import BlockedSource, SecurityEvent, SecurityRule, SystemHealth, ThreatIncident

# Real in-process application telemetry
_START_MONOTONIC = time.monotonic()
_START_UTC = datetime.now(timezone.utc)
_REAL_REQUEST_COUNT = 0
_REAL_ERROR_COUNT = 0
_RECENT_LATENCIES_MS = deque(maxlen=100)
_MONITORING_EVENTS = deque(maxlen=80)

# Simulated infrastructure/service state for safe self-recovery demos
_SIMULATED_STATE = {
    "api_status": "Operational",
    "database_status": "Operational",
    "service_status": "Operational",
    "failure_reason": None,
    "last_changed_at": datetime.now(timezone.utc).isoformat(),
    "failed_since_monotonic": None,
}

# Autonomous Self-Healing Watchdog state
_AUTO_HEAL_CONFIG = {
    "enabled": True,
    "delay_seconds": 6,
}
_WATCHDOG_STARTED = False
_WATCHDOG_LOCK = threading.Lock()
_LOGIN_WARNING_DISMISSED_AT = {}


def record_monitoring_log(category, message, level="INFO", source="FlaskMonitor", is_simulated=False):
    """Append a structured monitoring event to the in-memory ring buffer."""
    _MONITORING_EVENTS.appendleft(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "category": category,
            "level": level,
            "source": source,
            "message": message,
            "is_simulated": is_simulated,
        }
    )


def record_http_activity(path, method, status_code, latency_ms):
    """Record real Flask request metrics from middleware."""
    global _REAL_REQUEST_COUNT, _REAL_ERROR_COUNT
    _REAL_REQUEST_COUNT += 1
    _RECENT_LATENCIES_MS.append(latency_ms)

    if status_code >= 400:
        _REAL_ERROR_COUNT += 1
        record_monitoring_log(
            category="http_error",
            level="WARNING" if status_code < 500 else "ERROR",
            message=f"{method} {path} returned HTTP {status_code} ({latency_ms:.1f} ms)",
            source="FlaskMiddleware",
            is_simulated=False,
        )
    elif path.startswith("/api/simulation"):
        record_monitoring_log(
            category="simulation_trigger",
            level="INFO",
            message=f"Simulation endpoint {method} {path} executed ({latency_ms:.1f} ms)",
            source="FlaskMiddleware",
            is_simulated=False,
        )


def check_real_database_health():
    """Run a lightweight real SQLite SELECT 1 check and measure latency."""
    started = time.perf_counter()
    try:
        db.session.execute(text("SELECT 1"))
        latency_ms = (time.perf_counter() - started) * 1000.0
        return {"reachable": True, "latency_ms": round(latency_ms, 2), "error": None}
    except Exception as exc:  # pragma: no cover - defensive fallback
        latency_ms = (time.perf_counter() - started) * 1000.0
        return {"reachable": False, "latency_ms": round(latency_ms, 2), "error": str(exc)}


def set_simulated_service_state(api_status=None, database_status=None, service_status=None, reason=None):
    """Update simulated service states for failure and recovery testing."""
    if api_status is not None:
        _SIMULATED_STATE["api_status"] = api_status
    if database_status is not None:
        _SIMULATED_STATE["database_status"] = database_status
    if service_status is not None:
        _SIMULATED_STATE["service_status"] = service_status
    _SIMULATED_STATE["failure_reason"] = reason
    _SIMULATED_STATE["last_changed_at"] = datetime.now(timezone.utc).isoformat()
    is_unhealthy = any(
        _SIMULATED_STATE[k] != "Operational"
        for k in ("api_status", "database_status", "service_status")
    )
    if is_unhealthy and _SIMULATED_STATE["failed_since_monotonic"] is None:
        _SIMULATED_STATE["failed_since_monotonic"] = time.monotonic()
    elif not is_unhealthy:
        _SIMULATED_STATE["failed_since_monotonic"] = None

    record_monitoring_log(
        category="simulated_service_state",
        level="CRITICAL" if "Failed" in _SIMULATED_STATE.values() else "INFO",
        message=(
            f"Simulated state updated -> API: {_SIMULATED_STATE['api_status']}, "
            f"DB: {_SIMULATED_STATE['database_status']}, Service: {_SIMULATED_STATE['service_status']}"
            + (f" ({reason})" if reason else "")
        ),
        source="SimulationState",
        is_simulated=True,
    )


def get_simulated_state():
    """Return a copy of the simulated infrastructure state."""
    return dict(_SIMULATED_STATE)


def get_auto_heal_config():
    """Return current autonomous self-healing watchdog settings."""
    failed_since = _SIMULATED_STATE.get("failed_since_monotonic")
    seconds_until_heal = None
    if _AUTO_HEAL_CONFIG["enabled"] and failed_since is not None:
        elapsed = time.monotonic() - failed_since
        seconds_until_heal = max(0.0, round(_AUTO_HEAL_CONFIG["delay_seconds"] - elapsed, 1))
    return {
        "enabled": _AUTO_HEAL_CONFIG["enabled"],
        "delay_seconds": _AUTO_HEAL_CONFIG["delay_seconds"],
        "seconds_until_heal": seconds_until_heal,
    }


def set_auto_heal_config(enabled=None, delay_seconds=None):
    """Update autonomous self-healing settings."""
    if enabled is not None:
        _AUTO_HEAL_CONFIG["enabled"] = bool(enabled)
    if delay_seconds is not None:
        _AUTO_HEAL_CONFIG["delay_seconds"] = max(2, min(120, int(delay_seconds)))
    record_monitoring_log(
        category="watchdog_config",
        level="INFO",
        message=(
            f"Autonomous Self-Healing Watchdog set to "
            f"{'ENABLED' if _AUTO_HEAL_CONFIG['enabled'] else 'DISABLED'} "
            f"(delay={_AUTO_HEAL_CONFIG['delay_seconds']}s)."
        ),
        source="SelfHealingWatchdog",
        is_simulated=False,
    )
    return get_auto_heal_config()


def start_autonomous_watchdog(app):
    """Launch background daemon thread that autonomously heals degraded simulated services."""
    global _WATCHDOG_STARTED
    with _WATCHDOG_LOCK:
        if _WATCHDOG_STARTED:
            return
        _WATCHDOG_STARTED = True

    def _watchdog_loop():
        from services.recovery_engine import execute_recovery

        while True:
            time.sleep(2.0)
            try:
                if not _AUTO_HEAL_CONFIG["enabled"]:
                    continue
                failed_since = _SIMULATED_STATE.get("failed_since_monotonic")
                if failed_since is None:
                    continue
                if (time.monotonic() - failed_since) >= _AUTO_HEAL_CONFIG["delay_seconds"]:
                    with app.app_context():
                        execute_recovery(
                            target_type="auto",
                            actor="Autonomous Self-Healing Watchdog",
                        )
            except Exception as exc:  # pragma: no cover - defensive daemon guard
                record_monitoring_log(
                    category="watchdog_error",
                    level="ERROR",
                    message=f"Watchdog iteration error: {exc}",
                    source="SelfHealingWatchdog",
                    is_simulated=False,
                )

    t = threading.Thread(target=_watchdog_loop, name="cybershield-watchdog", daemon=True)
    t.start()


def reset_monitoring_state():
    """Reset simulated state and error counters for a clean demo baseline."""
    global _REAL_ERROR_COUNT
    _REAL_ERROR_COUNT = 0
    _LOGIN_WARNING_DISMISSED_AT.clear()
    _SIMULATED_STATE["api_status"] = "Operational"
    _SIMULATED_STATE["database_status"] = "Operational"
    _SIMULATED_STATE["service_status"] = "Operational"
    _SIMULATED_STATE["failure_reason"] = None
    _SIMULATED_STATE["last_changed_at"] = datetime.now(timezone.utc).isoformat()
    _SIMULATED_STATE["failed_since_monotonic"] = None
    _MONITORING_EVENTS.clear()
    record_monitoring_log(
        category="baseline_reset",
        level="INFO",
        message="Monitoring baseline restored to Healthy operational state.",
        source="FlaskMonitor",
        is_simulated=False,
    )


def _as_naive_utc(dt):
    return dt.replace(tzinfo=None) if dt and dt.tzinfo else dt


def get_login_streak_cutoff(source_ip, since_naive):
    """Return (cutoff_dt, is_explicit_clear) so unblocked/resolved/dismissed streaks restart cleanly."""
    cutoff = _LOGIN_WARNING_DISMISSED_AT.get(source_ip)
    wildcard_cutoff = _LOGIN_WARNING_DISMISSED_AT.get("*")
    if wildcard_cutoff and (cutoff is None or wildcard_cutoff > cutoff):
        cutoff = wildcard_cutoff
    is_explicit = cutoff is not None

    latest_unblocked = (
        BlockedSource.query.filter(
            BlockedSource.source_ip == source_ip,
            BlockedSource.unblocked_at.isnot(None),
        )
        .order_by(BlockedSource.unblocked_at.desc())
        .first()
    )
    if latest_unblocked and latest_unblocked.unblocked_at:
        ub_dt = _as_naive_utc(latest_unblocked.unblocked_at)
        if cutoff is None or ub_dt > cutoff:
            cutoff = ub_dt
            is_explicit = True

    latest_resolved = (
        ThreatIncident.query.filter(
            ThreatIncident.source_ip == source_ip,
            ThreatIncident.event_type == "failed_login_burst",
            ThreatIncident.status.in_(["Resolved", "False Positive"]),
            ThreatIncident.resolved_at.isnot(None),
        )
        .order_by(ThreatIncident.resolved_at.desc())
        .first()
    )
    if latest_resolved and latest_resolved.resolved_at:
        res_dt = _as_naive_utc(latest_resolved.resolved_at)
        if cutoff is None or res_dt > cutoff:
            cutoff = res_dt
            is_explicit = True

    if cutoff is None or since_naive > cutoff:
        return since_naive, False
    return cutoff, is_explicit


def dismiss_login_warnings(source_ip=None):
    """Clear active wrong-login warnings so the admin monitor returns cleanly to Healthy."""
    now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    if source_ip:
        _LOGIN_WARNING_DISMISSED_AT[source_ip] = now_naive
    else:
        _LOGIN_WARNING_DISMISSED_AT["*"] = now_naive
    record_monitoring_log(
        category="warning_cleared",
        level="INFO",
        message=f"Administrator cleared wrong-login warning state ({source_ip or 'all sources'}).",
        source="AdminMonitor",
        is_simulated=False,
    )


def _collect_login_warning_state(now_naive):
    """Identify IPs with recent unresolved failed login attempts (triggers Warning at 2+)."""
    since = now_naive - timedelta(seconds=300)
    recent_failed = (
        SecurityEvent.query.filter(
            SecurityEvent.event_type == "failed_login_burst",
            SecurityEvent.created_at >= since,
        )
        .order_by(SecurityEvent.created_at.asc())
        .all()
    )

    by_ip = {}
    for ev in recent_failed:
        by_ip.setdefault(ev.source_ip, []).append(ev)

    # Also surface any active blocks on login even if older than 5m
    active_login_blocks = BlockedSource.query.filter_by(is_active=True).all()
    for blk in active_login_blocks:
        by_ip.setdefault(blk.source_ip, [])

    login_rule = SecurityRule.query.filter_by(event_type="failed_login_burst", is_active=True).first()
    block_threshold = login_rule.threshold_count if login_rule else 5

    warnings = []
    unresolved_attempts_total = 0

    for ip, events in by_ip.items():
        cutoff, is_explicit = get_login_streak_cutoff(ip, since)
        active_events = [
            ev
            for ev in events
            if _as_naive_utc(ev.created_at)
            and (
                _as_naive_utc(ev.created_at) > cutoff
                if is_explicit
                else _as_naive_utc(ev.created_at) >= cutoff
            )
        ]
        attempts = sum(max(ev.failed_login_count, 1) for ev in active_events)
        unresolved_attempts_total += attempts
        active_block = BlockedSource.query.filter_by(source_ip=ip, is_active=True).first()

        if attempts >= 2 or active_block:
            last_ev = active_events[-1] if active_events else (events[-1] if events else None)
            is_blocked = bool(active_block)
            effective_attempts = max(attempts, block_threshold if is_blocked else attempts)
            warnings.append(
                {
                    "source_ip": ip,
                    "attempts": effective_attempts,
                    "threshold": block_threshold,
                    "blocked": is_blocked,
                    "block_id": active_block.id if active_block else None,
                    "status_label": "Blocked (Auto-Protected)" if is_blocked else "System Warning",
                    "last_attempt_at": (
                        last_ev.created_at.replace(tzinfo=timezone.utc).isoformat()
                        if last_ev and last_ev.created_at
                        else (
                            active_block.blocked_at.replace(tzinfo=timezone.utc).isoformat()
                            if active_block and active_block.blocked_at
                            else None
                        )
                    ),
                    "summary": (
                        last_ev.payload_summary
                        if last_ev and last_ev.payload_summary
                        else (active_block.reason if active_block else f"{effective_attempts} wrong login attempts")
                    ),
                    "message": (
                        f"Blocked after {effective_attempts} wrong login attempts from {ip}."
                        if is_blocked
                        else f"Multiple wrong login attempts ({effective_attempts}/{block_threshold}) detected from {ip}."
                    ),
                }
            )

    warnings.sort(key=lambda w: (w["blocked"], w["attempts"]), reverse=True)
    return warnings, unresolved_attempts_total


def compute_current_health():
    """Compute unified real + simulated health status directly from live state and DB."""
    real_db = check_real_database_health()
    uptime_seconds = round(time.monotonic() - _START_MONOTONIC, 1)
    avg_latency = (
        round(sum(_RECENT_LATENCIES_MS) / len(_RECENT_LATENCIES_MS), 2)
        if _RECENT_LATENCIES_MS
        else real_db["latency_ms"]
    )
    error_rate = (
        round((_REAL_ERROR_COUNT / _REAL_REQUEST_COUNT) * 100.0, 2)
        if _REAL_REQUEST_COUNT > 0
        else 0.0
    )

    # Expire any simulated blocks whose TTL has elapsed
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expired_blocks = BlockedSource.query.filter(
        BlockedSource.is_active.is_(True),
        BlockedSource.expires_at.isnot(None),
    ).all()
    expired_any = False
    for block in expired_blocks:
        exp = block.expires_at.replace(tzinfo=None) if block.expires_at else None
        if exp and exp <= now:
            block.is_active = False
            block.unblocked_at = now
            block.unblocked_by = "TTL Auto-Expiry"
            expired_any = True
    if expired_any:
        db.session.commit()

    active_blocks_count = BlockedSource.query.filter_by(is_active=True).count()
    open_incidents = ThreatIncident.query.filter(
        ThreatIncident.status.in_(["New", "Investigating"])
    ).all()
    open_incidents_count = len(open_incidents)
    critical_open_count = sum(1 for inc in open_incidents if inc.severity == "Critical")
    high_open_count = sum(1 for inc in open_incidents if inc.severity == "High")

    login_warnings, unresolved_wrong_logins = _collect_login_warning_state(now)

    sim_api = _SIMULATED_STATE["api_status"]
    sim_db = _SIMULATED_STATE["database_status"]
    sim_svc = _SIMULATED_STATE["service_status"]

    failed_components = [
        name
        for name, val in [("API", sim_api), ("Database", sim_db), ("Service", sim_svc)]
        if val == "Failed"
    ]
    degraded_components = [
        name
        for name, val in [("API", sim_api), ("Database", sim_db), ("Service", sim_svc)]
        if val == "Degraded"
    ]

    # Determine overall status: Healthy, Warning, Critical
    if not real_db["reachable"] or failed_components or critical_open_count > 0:
        overall_status = "Critical"
    elif (
        degraded_components
        or open_incidents_count > 0
        or active_blocks_count > 0
        or high_open_count > 0
        or len(login_warnings) > 0
    ):
        overall_status = "Warning"
    else:
        overall_status = "Healthy"

    status_reasons = []
    if failed_components:
        status_reasons.append(f"Service disruption in: {', '.join(failed_components)} (auto-healing ready)")
    if degraded_components:
        status_reasons.append(f"Degraded service performance in: {', '.join(degraded_components)}")
    for lw in login_warnings:
        status_reasons.append(lw["message"])
    if not status_reasons and open_incidents_count > 0:
        status_reasons.append(f"{open_incidents_count} open security alert(s) under review")

    # Calculate availability metric transparently from simulated + real states
    availability = 100.0
    availability -= len(failed_components) * 28.5
    availability -= len(degraded_components) * 11.0
    if not real_db["reachable"]:
        availability -= 35.0
    availability = max(0.0, round(availability, 2))

    return {
        "overall_status": overall_status,
        "status_reasons": status_reasons,
        "api_status": sim_api,
        "database_status": sim_db if real_db["reachable"] else "Failed",
        "service_status": sim_svc,
        "availability_pct": availability,
        "avg_response_ms": avg_latency,
        "error_rate_pct": error_rate,
        "active_blocks_count": active_blocks_count,
        "open_incidents_count": open_incidents_count,
        "critical_open_count": critical_open_count,
        "login_warnings": login_warnings,
        "recent_wrong_logins": unresolved_wrong_logins,
        "real_metrics": {
            "flask_app_status": "Running",
            "started_at": _START_UTC.isoformat(),
            "uptime_seconds": uptime_seconds,
            "real_request_count": _REAL_REQUEST_COUNT,
            "real_error_count": _REAL_ERROR_COUNT,
            "sqlite_reachable": real_db["reachable"],
            "sqlite_ping_ms": real_db["latency_ms"],
            "scope_note": "Real metrics cover only the local Flask process and SQLite connection, not host OS or external infrastructure.",
        },
        "simulated_state": {
            "api_status": sim_api,
            "database_status": sim_db,
            "service_status": sim_svc,
            "failure_reason": _SIMULATED_STATE["failure_reason"],
            "last_changed_at": _SIMULATED_STATE["last_changed_at"],
            "scope_note": "Service/DB failure states are locally simulated in-memory flags for safe self-recovery demonstrations.",
        },
        "auto_heal": get_auto_heal_config(),
    }


def persist_health_snapshot(health_data=None):
    """Store a SystemHealth snapshot in SQLite and return the model instance."""
    data = health_data or compute_current_health()
    snapshot = SystemHealth(
        overall_status=data["overall_status"],
        api_status=data["api_status"],
        database_status=data["database_status"],
        service_status=data["service_status"],
        availability_pct=data["availability_pct"],
        avg_response_ms=data["avg_response_ms"],
        error_rate_pct=data["error_rate_pct"],
        active_blocks_count=data["active_blocks_count"],
        open_incidents_count=data["open_incidents_count"],
        real_request_count=data["real_metrics"]["real_request_count"],
        real_error_count=data["real_metrics"]["real_error_count"],
        details_json=json.dumps(
            {
                "real_metrics": data["real_metrics"],
                "simulated_state": data["simulated_state"],
            }
        ),
    )
    db.session.add(snapshot)
    db.session.commit()
    return snapshot


def get_monitoring_logs(limit=40):
    """Return recent monitoring events."""
    return list(_MONITORING_EVENTS)[:limit]
