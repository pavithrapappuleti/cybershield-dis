"""Rule-Based Threat Detection Engine.

Evaluates incoming telemetry against configurable SecurityRule thresholds.
Normal baseline traffic and isolated single anomalies are logged without
raising false-alarm incidents.
"""

from datetime import datetime, timedelta, timezone
from models import SecurityEvent, SecurityRule
from services.monitoring_service import _as_naive_utc, get_login_streak_cutoff


def _default_rules_map():
    """Fetch active rules keyed by event_type."""
    rules = SecurityRule.query.filter_by(is_active=True).all()
    return {rule.event_type: rule for rule in rules}


def evaluate_event(
    source_ip,
    event_type,
    endpoint="/api/auth/login",
    method="POST",
    status_code=200,
    request_count=1,
    failed_login_count=0,
):
    """Analyze telemetry parameters and return structured detection findings.

    Returns a dictionary containing:
      - is_threat (bool)
      - event_type (str)
      - matched_rule (SecurityRule | None)
      - observed_count (int)
      - threshold (int)
      - detection_reason (str)
      - immune_signature (str)
      - false_alarm_prevented (bool)
    """
    rules_by_type = _default_rules_map()
    now = datetime.now(timezone.utc)

    # Normal baseline traffic never escalates unless frequency rule is exceeded
    if event_type == "normal_traffic":
        freq_rule = rules_by_type.get("suspicious_frequency")
        threshold = freq_rule.threshold_count if freq_rule else 40
        if request_count < threshold:
            return {
                "is_threat": False,
                "event_type": "normal_traffic",
                "matched_rule": None,
                "observed_count": request_count,
                "threshold": threshold,
                "detection_reason": (
                    f"Normal baseline traffic ({request_count} requests) from {source_ip} "
                    f"is well below suspicious frequency threshold ({threshold}). No alarm raised."
                ),
                "immune_signature": f"normal_traffic::{source_ip}",
                "false_alarm_prevented": False,
            }

    rule = rules_by_type.get(event_type)

    # Compute recent rolling window counts in SQLite for cumulative threshold checks
    window_seconds = rule.window_seconds if rule else 300
    since = now - timedelta(seconds=window_seconds)
    recent_events = SecurityEvent.query.filter(
        SecurityEvent.source_ip == source_ip,
        SecurityEvent.event_type == event_type,
        SecurityEvent.created_at >= since,
    ).all()

    if event_type == "failed_login_burst":
        since_naive = since.replace(tzinfo=None)
        cutoff, is_explicit_clear = get_login_streak_cutoff(source_ip, since_naive)
        active_events = [
            ev
            for ev in recent_events
            if _as_naive_utc(ev.created_at)
            and (
                _as_naive_utc(ev.created_at) > cutoff
                if is_explicit_clear
                else _as_naive_utc(ev.created_at) >= cutoff
            )
        ]
        historical_failed = sum(ev.failed_login_count for ev in active_events)
        observed_count = historical_failed + max(failed_login_count, 1)
        threshold = rule.threshold_count if rule else 5
        immune_sig = f"failed_login_burst::{source_ip}"

        if observed_count < threshold:
            return {
                "is_threat": False,
                "event_type": event_type,
                "matched_rule": rule,
                "observed_count": observed_count,
                "threshold": threshold,
                "detection_reason": (
                    f"Single or low-volume failed login ({observed_count}/{threshold} in {window_seconds}s) "
                    f"from {source_ip}. Logged for observation without raising a false alarm."
                ),
                "immune_signature": immune_sig,
                "false_alarm_prevented": True,
            }

        return {
            "is_threat": True,
            "event_type": event_type,
            "matched_rule": rule,
            "observed_count": observed_count,
            "threshold": threshold,
            "detection_reason": (
                f"Detected {observed_count} failed login attempts from {source_ip} within "
                f"{window_seconds}s, exceeding configured threshold of {threshold} (brute-force indicator)."
            ),
            "immune_signature": immune_sig,
            "false_alarm_prevented": False,
        }

    if event_type in ("suspicious_frequency", "repeated_ip_requests"):
        historical_reqs = sum(ev.request_count for ev in recent_events)
        observed_count = historical_reqs + max(request_count, 1)
        threshold = rule.threshold_count if rule else 40
        immune_sig = f"{event_type}::{source_ip}"

        if observed_count < threshold:
            return {
                "is_threat": False,
                "event_type": event_type,
                "matched_rule": rule,
                "observed_count": observed_count,
                "threshold": threshold,
                "detection_reason": (
                    f"Request volume ({observed_count}/{threshold} in {window_seconds}s) from {source_ip} "
                    f"remains within safe operating bounds."
                ),
                "immune_signature": immune_sig,
                "false_alarm_prevented": True,
            }

        return {
            "is_threat": True,
            "event_type": event_type,
            "matched_rule": rule,
            "observed_count": observed_count,
            "threshold": threshold,
            "detection_reason": (
                f"Abnormal request burst from {source_ip}: {observed_count} requests in {window_seconds}s "
                f"targeting {endpoint} (threshold: {threshold})."
            ),
            "immune_signature": immune_sig,
            "false_alarm_prevented": False,
        }

    if event_type == "restricted_endpoint_access":
        observed_count = len(recent_events) + max(request_count, 1)
        threshold = rule.threshold_count if rule else 2
        immune_sig = f"restricted_endpoint_access::{endpoint}"

        if observed_count < threshold:
            return {
                "is_threat": False,
                "event_type": event_type,
                "matched_rule": rule,
                "observed_count": observed_count,
                "threshold": threshold,
                "detection_reason": (
                    f"Single probe ({observed_count}/{threshold}) to restricted test endpoint {endpoint} "
                    f"from {source_ip}. Flagged for correlation before escalating."
                ),
                "immune_signature": immune_sig,
                "false_alarm_prevented": True,
            }

        return {
            "is_threat": True,
            "event_type": event_type,
            "matched_rule": rule,
            "observed_count": observed_count,
            "threshold": threshold,
            "detection_reason": (
                f"Repeated unauthorized access attempts ({observed_count} probes) to restricted test "
                f"endpoint {endpoint} from {source_ip} (threshold: {threshold})."
            ),
            "immune_signature": immune_sig,
            "false_alarm_prevented": False,
        }

    if event_type in ("unusual_activity_pattern", "service_failure", "database_failure", "excessive_errors"):
        observed_count = len(recent_events) + max(request_count, 1)
        threshold = rule.threshold_count if rule else 1
        immune_sig = f"{event_type}::{endpoint}"
        return {
            "is_threat": True,
            "event_type": event_type,
            "matched_rule": rule,
            "observed_count": observed_count,
            "threshold": threshold,
            "detection_reason": (
                f"Anomalous event '{event_type}' detected on {endpoint} from {source_ip} "
                f"(status {status_code}, observed count: {observed_count})."
            ),
            "immune_signature": immune_sig,
            "false_alarm_prevented": False,
        }

    # Generic fallback for custom event types
    observed_count = len(recent_events) + 1
    threshold = rule.threshold_count if rule else 3
    is_threat = observed_count >= threshold
    return {
        "is_threat": is_threat,
        "event_type": event_type,
        "matched_rule": rule,
        "observed_count": observed_count,
        "threshold": threshold,
        "detection_reason": (
            f"Event '{event_type}' observed {observed_count} times from {source_ip} "
            f"(threshold: {threshold})."
        ),
        "immune_signature": f"{event_type}::{source_ip}",
        "false_alarm_prevented": not is_threat,
    }
