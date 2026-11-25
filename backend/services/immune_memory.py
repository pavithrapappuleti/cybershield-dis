"""Digital Immune Memory (Historical Pattern Tracking).

Inspired by biological immune memory, this module indexes historical incidents,
tracks recurring signatures and prior containment outcomes, and adjusts rule
sensitivity weights transparently. It performs deterministic historical pattern
matching (not autonomous self-training ML).
"""

from collections import defaultdict
from datetime import datetime, timezone

from extensions import db
from models import IncidentHistory, SecurityRule, ThreatIncident


def count_pattern_occurrences(immune_signature):
    """Return number of prior ThreatIncident records matching a signature."""
    if not immune_signature:
        return 0
    return ThreatIncident.query.filter_by(immune_signature=immune_signature).count()


def update_immune_memory(incident, detection_result, response_result):
    """Record historical pattern insight and adapt rule boost if pattern recurs."""
    sig = incident.immune_signature
    prior_count = ThreatIncident.query.filter_by(immune_signature=sig).count()
    matched_rule = detection_result.get("matched_rule")

    boost_applied = 0
    if prior_count >= 2:
        boost_applied = min(15, (prior_count - 1) * 5)
        if matched_rule and matched_rule.immune_boost_applied < boost_applied:
            matched_rule.immune_boost_applied = boost_applied
            matched_rule.updated_at = datetime.now(timezone.utc)

        note = (
            f"Recurring signature '{sig}' seen {prior_count} time(s). "
            f"Historical pattern tracking elevated rule sensitivity (+{boost_applied} risk weight)."
        )
    else:
        note = (
            f"New signature '{sig}' cataloged in Digital Immune Memory for future correlation "
            f"(prior response: {response_result.get('action_taken', 'Logged')})."
        )

    db.session.add(
        IncidentHistory(
            incident_id=incident.id,
            event_stage="ImmuneMemory",
            actor="Historical Pattern Tracker",
            action=f"Pattern '{sig}' recorded (recurrence #{prior_count})",
            notes=note,
        )
    )
    db.session.commit()

    return {
        "immune_signature": sig,
        "recurrence_count": prior_count,
        "rule_boost_applied": boost_applied,
        "note": note,
    }


def get_immune_memory_summary():
    """Aggregate historical patterns, recurring signatures, and adapted rules."""
    incidents = ThreatIncident.query.order_by(ThreatIncident.created_at.desc()).all()
    grouped = defaultdict(list)
    for inc in incidents:
        grouped[inc.immune_signature].append(inc)

    patterns = []
    for sig, items in grouped.items():
        latest = items[0]
        total_occurrences = sum(item.occurrence_count for item in items)
        severities = [item.severity for item in items]
        highest_sev = (
            "Critical"
            if "Critical" in severities
            else "High"
            if "High" in severities
            else "Medium"
            if "Medium" in severities
            else "Low"
        )
        prior_actions = list(dict.fromkeys(item.response_action for item in items if item.response_action))
        patterns.append(
            {
                "immune_signature": sig,
                "event_type": latest.event_type,
                "source_ip": latest.source_ip,
                "incident_count": len(items),
                "total_occurrences": total_occurrences,
                "highest_severity": highest_sev,
                "latest_risk_score": latest.risk_score,
                "last_seen": latest.created_at.isoformat() if latest.created_at else None,
                "previous_responses": prior_actions[:3],
                "is_recurring": len(items) >= 2 or total_occurrences >= 2,
                "adaptive_boost": min(15, max(0, (len(items) - 1) * 5)),
            }
        )

    patterns.sort(key=lambda p: (p["is_recurring"], p["incident_count"], p["latest_risk_score"]), reverse=True)
    rules = SecurityRule.query.order_by(SecurityRule.id.asc()).all()

    return {
        "methodology_note": (
            "Digital Immune Memory uses deterministic historical pattern tracking inspired by "
            "adaptive immunity. It logs past incident signatures and adjusts rule risk weights "
            "when patterns recur; it is not an autonomous self-training neural network."
        ),
        "total_cataloged_signatures": len(patterns),
        "recurring_patterns_count": sum(1 for p in patterns if p["is_recurring"]),
        "patterns": patterns,
        "adapted_rules": [r.to_dict() for r in rules],
    }
