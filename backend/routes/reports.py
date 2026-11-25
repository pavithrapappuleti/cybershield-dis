"""Reports and CSV Export API endpoints."""

from collections import Counter
import csv
from datetime import datetime, timedelta, timezone
import io
from flask import Blueprint, Response, jsonify

from models import RecoveryAction, SecurityEvent, ThreatIncident
from routes.guards import admin_required

reports_bp = Blueprint("reports", __name__, url_prefix="/api/reports")


def _build_report_payload():
    events = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).all()
    incidents = ThreatIncident.query.order_by(ThreatIncident.created_at.desc()).all()
    recoveries = RecoveryAction.query.order_by(RecoveryAction.created_at.desc()).all()

    threats_by_severity = {sev: 0 for sev in ["Low", "Medium", "High", "Critical"]}
    resolution_status = {st: 0 for st in ["New", "Investigating", "Resolved", "False Positive"]}
    for inc in incidents:
        if inc.severity in threats_by_severity:
            threats_by_severity[inc.severity] += 1
        if inc.status in resolution_status:
            resolution_status[inc.status] += 1

    event_type_counts = Counter(ev.event_type for ev in events)
    common_event_types = [
        {"event_type": et, "count": count}
        for et, count in event_type_counts.most_common(8)
    ]

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    trend = {}
    for offset in range(6, -1, -1):
        day_str = (now - timedelta(days=offset)).strftime("%Y-%m-%d")
        trend[day_str] = {"date": day_str, "total_events": 0, "threat_events": 0}

    seven_days_ago = now - timedelta(days=7)
    for ev in events:
        ev_ts = ev.created_at.replace(tzinfo=None) if ev.created_at else None
        if ev_ts and ev_ts >= seven_days_ago:
            d = ev_ts.strftime("%Y-%m-%d")
            if d in trend:
                trend[d]["total_events"] += 1
                if ev.is_threat:
                    trend[d]["threat_events"] += 1

    completed_rec = sum(1 for r in recoveries if r.status == "Completed")
    failed_rec = sum(1 for r in recoveries if r.status == "Failed")
    avg_rec_ms = round(sum(r.duration_ms for r in recoveries) / len(recoveries), 1) if recoveries else 0.0

    return {
        "generated_at": now.isoformat(),
        "totals": {
            "total_events": len(events),
            "threat_events": sum(1 for e in events if e.is_threat),
            "total_incidents": len(incidents),
            "total_recoveries": len(recoveries),
        },
        "threats_by_severity": threats_by_severity,
        "common_event_types": common_event_types,
        "incident_resolution_status": resolution_status,
        "recovery_statistics": {
            "total": len(recoveries),
            "completed": completed_rec,
            "failed": failed_rec,
            "success_rate_pct": round((completed_rec / len(recoveries)) * 100.0, 1) if recoveries else 100.0,
            "avg_duration_ms": avg_rec_ms,
        },
        "event_trends": list(trend.values()),
    }


@reports_bp.route("", methods=["GET"])
@admin_required
def get_reports():
    """Return structured analytics data computed from SQLite."""
    return jsonify(_build_report_payload())


@reports_bp.route("/export", methods=["GET"])
@admin_required
def export_reports_csv():
    """Export incidents and security telemetry as a downloadable CSV report."""
    incidents = ThreatIncident.query.order_by(ThreatIncident.created_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Incident Code",
            "Title",
            "Source IP",
            "Event Type",
            "Severity",
            "Risk Score",
            "Status",
            "Detection Reason",
            "Response Action",
            "Immune Signature",
            "Created At (UTC)",
            "Resolved At (UTC)",
        ]
    )
    for inc in incidents:
        writer.writerow(
            [
                inc.incident_code,
                inc.title,
                inc.source_ip,
                inc.event_type,
                inc.severity,
                inc.risk_score,
                inc.status,
                inc.detection_reason,
                inc.response_action,
                inc.immune_signature,
                inc.created_at.isoformat() if inc.created_at else "",
                inc.resolved_at.isoformat() if inc.resolved_at else "",
            ]
        )

    csv_data = output.getvalue()
    filename = f"cybershield_security_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
