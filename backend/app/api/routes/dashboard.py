from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.dependencies import get_current_user
from app.models.agent import Agent, AgentStatus
from app.models.alert import Alert, AlertStatus
from app.models.log import Log, Severity
from app.models.rule import DetectionRule
from app.models.soar import SoarAction
from app.schemas.dashboard import DashboardStats

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    total_events = db.query(func.count(Log.id)).scalar() or 0
    events_today = db.query(func.count(Log.id)).filter(Log.timestamp >= today_start).scalar() or 0

    active_alert_statuses = [AlertStatus.NEW, AlertStatus.INVESTIGATING]
    active_alerts = (
        db.query(func.count(Alert.id)).filter(Alert.status.in_(active_alert_statuses)).scalar() or 0
    )
    critical_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.severity == Severity.CRITICAL, Alert.status.in_(active_alert_statuses))
        .scalar()
        or 0
    )
    high_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.severity == Severity.HIGH, Alert.status.in_(active_alert_statuses))
        .scalar()
        or 0
    )

    monitored_endpoints = db.query(func.count(Agent.id)).scalar() or 0
    online_endpoints = (
        db.query(func.count(Agent.id)).filter(Agent.status == AgentStatus.ONLINE).scalar() or 0
    )

    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    false_positives = (
        db.query(func.count(Alert.id)).filter(Alert.status == AlertStatus.FALSE_POSITIVE).scalar() or 0
    )
    # Detection rate: share of raised alerts that were NOT dismissed as
    # false positives. Undefined (None) until at least one alert exists --
    # returning 0 would misleadingly look like "the engine caught nothing".
    detection_rate = round((total_alerts - false_positives) / total_alerts * 100, 1) if total_alerts else None

    # Average detection time = seconds between the triggering log event and
    # the alert being created. Requires alerts linked to a log_id, which
    # only exist once the detection engine (next phase) is running.
    rows = (
        db.query(Log.timestamp, Alert.created_at)
        .join(Alert, Alert.log_id == Log.id)
        .all()
    )
    if rows:
        deltas = [(alert_created - log_ts).total_seconds() for log_ts, alert_created in rows]
        avg_detection_time_seconds = round(sum(deltas) / len(deltas), 2)
    else:
        avg_detection_time_seconds = None

    soar_actions = db.query(func.count(SoarAction.id)).scalar() or 0
    soar_actions_today = (
        db.query(func.count(SoarAction.id)).filter(SoarAction.timestamp >= today_start).scalar() or 0
    )

    return DashboardStats(
        total_events=total_events,
        events_today=events_today,
        active_alerts=active_alerts,
        critical_alerts=critical_alerts,
        high_alerts=high_alerts,
        monitored_endpoints=monitored_endpoints,
        online_endpoints=online_endpoints,
        detection_rate=detection_rate,
        avg_detection_time_seconds=avg_detection_time_seconds,
        soar_actions=soar_actions,
        soar_actions_today=soar_actions_today,
    )


@router.get("/severity-distribution")
def get_severity_distribution(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    """Counts of ACTIVE alerts per severity, for the console's severity
    chart. Every severity is present in the response even when its count
    is zero -- a chart whose categories appear and disappear between
    refreshes is unreadable, and "zero critical alerts" is meaningful
    information that an absent key would hide."""
    active = [AlertStatus.NEW, AlertStatus.INVESTIGATING]
    rows = (
        db.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.status.in_(active))
        .group_by(Alert.severity)
        .all()
    )
    counts = {severity.value: 0 for severity in Severity}
    for severity, count in rows:
        counts[severity.value] = count
    return {"counts": counts, "total": sum(counts.values())}


@router.get("/timeline")
def get_timeline(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
    hours: int = Query(default=24, ge=1, le=168),
):
    """Events and alerts bucketed per hour over the requested window.

    Bucketing is done in Python rather than with a SQL date-truncation
    function on purpose: strftime() is SQLite-specific and date_trunc()
    is PostgreSQL-specific, and this project keeps its models and queries
    portable across both (see app/database.py). The window is bounded to
    one week, so the row count stays small enough that pulling timestamps
    and counting them here is cheap.

    Empty hours are emitted explicitly so the chart shows a real gap in
    activity instead of silently compressing the x-axis.
    """
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(hours=hours - 1)).replace(minute=0, second=0, microsecond=0)

    def _bucket(rows) -> dict[datetime, int]:
        counts: dict[datetime, int] = {}
        for (timestamp,) in rows:
            if timestamp is None:
                continue
            hour = timestamp.replace(minute=0, second=0, microsecond=0, tzinfo=None)
            counts[hour] = counts.get(hour, 0) + 1
        return counts

    log_counts = _bucket(db.query(Log.timestamp).filter(Log.timestamp >= window_start).all())
    alert_counts = _bucket(db.query(Alert.timestamp).filter(Alert.timestamp >= window_start).all())

    buckets = []
    for offset in range(hours):
        hour = (window_start + timedelta(hours=offset)).replace(tzinfo=None)
        buckets.append(
            {
                "hour": hour.isoformat(),
                "events": log_counts.get(hour, 0),
                "alerts": alert_counts.get(hour, 0),
            }
        )
    return {"hours": hours, "buckets": buckets}


@router.get("/top-sources")
def get_top_sources(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
    limit: int = Query(default=5, ge=1, le=50),
):
    """The source addresses generating the most alerts -- the "who is
    attacking us" panel. Alerts with no source IP (file-integrity and
    privilege-escalation events often have none) are excluded rather
    than grouped under a meaningless empty label."""
    rows = (
        db.query(Alert.source_ip, func.count(Alert.id).label("count"))
        .filter(Alert.source_ip.isnot(None))
        .group_by(Alert.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(limit)
        .all()
    )
    return [{"source_ip": source_ip, "alerts": count} for source_ip, count in rows]


@router.get("/mitre-coverage")
def get_mitre_coverage(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    """MITRE ATT&CK / Cyber Kill Chain mapping per rule, with how many
    alerts each rule has actually produced (objective O6). Rules with
    zero alerts are included -- "this technique is covered but has never
    fired" is exactly what a coverage view is for."""
    alert_counts = dict(
        db.query(Alert.rule_id, func.count(Alert.id)).group_by(Alert.rule_id).all()
    )
    rules = db.query(DetectionRule).order_by(DetectionRule.id).all()
    return [
        {
            "rule_id": rule.id,
            "rule_name": rule.name,
            "rule_type": rule.rule_type,
            "mitre_id": rule.mitre_id,
            "kill_chain_phase": rule.kill_chain_phase,
            "severity": rule.severity.value,
            "enabled": rule.enabled,
            "alerts": alert_counts.get(rule.id, 0),
        }
        for rule in rules
    ]
