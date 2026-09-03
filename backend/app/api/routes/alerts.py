"""
Alert querying and triage (project section 11 -- the investigation page).

Reading is open to both roles; changing an alert's status is the
analyst's core action and is therefore also open to both -- triage is
literally the Security Analyst's job in the project's use-case diagram,
so restricting it to administrators would be backwards.
"""
import csv
import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session, joinedload

from app.api.deps import get_db
from app.auth.dependencies import get_current_user, require_role
from app.models.alert import Alert, AlertStatus, AlertStatusHistory
from app.models.log import Log, Severity
from app.models.rule import DetectionRule
from app.models.soar import SoarAction
from app.models.user import User, UserRole
from app.realtime.events import serialize_alert
from app.realtime.hub import EVENT_ALERT, hub
from app.schemas.alert import (
    AlertDetail,
    AlertListResponse,
    AlertLogContext,
    AlertOut,
    AlertStatusChange,
    AlertStatusUpdate,
)

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

# How much surrounding evidence the investigation view pulls in. Capped
# because an alert on a busy source IP could otherwise match thousands of
# log rows and turn one page load into a table scan.
RELATED_LOG_LIMIT = 25


def _to_out(alert: Alert) -> AlertOut:
    payload = AlertOut.model_validate(alert)
    if alert.rule is not None:
        payload.rule_name = alert.rule.name
        payload.rule_type = alert.rule.rule_type
    return payload


# v2.2 --- CSV export column contract.
#
# The columns are deliberately named to be unambiguous when opened in
# Excel or piped to another SOC's ticketing system: no ambiguous "date"
# vs "created_at", no raw enum values without the human label. Order is
# fixed so that a downstream cron pipeline can rely on positional
# parsing.
_ALERT_CSV_COLUMNS = [
    "alert_id", "timestamp_utc", "severity", "status", "rule_id",
    "rule_name", "rule_type", "mitre_id", "kill_chain_phase",
    "source_ip", "destination_ip", "dedup_key", "description",
    "triggering_log_id", "incident_id", "created_at_utc",
]


def _alert_csv_row(alert: Alert) -> list:
    rule = alert.rule
    return [
        alert.id,
        alert.timestamp.isoformat() if alert.timestamp else "",
        alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
        alert.status.value if hasattr(alert.status, "value") else str(alert.status),
        alert.rule_id or "",
        rule.name if rule else "",
        rule.rule_type if rule else "",
        alert.mitre_id or "",
        alert.kill_chain_phase or "",
        alert.source_ip or "",
        alert.destination_ip or "",
        alert.dedup_key or "",
        (alert.description or "").replace("\n", " ").strip(),
        alert.log_id or "",
        alert.incident_id or "",
        alert.created_at.isoformat() if alert.created_at else "",
    ]


@router.get("", response_model=AlertListResponse)
def list_alerts(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
    severity: Severity | None = None,
    alert_status: AlertStatus | None = Query(default=None, alias="status"),
    source_ip: str | None = None,
    rule_id: int | None = None,
    since_hours: int | None = Query(default=None, ge=1, le=8760),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    format: str | None = Query(default=None, pattern="^(csv|json)$"),
):
    """Newest first. `total` is the count BEFORE limit/offset so the UI
    can show "showing 100 of 1,432" rather than implying it has
    everything.

    ``?format=csv`` returns a text/csv stream with a fixed column set
    (see ``_ALERT_CSV_COLUMNS``). CSV export honours the same filters
    as the JSON view and enforces the same ``limit`` cap so an exported
    ticket batch never quietly exceeds what the operator saw on
    screen.
    """
    query = db.query(Alert).options(joinedload(Alert.rule))

    if severity is not None:
        query = query.filter(Alert.severity == severity)
    if alert_status is not None:
        query = query.filter(Alert.status == alert_status)
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)
    if rule_id is not None:
        query = query.filter(Alert.rule_id == rule_id)
    if since_hours is not None:
        query = query.filter(
            Alert.timestamp >= datetime.now(timezone.utc) - timedelta(hours=since_hours)
        )

    if format == "csv":
        # A generator streams the rows so a 1000-row export never
        # buffers the whole result set into memory. Excel-safe UTF-8
        # BOM prefix so accented usernames and Arabic hostnames open
        # correctly without a manual "text import" dance.
        rows = query.order_by(Alert.timestamp.desc(), Alert.id.desc()).limit(limit).all()

        def _iter():
            buf = io.StringIO()
            buf.write("﻿")  # BOM
            writer = csv.writer(buf)
            writer.writerow(_ALERT_CSV_COLUMNS)
            yield buf.getvalue(); buf.seek(0); buf.truncate(0)
            for a in rows:
                writer.writerow(_alert_csv_row(a))
                yield buf.getvalue(); buf.seek(0); buf.truncate(0)

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return StreamingResponse(
            _iter(),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="aegisiq_alerts_{stamp}.csv"',
                "X-AegisIQ-Export-Rows": str(len(rows)),
            },
        )

    total = query.count()
    alerts = query.order_by(Alert.timestamp.desc(), Alert.id.desc()).offset(offset).limit(limit).all()
    return AlertListResponse(total=total, items=[_to_out(a) for a in alerts])


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    alert = (
        db.query(Alert)
        .options(joinedload(Alert.rule), joinedload(Alert.log))
        .filter(Alert.id == alert_id)
        .first()
    )
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    detail = AlertDetail(**_to_out(alert).model_dump())

    rule: DetectionRule | None = alert.rule
    if rule is not None:
        detail.rule_description = rule.description
        detail.rule_threshold = rule.threshold
        detail.rule_time_window_seconds = rule.time_window_seconds

    if alert.log is not None:
        detail.triggering_log = AlertLogContext.model_validate(alert.log)

        # The evidence behind the verdict: the other events from the same
        # source, of the same type, inside the rule's own detection
        # window. This is what lets an analyst confirm or dismiss the
        # alert without writing a database query by hand.
        if rule is not None and alert.log.source_ip:
            window_start = alert.log.timestamp - timedelta(seconds=rule.time_window_seconds)
            related = (
                db.query(Log)
                .filter(
                    Log.source_ip == alert.log.source_ip,
                    Log.event_type == alert.log.event_type,
                    Log.timestamp >= window_start,
                    Log.timestamp <= alert.log.timestamp,
                )
                .order_by(Log.timestamp.desc())
                .limit(RELATED_LOG_LIMIT)
                .all()
            )
            detail.related_logs = [AlertLogContext.model_validate(row) for row in related]

    history = (
        db.query(AlertStatusHistory)
        .filter(AlertStatusHistory.alert_id == alert.id)
        .order_by(AlertStatusHistory.changed_at.asc())
        .all()
    )
    detail.status_history = [
        AlertStatusChange(
            previous_status=entry.previous_status,
            new_status=entry.new_status,
            changed_by=entry.changed_by_user.username if entry.changed_by_user else None,
            changed_at=entry.changed_at,
        )
        for entry in history
    ]
    return detail


@router.patch("/{alert_id}/status", response_model=AlertOut)
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Triage. The change is recorded in alert_status_history (who, when,
    from what, to what) rather than only overwriting the column, so a
    "false positive" verdict can be traced back to the analyst who made
    it -- see app/models/alert.py."""
    alert = db.query(Alert).options(joinedload(Alert.rule)).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    previous = alert.status
    if previous == payload.status:
        # Not an error, but not an audit-trail entry either -- recording
        # "changed from resolved to resolved" would be noise.
        return _to_out(alert)

    alert.status = payload.status
    db.add(
        AlertStatusHistory(
            alert_id=alert.id,
            previous_status=previous,
            new_status=payload.status,
            changed_by=user.id,
        )
    )
    db.commit()
    db.refresh(alert)

    # Other analysts' open consoles see the triage immediately, which is
    # what stops two people working the same alert.
    hub.publish(EVENT_ALERT, serialize_alert(alert))
    return _to_out(alert)


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role(UserRole.ADMINISTRATOR)),
):
    """Permanently remove one alert.

    Cascade rules (SQLite has no FK cascade at the database level, so
    we do them here explicitly):
      * the alert's own status_history is removed (audit trail for a
        row that no longer exists is meaningless);
      * SoarAction rows tied to this alert are removed for the same
        reason -- an orphan containment action pointing at a missing
        alert would be confusing in the response history.

    Restricted to administrators. The action is logged so an auditor
    can trace who removed what."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    db.query(AlertStatusHistory).filter(AlertStatusHistory.alert_id == alert_id).delete(
        synchronize_session=False
    )
    db.query(SoarAction).filter(SoarAction.alert_id == alert_id).delete(
        synchronize_session=False
    )
    db.delete(alert)
    db.commit()
    return None


@router.post("/bulk-delete", status_code=status.HTTP_200_OK)
def bulk_delete_alerts(
    payload: dict,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role(UserRole.ADMINISTRATOR)),
):
    """Delete several alerts by id in one call. Useful from the console's
    checkbox-select flow. Payload: {"ids": [1, 2, 3]}.

    Returns the exact number removed -- an id that no longer exists is
    quietly skipped rather than failing the whole batch, so a stale UI
    can retry safely."""
    ids = payload.get("ids")
    if not isinstance(ids, list) or not all(isinstance(i, int) for i in ids):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must be {\"ids\": [<int>, ...]}",
        )
    if not ids:
        return {"deleted": 0}

    db.query(AlertStatusHistory).filter(AlertStatusHistory.alert_id.in_(ids)).delete(
        synchronize_session=False
    )
    db.query(SoarAction).filter(SoarAction.alert_id.in_(ids)).delete(synchronize_session=False)
    deleted = db.query(Alert).filter(Alert.id.in_(ids)).delete(synchronize_session=False)
    db.commit()
    return {"deleted": deleted}
