"""
app/api/routes/retention.py -- data lifecycle management.

The Rules page controls what the SIEM alerts on; this file controls how
long it keeps evidence around. Two operations:

    POST /api/retention/purge   -- bulk cleanup by age / status / severity
    GET  /api/retention/config  -- current defaults (from .env / config)

Individual DELETE endpoints for a single alert or log live next to the
resource they touch:

    DELETE /api/alerts/{id}   -- see app/api/routes/alerts.py
    DELETE /api/logs/{id}     -- see app/api/routes/logs.py

Every mutating call is administrator-only, matching the RBAC split in
the project's use-case diagram: analysts triage, administrators shape
retention. Deletions are logged to the application log so an auditor
can see what was removed and by whom.

Cascade rule, stated explicitly to avoid surprise:
- Deleting an ALERT removes its status_history rows (audit trail for
  that alert) and its SOAR action rows (the recorded response for that
  alert). This is intentional -- an alert removed for retention should
  not leave orphan audit rows referring to a row that no longer exists.
- Deleting a LOG does NOT cascade to its alerts. Alerts are the SOC's
  work product; the raw log is the evidence chain, and losing evidence
  should not silently disappear the alert that referenced it. The
  alert.log_id becomes NULL and the alert stays.
- Alerts protected by "keep alerts above severity X" (default HIGH) are
  never removed, even by an "everything older than N days" purge --
  this is the safety guard against a bad purge deleting a CRITICAL
  intrusion because it was old.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.dependencies import require_role
from app.security.rate_limit import enforce_mutate
from app.config import get_settings
from app.models.alert import Alert, AlertStatus, AlertStatusHistory
from app.models.log import Log, Severity
from app.models.soar import SoarAction
from app.models.user import User, UserRole

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/api/retention", tags=["retention"])


# Ordering of severities so a "min_severity" comparison is meaningful --
# don't rely on the Python enum's declaration order (which happens to
# match today, but any refactor could break silently).
_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


class PurgeRequest(BaseModel):
    """What to purge. Every field is optional; the fields you leave unset
    are simply not applied. A request with no criteria set is rejected
    (see the endpoint) rather than silently interpreted as "delete
    everything"."""

    # Delete alerts strictly older than this many days.
    alerts_older_than_days: int | None = Field(None, ge=1, le=3650)
    # Delete logs strictly older than this many days.
    logs_older_than_days: int | None = Field(None, ge=1, le=3650)
    # If true, only alerts already triaged (resolved / false_positive)
    # are eligible for deletion. Defaults to True as a safety guard --
    # an "old alert" that is still NEW or INVESTIGATING is an alert an
    # analyst hasn't finished with, and retention should not throw
    # unfinished work away.
    only_triaged_alerts: bool = True
    # Alerts of this severity or higher are preserved regardless of
    # age. Defaults to HIGH so CRITICAL and HIGH alerts are never
    # deleted by retention -- if you actually want to drop them you have
    # to say so explicitly (min_severity_to_keep = "critical" means
    # HIGH is deletable, or set it to null to remove the guard).
    min_severity_to_keep: Severity | None = Severity.HIGH


class PurgeResponse(BaseModel):
    deleted_alerts: int
    deleted_logs: int
    deleted_soar_actions: int
    deleted_alert_status_history: int
    cutoff_alerts: datetime | None = None
    cutoff_logs: datetime | None = None
    detail: str


class RetentionConfig(BaseModel):
    """The application-level defaults for retention windows, read from
    .env. These are advisory -- purge runs on-demand rather than on a
    schedule, and the request body's own numbers win."""

    log_retention_days: int
    alert_retention_days: int
    max_db_size_mb: int


@router.get("/config", response_model=RetentionConfig)
def get_retention_config(_user: User = Depends(require_role(UserRole.ADMINISTRATOR))):
    return RetentionConfig(
        log_retention_days=settings.LOG_RETENTION_DAYS,
        alert_retention_days=settings.ALERT_RETENTION_DAYS,
        max_db_size_mb=settings.MAX_DB_SIZE_MB,
    )


@router.post("/purge", response_model=PurgeResponse, dependencies=[Depends(enforce_mutate)])
def purge(
    payload: PurgeRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(UserRole.ADMINISTRATOR)),
) -> PurgeResponse:
    """Bulk cleanup. Reads the criteria from the request, computes what
    would be removed, deletes it, and returns the exact counts so the
    console can tell the analyst what happened."""

    if payload.alerts_older_than_days is None and payload.logs_older_than_days is None:
        # A completely empty request is almost certainly a mistake --
        # reject it rather than silently interpreting it as "purge
        # everything I haven't specifically excluded".
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Provide at least one of alerts_older_than_days or logs_older_than_days. "
                "An empty request is rejected on purpose."
            ),
        )

    now = datetime.now(timezone.utc)
    cutoff_alerts = (
        now - timedelta(days=payload.alerts_older_than_days)
        if payload.alerts_older_than_days is not None
        else None
    )
    cutoff_logs = (
        now - timedelta(days=payload.logs_older_than_days)
        if payload.logs_older_than_days is not None
        else None
    )

    deleted_alerts = 0
    deleted_soar = 0
    deleted_history = 0
    deleted_logs = 0

    # ---- alerts ----------------------------------------------------------
    if cutoff_alerts is not None:
        alert_query = db.query(Alert).filter(Alert.timestamp < cutoff_alerts)

        if payload.only_triaged_alerts:
            # Untriaged alerts are unfinished analyst work. Never delete.
            alert_query = alert_query.filter(
                Alert.status.in_([AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE])
            )

        if payload.min_severity_to_keep is not None:
            # Keep anything AT OR ABOVE min_severity_to_keep, i.e. only
            # allow deletion of severities strictly below it.
            keep_rank = _SEVERITY_RANK[payload.min_severity_to_keep]
            allowed_severities = [sev for sev, rank in _SEVERITY_RANK.items() if rank < keep_rank]
            if not allowed_severities:
                # min_severity_to_keep = LOW means nothing is deletable
                # by severity; leave the alert_query empty.
                allowed_severities = []
            alert_query = alert_query.filter(Alert.severity.in_(allowed_severities))

        # Collect the ids first so we can also clean up their audit-trail
        # and SOAR rows in a way that works on SQLite without ON DELETE
        # CASCADE support (SQLAlchemy doesn't add DB-level cascades to
        # SQLite without explicit FK constraint declaration).
        alert_ids = [row.id for row in alert_query.with_entities(Alert.id).all()]
        if alert_ids:
            deleted_history = (
                db.query(AlertStatusHistory)
                .filter(AlertStatusHistory.alert_id.in_(alert_ids))
                .delete(synchronize_session=False)
            )
            deleted_soar = (
                db.query(SoarAction)
                .filter(SoarAction.alert_id.in_(alert_ids))
                .delete(synchronize_session=False)
            )
            deleted_alerts = (
                db.query(Alert)
                .filter(Alert.id.in_(alert_ids))
                .delete(synchronize_session=False)
            )

    # ---- logs ------------------------------------------------------------
    if cutoff_logs is not None:
        # Any alerts still pointing at a log we are about to delete lose
        # only their log_id -- the alert itself stays. This is deliberate;
        # see the module docstring.
        log_ids_subq = (
            db.query(Log.id).filter(Log.timestamp < cutoff_logs).subquery()
        )
        db.query(Alert).filter(Alert.log_id.in_(log_ids_subq)).update(
            {"log_id": None}, synchronize_session=False
        )
        deleted_logs = (
            db.query(Log)
            .filter(Log.timestamp < cutoff_logs)
            .delete(synchronize_session=False)
        )

    db.commit()

    logger.info(
        "Retention purge by %s: deleted %s alerts (+ %s history, %s SOAR) and %s logs",
        user.username,
        deleted_alerts,
        deleted_history,
        deleted_soar,
        deleted_logs,
    )

    detail_parts: list[str] = []
    if cutoff_alerts:
        detail_parts.append(
            f"deleted {deleted_alerts} alert(s) older than "
            f"{payload.alerts_older_than_days} day(s)"
        )
    if cutoff_logs:
        detail_parts.append(
            f"deleted {deleted_logs} log(s) older than {payload.logs_older_than_days} day(s)"
        )
    detail = "; ".join(detail_parts) if detail_parts else "no criteria matched — nothing removed"

    return PurgeResponse(
        deleted_alerts=deleted_alerts,
        deleted_logs=deleted_logs,
        deleted_soar_actions=deleted_soar,
        deleted_alert_status_history=deleted_history,
        cutoff_alerts=cutoff_alerts,
        cutoff_logs=cutoff_logs,
        detail=detail,
    )


@router.post("/dry-run", response_model=dict[str, Any])
def dry_run(
    payload: PurgeRequest,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role(UserRole.ADMINISTRATOR)),
) -> dict[str, Any]:
    """Compute what /api/retention/purge would remove WITHOUT deleting.
    A "type this to confirm" step for a destructive operation."""

    if payload.alerts_older_than_days is None and payload.logs_older_than_days is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide at least one of alerts_older_than_days or logs_older_than_days.",
        )

    now = datetime.now(timezone.utc)
    result: dict[str, Any] = {"would_delete_alerts": 0, "would_delete_logs": 0}

    if payload.alerts_older_than_days is not None:
        cutoff = now - timedelta(days=payload.alerts_older_than_days)
        q = db.query(Alert).filter(Alert.timestamp < cutoff)
        if payload.only_triaged_alerts:
            q = q.filter(Alert.status.in_([AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]))
        if payload.min_severity_to_keep is not None:
            keep_rank = _SEVERITY_RANK[payload.min_severity_to_keep]
            allowed = [sev for sev, rank in _SEVERITY_RANK.items() if rank < keep_rank]
            q = q.filter(Alert.severity.in_(allowed))
        result["would_delete_alerts"] = q.count()
        result["cutoff_alerts"] = cutoff.isoformat()

    if payload.logs_older_than_days is not None:
        cutoff = now - timedelta(days=payload.logs_older_than_days)
        result["would_delete_logs"] = (
            db.query(Log).filter(Log.timestamp < cutoff).count()
        )
        result["cutoff_logs"] = cutoff.isoformat()

    return result
