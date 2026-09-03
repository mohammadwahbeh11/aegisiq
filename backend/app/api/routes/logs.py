import csv
import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.dependencies import get_current_user, require_role
from app.ingestion.schemas import LogIngestRequest, LogIngestResponse
from app.ingestion.service import ingest_log
from app.models.alert import Alert
from app.models.log import Log, Severity
from app.models.user import User, UserRole
from app.schemas.log import LogListResponse, LogOut

router = APIRouter(prefix="/api/logs", tags=["logs"])


# v2.2 --- CSV export column contract for logs.
# See alerts.py for the design rationale (positional stability +
# UTF-8 BOM for Excel).
_LOG_CSV_COLUMNS = [
    "log_id", "timestamp_utc", "severity", "event_type", "source",
    "hostname", "source_ip", "destination_ip", "destination_port",
    "username", "operating_system", "event_id", "agent_id",
    "raw_log",
]


def _log_csv_row(row: Log) -> list:
    return [
        row.id,
        row.timestamp.isoformat() if row.timestamp else "",
        row.severity.value if hasattr(row.severity, "value") else str(row.severity),
        row.event_type or "",
        row.source or "",
        row.hostname or "",
        row.source_ip or "",
        row.destination_ip or "",
        row.destination_port or "",
        row.username or "",
        row.operating_system or "",
        row.event_id or "",
        row.agent_id or "",
        (row.raw_log or "").replace("\n", " ").replace("\r", " ").strip(),
    ]


@router.post("", response_model=LogIngestResponse, status_code=201)
def create_log(
    payload: LogIngestRequest,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
):
    """
    Authenticate (existing get_current_user dependency, reused as-is) ->
    validate (LogIngestRequest) -> ingest_log() does normalize -> store
    -> broadcast -> detection -> SOAR (see app/ingestion/service.py).
    """
    return ingest_log(payload, db)


@router.get("", response_model=LogListResponse)
def list_logs(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
    severity: Severity | None = None,
    event_type: str | None = None,
    source_ip: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    search: str | None = Query(default=None, max_length=200),
    since_hours: int | None = Query(default=None, ge=1, le=8760),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    format: str | None = Query(default=None, pattern="^(csv|json)$"),
):
    """
    Log search, newest first. `total` is the match count BEFORE
    limit/offset, so the UI can honestly say "showing 100 of 12,904"
    instead of implying the page is everything.

    `search` is a substring match over the raw log line and the parsed
    username/hostname. It is deliberately a LIKE, not a full-text index:
    at this project's scale a LIKE over an indexed-by-time working set is
    fast enough, and adding FTS5 tables would cost storage and a schema
    migration for a feature no requirement asks for.

    ``?format=csv`` returns a text/csv stream with a fixed column set
    (see ``_LOG_CSV_COLUMNS``). Honours every filter above and caps at
    ``limit`` rows so an export can never exceed what the operator saw
    in the search UI.
    """
    query = db.query(Log)

    if severity is not None:
        query = query.filter(Log.severity == severity)
    if event_type:
        query = query.filter(Log.event_type == event_type)
    if source_ip:
        query = query.filter(Log.source_ip == source_ip)
    if hostname:
        query = query.filter(Log.hostname == hostname)
    if username:
        query = query.filter(Log.username == username)
    if since_hours is not None:
        query = query.filter(Log.timestamp >= datetime.now(timezone.utc) - timedelta(hours=since_hours))
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                Log.raw_log.ilike(pattern),
                Log.username.ilike(pattern),
                Log.hostname.ilike(pattern),
                Log.event_type.ilike(pattern),
            )
        )

    if format == "csv":
        rows = query.order_by(Log.timestamp.desc(), Log.id.desc()).limit(limit).all()

        def _iter():
            buf = io.StringIO()
            buf.write("﻿")  # UTF-8 BOM for Excel-safe accented/Arabic
            writer = csv.writer(buf)
            writer.writerow(_LOG_CSV_COLUMNS)
            yield buf.getvalue(); buf.seek(0); buf.truncate(0)
            for r in rows:
                writer.writerow(_log_csv_row(r))
                yield buf.getvalue(); buf.seek(0); buf.truncate(0)

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return StreamingResponse(
            _iter(),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="aegisiq_logs_{stamp}.csv"',
                "X-AegisIQ-Export-Rows": str(len(rows)),
            },
        )

    total = query.count()
    rows = query.order_by(Log.timestamp.desc(), Log.id.desc()).offset(offset).limit(limit).all()
    return LogListResponse(total=total, items=[LogOut.model_validate(row) for row in rows])


@router.get("/event-types", response_model=list[str])
def list_event_types(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    """The event types actually present in this database, for populating
    the search filter. Derived from the data rather than a hardcoded list
    because event_type is intentionally an open string -- new log sources
    introduce new types without a schema change (see app/models/log.py)."""
    rows = db.query(Log.event_type).distinct().order_by(Log.event_type).all()
    return [row[0] for row in rows]


@router.get("/{log_id}", response_model=LogOut)
def get_log(log_id: int, db: Session = Depends(get_db), _user=Depends(get_current_user)):
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log not found")
    return LogOut.model_validate(log)


@router.delete("/{log_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_log(
    log_id: int,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role(UserRole.ADMINISTRATOR)),
):
    """Permanently remove one stored log event.

    Alerts that referenced this log lose their log_id (set to NULL) but
    are NOT themselves deleted -- alerts are the SOC's work product; the
    log is the evidence chain. Losing evidence should not silently
    disappear the alert that pointed at it. Administrator only."""
    log = db.query(Log).filter(Log.id == log_id).first()
    if log is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log not found")

    db.query(Alert).filter(Alert.log_id == log_id).update(
        {"log_id": None}, synchronize_session=False
    )
    db.delete(log)
    db.commit()
    return None


@router.post("/bulk-delete", status_code=status.HTTP_200_OK)
def bulk_delete_logs(
    payload: dict,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role(UserRole.ADMINISTRATOR)),
):
    """Delete several logs by id in one call. Payload: {"ids": [1, 2, 3]}."""
    ids = payload.get("ids")
    if not isinstance(ids, list) or not all(isinstance(i, int) for i in ids):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must be {\"ids\": [<int>, ...]}",
        )
    if not ids:
        return {"deleted": 0}

    db.query(Alert).filter(Alert.log_id.in_(ids)).update(
        {"log_id": None}, synchronize_session=False
    )
    deleted = db.query(Log).filter(Log.id.in_(ids)).delete(synchronize_session=False)
    db.commit()
    return {"deleted": deleted}
