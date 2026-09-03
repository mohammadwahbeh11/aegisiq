"""
app/api/routes/audit.py -- read the audit trail (v2.0).

Every mutating action goes into app.security.audit.AuditEntry via
audit.record(). This route surfaces those rows for the console's
Audit page. Rows are never modified or deleted from the application;
that's the point of an audit trail.

RBAC:
  * Analyst can see THEIR OWN audit rows (username = current user).
  * Administrator can see EVERYONE'S rows.

Filters: username (admin only), action, outcome, since_hours.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.dependencies import get_current_user
from app.config import get_settings
from app.models.user import User, UserRole
from app.security.audit import AuditEntry

router = APIRouter(prefix="/api/audit", tags=["audit"])
settings = get_settings()


@router.get("")
def list_audit_entries(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    username: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    since_hours: int | None = Query(default=None, ge=1, le=8760),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    if not settings.AUDIT_API_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Audit API disabled for this deployment (AUDIT_API_ENABLED=false).",
        )

    query = db.query(AuditEntry)

    # Analysts can only see their own rows. If they pass ?username=...
    # (even their own) we ignore it and force it to the current user.
    if user.role != UserRole.ADMINISTRATOR:
        query = query.filter(AuditEntry.username == user.username)
    elif username:
        query = query.filter(AuditEntry.username == username)

    if action:
        query = query.filter(AuditEntry.action == action)
    if outcome:
        query = query.filter(AuditEntry.outcome == outcome)
    if since_hours is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        query = query.filter(AuditEntry.timestamp >= cutoff)

    total = query.count()
    rows = (query.order_by(AuditEntry.timestamp.desc(), AuditEntry.id.desc())
                 .offset(offset).limit(limit).all())

    return {
        "total": total,
        "items": [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "username": r.username,
                "action": r.action,
                "target": r.target,
                "outcome": r.outcome,
                "source_ip": r.source_ip,
                "details": r.details,
            }
            for r in rows
        ],
    }
