"""
Automated-response history (the SOAR half of "SIEM & SOAR").

Read-only by design. Actions are created by app/soar/engine.py in
reaction to alerts; there is no endpoint to invent one by hand, because
an action with no alert behind it would break the audit chain the table
exists to provide.

The response includes `execution_mode` so the console can state plainly
whether these actions were carried out or only recorded -- see
app/soar/engine.py's module docstring for why this build records only.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.dependencies import get_current_user
from app.config import get_settings
from app.models.soar import SoarAction, SoarActionStatus, SoarActionType
from app.soar.engine import serialize_action

router = APIRouter(prefix="/api/soar", tags=["soar"])

settings = get_settings()


@router.get("/actions")
def list_soar_actions(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
    action_type: SoarActionType | None = None,
    action_status: SoarActionStatus | None = Query(default=None, alias="status"),
    target: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    query = db.query(SoarAction)
    if action_type is not None:
        query = query.filter(SoarAction.action_type == action_type)
    if action_status is not None:
        query = query.filter(SoarAction.status == action_status)
    if target:
        query = query.filter(SoarAction.target == target)

    total = query.count()
    actions = (
        query.order_by(SoarAction.timestamp.desc(), SoarAction.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "enabled": settings.SOAR_ENABLED,
        # "record_only" is the truthful description of what this build
        # does; "execute_requested" means a deployment opted in via
        # SOAR_EXECUTE and actions are queued as PENDING for an executor
        # that is not part of this project.
        "execution_mode": "execute_requested" if settings.SOAR_EXECUTE else "record_only",
        "items": [serialize_action(action) for action in actions],
    }
