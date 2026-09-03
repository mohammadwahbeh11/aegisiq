"""
Detection rule management (project section 3.6 / Table 1).

Rules are data, not code: the engine reads threshold, time window,
severity, enabled and parameters from these rows at evaluation time
(see app/detection/rules/*), so a PATCH here changes real detection
behavior on the very next ingested event -- no restart, no redeploy.

Editing is restricted to administrators, matching the RBAC split in the
project's use-case diagram: an analyst triages alerts, an administrator
decides what the system alerts on.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.dependencies import get_current_user, require_role
from app.detection.engine import implemented_rule_types
from app.models.rule import DetectionRule
from app.models.user import UserRole
from app.schemas.rule import RuleOut, RuleUpdate

router = APIRouter(prefix="/api/rules", tags=["rules"])


def _to_out(rule: DetectionRule, implemented: set[str]) -> RuleOut:
    payload = RuleOut.model_validate(rule)
    payload.implemented = rule.rule_type in implemented
    return payload


@router.get("", response_model=list[RuleOut])
def list_rules(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    implemented = implemented_rule_types()
    rules = db.query(DetectionRule).order_by(DetectionRule.id).all()
    return [_to_out(rule, implemented) for rule in rules]


@router.patch("/{rule_id}", response_model=RuleOut)
def update_rule(
    rule_id: int,
    payload: RuleUpdate,
    db: Session = Depends(get_db),
    _user=Depends(require_role(UserRole.ADMINISTRATOR)),
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    # exclude_unset so a PATCH that only toggles `enabled` doesn't quietly
    # reset threshold/window to their schema defaults.
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)

    db.commit()
    db.refresh(rule)
    return _to_out(rule, implemented_rule_types())
