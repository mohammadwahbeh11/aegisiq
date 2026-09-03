"""
Detection engine entry point.

STATUS: all five detection rules from the project document's Table 1
(section 3.6 - Features of the Detection Engine) are now implemented and
dispatched from here:

    brute_force           -- Phase B1
    port_scan             -- Phase B2
    login_after_failure   -- Phase C
    file_integrity        -- Phase C
    privilege_escalation  -- Phase C

Architecture: this module is a thin dispatcher. Each rule's actual logic
lives in its own module under app/detection/rules/, keeping "which rules
exist" (this file) separate from "how each rule decides" (the rules/
subpackage) -- so adding a new rule means adding one new module and one
registry entry, not touching this function's body. Shared
deduplication/alert-creation logic lives in app/detection/alerting.py,
used by every rule module.

A rule row whose rule_type has no handler here is skipped rather than
treated as an error: an administrator can add a row for a rule type this
build does not implement, and the engine's job is to run what it can,
not to crash on what it cannot.

The public contract (evaluate(log, db) -> list[int]) is unchanged since
Phase A, so app/ingestion/service.py's call site needed no changes.
"""
from sqlalchemy.orm import Session

from app.detection.rules import (
    brute_force,
    credential_stuffing,
    file_integrity,
    login_after_failure,
    port_scan,
    privilege_escalation,
    suspicious_user_agent,
    web_attack,
)
from app.models.log import Log
from app.models.rule import DetectionRule

# rule_type -> (log, rule, db) -> Alert | None
_RULE_HANDLERS = {
    "brute_force": brute_force.evaluate,
    "port_scan": port_scan.evaluate,
    "login_after_failure": login_after_failure.evaluate,
    "file_integrity": file_integrity.evaluate,
    "privilege_escalation": privilege_escalation.evaluate,
    # v2.0 additions
    "web_attack": web_attack.evaluate,
    "credential_stuffing": credential_stuffing.evaluate,
    "suspicious_user_agent": suspicious_user_agent.evaluate,
}


def implemented_rule_types() -> set[str]:
    """Which rule types this build can actually execute. Used by /health
    so the reported detection-engine status is derived from the registry
    rather than being a string somebody has to remember to update."""
    return set(_RULE_HANDLERS)


def evaluate(log: Log, db: Session, store=None) -> list[int]:
    """Evaluate every enabled rule with an implemented handler against a
    newly persisted log. Returns the ids of any Alert rows created.

    `store` is the LogStore the historical-count rules query against
    (v2.4). It defaults to the SQLAlchemy backend over `db`, so behaviour
    is identical to before when LOG_STORE=sqlalchemy; with an external
    event store the same rules query there instead. Handlers receive it
    as a 4th argument; per-event rules (web_attack, suspicious_user_agent)
    accept and ignore it."""
    if store is None:
        from app.storage import get_log_store
        store = get_log_store(db)

    alert_ids: list[int] = []

    rules = db.query(DetectionRule).filter(DetectionRule.enabled.is_(True)).all()
    for rule in rules:
        handler = _RULE_HANDLERS.get(rule.rule_type)
        if handler is None:
            continue  # no handler for this rule type in this build -- not a bug
        alert = handler(log, rule, db, store)
        if alert is not None:
            alert_ids.append(alert.id)

    return alert_ids
