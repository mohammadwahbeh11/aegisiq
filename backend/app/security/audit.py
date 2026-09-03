"""
app/security/audit.py -- append-only audit trail for mutating actions.

Every action that changes system state -- login (success and failure),
password change, rule edit, alert deletion, retention purge, agent
registration, SOAR mode change -- is recorded in the audit_log table
via `record()`. The table is never updated or deleted from application
code; entries are strictly append-only, and the retention purge does
NOT touch it (audit lifecycle is a separate policy the compliance team
sets, not a knob a mis-clicked purge can trip).

Design:
  * one row per action; who, when, what, target, outcome, source IP
  * schemaless `details` (JSON) for action-specific context
  * indexed on (username, action, timestamp) for the "what did user X
    do this week" query pattern

The audit route (app/api/routes/audit.py) exposes a read-only view.
Analysts can see their own actions; administrators see everything.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Column, DateTime, Integer, String, JSON, Boolean, Index
from sqlalchemy.orm import Session

from app.database import Base

logger = logging.getLogger(__name__)


class AuditEntry(Base):
    """One row = one action. Never mutated after insertion."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True,
                       default=lambda: datetime.now(timezone.utc))
    username = Column(String(128), nullable=True, index=True)  # nullable: pre-auth events
    action = Column(String(64), nullable=False, index=True)
    target = Column(String(255), nullable=True)   # rule id, alert id, IP, etc.
    outcome = Column(String(16), nullable=False)  # "success" | "failure"
    source_ip = Column(String(45), nullable=True, index=True)
    details = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_audit_username_action_ts", "username", "action", "timestamp"),
    )


# Canonical action names -- kept as constants so a typo becomes an
# ImportError, not a silently-broken query later.
ACT_LOGIN_SUCCESS = "auth.login.success"
ACT_LOGIN_FAILURE = "auth.login.failure"
ACT_LOGOUT = "auth.logout"
ACT_PASSWORD_CHANGE = "auth.password_change"
ACT_RULE_UPDATE = "rule.update"
ACT_ALERT_STATUS = "alert.status_change"
ACT_ALERT_DELETE = "alert.delete"
ACT_LOG_DELETE = "log.delete"
ACT_RETENTION_PURGE = "retention.purge"
ACT_AGENT_REGISTER = "agent.register"
ACT_SIMULATION_RUN = "simulation.run"
# v2.3 MFA
ACT_MFA_ENROLL_START = "auth.mfa.enroll_start"
ACT_MFA_ENROLL_CONFIRM = "auth.mfa.enroll_confirm"
ACT_MFA_DISABLE = "auth.mfa.disable"
ACT_MFA_CHALLENGE_SUCCESS = "auth.mfa.challenge_success"
ACT_MFA_CHALLENGE_FAILURE = "auth.mfa.challenge_failure"
ACT_MFA_BACKUP_USED = "auth.mfa.backup_used"


def record(
    db: Session,
    *,
    action: str,
    outcome: str = "success",
    username: str | None = None,
    target: str | None = None,
    source_ip: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Insert one audit row. Never raises into the caller -- an audit
    failure must not turn a successful operation into a failed HTTP
    response the analyst has to debug. Failures are logged."""
    try:
        entry = AuditEntry(
            action=action,
            outcome=outcome,
            username=username,
            target=str(target) if target is not None else None,
            source_ip=source_ip,
            details=details,
        )
        db.add(entry)
        db.commit()
    except Exception:  # noqa: BLE001
        logger.exception("audit write failed for action=%r target=%r", action, target)
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
