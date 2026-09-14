"""
app/security/lockout.py -- per-account lockout after consecutive failed
logons (NIST SP 800-53 AC-7, DoD STIG APSC-DV-000110, CIS Benchmark
"account lockout threshold", OWASP ASVS V2.2.1).

Why this exists alongside the rate limiter
------------------------------------------
``app/security/rate_limit.py`` throttles per SOURCE ADDRESS. That stops
one host hammering the login endpoint, and nothing else: a credential
stuffing run spread over a botnet sends one attempt per address, so
every bucket stays full and the limiter never fires. The control that
actually protects an ACCOUNT is a counter attached to the account.

Design decisions
----------------
* **Temporary, self-clearing lock.** ``LOCKOUT_MINUTES`` (default 15)
  rather than an administrator-only unlock. A permanent lock turns a
  failed-password guess against a known username into a denial of
  service on the real analyst — during an incident, that is the
  attacker's win condition. 800-63B endorses a throttle of this shape.
* **Counted on password failure only**, not on a wrong TOTP code (that
  path has its own audit events and already requires a valid password).
* **No enumeration.** A locked account returns the same 401 body as a
  wrong password. The distinction is recorded in the audit trail, where
  a defender can see it and an attacker cannot.
* **Failure is not fatal.** If the counter cannot be persisted the login
  still proceeds on its own merits; a broken counter must not lock
  everybody out.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.user import User

logger = logging.getLogger(__name__)
settings = get_settings()

# Audit action names (recorded by the caller, kept here so the strings
# live next to the logic that produces them).
ACT_ACCOUNT_LOCKED = "auth.account.locked"
ACT_LOGIN_BLOCKED_LOCKED = "auth.login.blocked_locked"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; compare them as UTC."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def is_locked(user: User) -> bool:
    """True while this account is inside its lockout window."""
    until = _aware(user.locked_until)
    return until is not None and until > _now()


def seconds_remaining(user: User) -> int:
    until = _aware(user.locked_until)
    if until is None:
        return 0
    return max(0, int((until - _now()).total_seconds()))


def register_failure(db: Session, user: User) -> bool:
    """Count one failed password attempt. Returns True if this attempt
    tripped the threshold and locked the account."""
    threshold = settings.LOCKOUT_THRESHOLD
    if threshold <= 0:
        return False
    try:
        user.failed_login_count = (user.failed_login_count or 0) + 1
        locked = False
        if user.failed_login_count >= threshold:
            user.locked_until = _now() + timedelta(minutes=settings.LOCKOUT_MINUTES)
            user.failed_login_count = 0
            locked = True
        db.commit()
        return locked
    except Exception:  # noqa: BLE001 - a broken counter must not break login
        logger.exception("failed to record a login failure for %r", user.username)
        db.rollback()
        return False


def register_success(db: Session, user: User) -> None:
    """Clear the counter after a successful authentication."""
    try:
        if user.failed_login_count or user.locked_until:
            user.failed_login_count = 0
            user.locked_until = None
            db.commit()
    except Exception:  # noqa: BLE001
        logger.exception("failed to clear the lockout counter for %r", user.username)
        db.rollback()


def unlock(db: Session, user: User) -> None:
    """Administrative unlock (also used by tests)."""
    user.failed_login_count = 0
    user.locked_until = None
    db.commit()
