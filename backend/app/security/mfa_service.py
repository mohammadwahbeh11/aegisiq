"""
app/security/mfa_service.py -- shared MFA helpers used by both the
login flow (app/api/routes/auth.py) and the enrolment routes
(app/api/routes/mfa.py). Keeping the logic here means the "is a second
factor required for this user?" and "does this code verify?" rules live
in exactly one place.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.mfa import MfaStatus, UserMFA
from app.models.user import User
from app.security import crypto, totp

settings = get_settings()


def get_mfa(db: Session, user: User) -> UserMFA | None:
    return db.query(UserMFA).filter(UserMFA.user_id == user.id).first()


def is_active(db: Session, user: User) -> bool:
    """True when the user has a confirmed TOTP enrolment that must be
    satisfied at login."""
    row = get_mfa(db, user)
    return bool(row and row.status == MfaStatus.ACTIVE and row.secret_enc)


def login_requires_second_factor(db: Session, user: User) -> bool:
    """Whether THIS login must present a second factor.

    * If the feature is globally off (MFA_ENABLED=false) → never.
    * If the user has active MFA → yes.
    * If MFA_REQUIRED is on but the user hasn't enrolled → yes, and the
      login flow will steer them to enrol (they cannot get a full token
      until they do).
    """
    if not settings.MFA_ENABLED:
        return False
    if is_active(db, user):
        return True
    return bool(settings.MFA_REQUIRED)


def verify_code(db: Session, user: User, code: str) -> tuple[bool, str]:
    """Verify a submitted code against the user's TOTP secret, then (if
    that fails) against the one-time backup codes. Returns
    (ok, method) where method is 'totp', 'backup', or '' on failure.

    A used backup code is consumed (removed from the stored list) so it
    cannot be replayed."""
    row = get_mfa(db, user)
    if row is None or row.status != MfaStatus.ACTIVE or not row.secret_enc:
        return False, ""

    secret = crypto.decrypt(row.secret_enc)
    if secret and totp.verify(secret, code, window=settings.MFA_TOTP_WINDOW):
        row.last_used_at = datetime.now(timezone.utc)
        db.commit()
        return True, "totp"

    # Fall back to backup codes (compared by salted hash, then consumed).
    submitted = code.strip().lower().replace(" ", "")
    hashes = row.load_backup_hashes()
    target = crypto.hash_lookup(submitted)
    if target in hashes:
        hashes.remove(target)                 # consume — single use
        row.store_backup_hashes(hashes)
        row.last_used_at = datetime.now(timezone.utc)
        db.commit()
        return True, "backup"

    return False, ""
