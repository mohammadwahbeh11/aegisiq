"""
Authentication routes -- login + password change.

v2.0 additions:
  * per-IP rate limit on /api/auth/login (app/security/rate_limit.py)
  * every login attempt (success and failure) recorded in audit_log
  * PATCH /api/auth/password enforces app/security/password_policy.py
  * successful password change re-hashes only that user's password;
    it does NOT invalidate other users' sessions (the JWTs already
    issued keep their own expiry).
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.dependencies import get_current_user
from app.auth.security import (
    create_access_token, create_mfa_challenge_token, decode_access_token,
    hash_password, verify_password,
)
from app.config import get_settings
from app.models.user import User
from app.schemas.auth import LoginRequest, LoginResult, MfaVerifyRequest, TokenResponse
from app.security import audit
from app.security.mfa_service import is_active, login_requires_second_factor, verify_code
from app.security.password_policy import validate as validate_password
from app.security.net import client_ip
from app.security.rate_limit import enforce_auth
from app.security import lockout

router = APIRouter(prefix="/api/auth", tags=["auth"])
settings = get_settings()


def _source_ip(request: Request) -> str | None:
    """v3.2 — see app/security/net.py. X-Forwarded-For is only honoured
    behind a declared reverse proxy; otherwise a client could spoof it
    to evade the rate limit and falsify the audit trail."""
    return client_ip(request)


@router.post("/login", response_model=LoginResult)
def login(
    payload: LoginRequest,
    request: Request,
    _rate=Depends(enforce_auth),
    db: Session = Depends(get_db),
):
    """
    Step 1 of login: exchange (username, password) for either a full JWT
    (no MFA) or a short-lived MFA challenge token (MFA active/required).
    Rate-limited per source IP to prevent credential-stuffing against the
    API itself.
    """
    src = _source_ip(request)
    user = db.query(User).filter(User.username == payload.username).first()

    # AC-7 — a locked account is refused before the password is even
    # checked, with the SAME body as a wrong password so the response
    # cannot be used to discover which usernames exist or which are
    # locked. The distinction lives in the audit trail.
    if user is not None and lockout.is_locked(user):
        audit.record(
            db,
            action=lockout.ACT_LOGIN_BLOCKED_LOCKED,
            outcome="failure",
            username=payload.username,
            source_ip=src,
            details={"reason": "account_locked",
                     "seconds_remaining": lockout.seconds_remaining(user)},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    # AC-2 — a disabled account never authenticates, for any reason.
    if user is not None and not user.is_active:
        audit.record(
            db, action=audit.ACT_LOGIN_FAILURE, outcome="failure",
            username=payload.username, source_ip=src,
            details={"reason": "account_disabled"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if user is None or not verify_password(payload.password, user.password_hash):
        # Same error for "user not found" and "wrong password" so the API
        # never reveals which usernames exist.
        just_locked = lockout.register_failure(db, user) if user is not None else False
        audit.record(
            db,
            action=audit.ACT_LOGIN_FAILURE,
            outcome="failure",
            username=payload.username,
            source_ip=src,
            details={"reason": "invalid_credentials"},
        )
        if just_locked:
            audit.record(
                db,
                action=lockout.ACT_ACCOUNT_LOCKED,
                outcome="failure",
                username=payload.username,
                source_ip=src,
                details={"threshold": settings.LOCKOUT_THRESHOLD,
                         "minutes": settings.LOCKOUT_MINUTES},
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    # ── Second-factor gate ────────────────────────────────────────────
    if login_requires_second_factor(db, user):
        challenge = create_mfa_challenge_token(subject=user.username)
        if is_active(db, user):
            # Enrolled: ask for the code. (Password step audited as success
            # once the second factor lands, at /mfa/verify.)
            return LoginResult(mfa_required=True, mfa_token=challenge)
        # MFA_REQUIRED is on but the user has never enrolled — the
        # challenge token authorises the /api/mfa/enroll call and nothing
        # else, so they can set it up and then log in properly.
        return LoginResult(mfa_required=True, enrollment_required=True, mfa_token=challenge)

    # ── No second factor needed → full token, as in v2.0/2.1 ──────────
    lockout.register_success(db, user)
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    audit.record(
        db, action=audit.ACT_LOGIN_SUCCESS, outcome="success",
        username=user.username, source_ip=src, details={"role": user.role.value},
    )
    token = create_access_token(
        subject=user.username, role=user.role.value, token_version=user.token_version,
    )
    return LoginResult(
        access_token=token, username=user.username, role=user.role,
    )


@router.post("/mfa/verify", response_model=TokenResponse)
def mfa_verify(
    payload: MfaVerifyRequest,
    request: Request,
    _rate=Depends(enforce_auth),
    db: Session = Depends(get_db),
):
    """
    Step 2 of login: exchange the challenge token + a TOTP (or backup)
    code for a full access token. Rate-limited like /login so codes
    cannot be brute-forced.
    """
    src = _source_ip(request)
    claims = decode_access_token(payload.mfa_token)
    if not claims or not claims.get("mfa_pending") or "sub" not in claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA challenge. Start login again.",
        )

    user = db.query(User).filter(User.username == claims["sub"]).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid or expired MFA challenge. Start login again.")

    ok, method = verify_code(db, user, payload.code)
    if not ok:
        audit.record(db, action=audit.ACT_MFA_CHALLENGE_FAILURE, outcome="failure",
                     username=user.username, source_ip=src)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="That authentication code is not valid.",
        )

    if method == "backup":
        audit.record(db, action=audit.ACT_MFA_BACKUP_USED, outcome="success",
                     username=user.username, source_ip=src)
    audit.record(db, action=audit.ACT_MFA_CHALLENGE_SUCCESS, outcome="success",
                 username=user.username, source_ip=src, details={"method": method})

    lockout.register_success(db, user)
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    audit.record(db, action=audit.ACT_LOGIN_SUCCESS, outcome="success",
                 username=user.username, source_ip=src,
                 details={"role": user.role.value, "mfa": method})

    token = create_access_token(
        subject=user.username, role=user.role.value, token_version=user.token_version,
    )
    return TokenResponse(access_token=token, username=user.username, role=user.role)


# ─── v2.0 password change ────────────────────────────────────────────
class PasswordChangeRequest(BaseModel):
    """User must supply the current password to change it -- prevents a
    hijacked session from locking the real user out with a new password."""
    current_password: str = Field(..., min_length=1, max_length=256)
    new_password: str = Field(..., min_length=1, max_length=256)


class PasswordChangeResponse(BaseModel):
    ok: bool
    detail: str
    policy_errors: list[str] = []


@router.patch("/password", response_model=PasswordChangeResponse)
def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Change the CURRENT user's password. Enforces the server-side
    policy (app/security/password_policy.py) and re-hashes with bcrypt.
    """
    src = _source_ip(request)

    if not verify_password(payload.current_password, user.password_hash):
        audit.record(db, action=audit.ACT_PASSWORD_CHANGE, outcome="failure",
                     username=user.username, source_ip=src,
                     details={"reason": "current_password_incorrect"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The current password you supplied is incorrect.",
        )

    result = validate_password(payload.new_password, user.username)
    if not result.ok:
        audit.record(db, action=audit.ACT_PASSWORD_CHANGE, outcome="failure",
                     username=user.username, source_ip=src,
                     details={"reason": "policy_violation", "errors": result.errors})
        return PasswordChangeResponse(
            ok=False,
            detail="The new password does not meet the password policy.",
            policy_errors=result.errors,
        )

    if verify_password(payload.new_password, user.password_hash):
        return PasswordChangeResponse(
            ok=False,
            detail="The new password must be different from the current password.",
            policy_errors=["Must differ from the current password."],
        )

    user.password_hash = hash_password(payload.new_password)
    # AC-12 / IA-5(1) — revoke every token minted before this change.
    # Previously the old JWTs stayed valid for the rest of their TTL,
    # which means changing a password after a suspected compromise did
    # not actually evict the intruder. Bumping token_version does.
    user.token_version = int(user.token_version or 1) + 1
    user.password_changed_at = datetime.now(timezone.utc)
    db.commit()

    audit.record(db, action=audit.ACT_PASSWORD_CHANGE, outcome="success",
                 username=user.username, source_ip=src,
                 details={"sessions_revoked": True,
                          "token_version": user.token_version})

    return PasswordChangeResponse(
        ok=True,
        detail=("Password changed successfully. All existing sessions have been "
                "signed out — log in again with the new password."),
    )


@router.get("/policy", response_model=dict)
def get_password_policy():
    """Return the current password policy so the frontend can show the
    exact requirements next to the password input, instead of guessing."""
    from app.security.password_policy import MIN_LENGTH, MIN_CATEGORIES
    return {
        "min_length": MIN_LENGTH,
        "min_categories": MIN_CATEGORIES,
        "categories": ["lowercase", "uppercase", "digit", "symbol"],
        "requirements": [
            f"At least {MIN_LENGTH} characters",
            f"At least {MIN_CATEGORIES} of: lowercase, uppercase, digit, symbol",
            "Not on the well-known-leak list",
            "Cannot equal or contain the username",
        ],
    }
