"""
app/api/routes/mfa.py -- multi-factor authentication enrolment &
management (AegisIQ v2.3).

Flow:
  GET    /api/mfa/status     -> where this user stands
  POST   /api/mfa/enroll     -> issue a secret + otpauth URI (status PENDING)
  POST   /api/mfa/confirm    -> submit first code -> status ACTIVE, returns
                                the one-time backup codes
  POST   /api/mfa/disable    -> turn MFA off (must prove a current code)

The actual login challenge lives in app/api/routes/auth.py
(/api/auth/mfa/verify) because it is part of the login exchange.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.dependencies import get_current_user
from app.config import get_settings
from app.models.mfa import MfaStatus, UserMFA
from app.models.user import User
from app.security import audit, crypto, totp
from app.security.mfa_service import get_mfa

router = APIRouter(prefix="/api/mfa", tags=["mfa"])
settings = get_settings()


def _source_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return fwd or (request.client.host if request.client else None)


class MfaStatusResponse(BaseModel):
    status: str
    enabled_globally: bool
    required_globally: bool
    backup_codes_remaining: int = 0
    confirmed_at: str | None = None


class EnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str
    issuer: str
    account: str
    note: str


class ConfirmRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=12)


class ConfirmResponse(BaseModel):
    status: str
    backup_codes: list[str]
    note: str


class DisableRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=12)


@router.get("/status", response_model=MfaStatusResponse)
def mfa_status(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    row = get_mfa(db, user)
    return MfaStatusResponse(
        status=(row.status.value if row else MfaStatus.DISABLED.value),
        enabled_globally=settings.MFA_ENABLED,
        required_globally=settings.MFA_REQUIRED,
        backup_codes_remaining=len(row.load_backup_hashes()) if row else 0,
        confirmed_at=row.confirmed_at.isoformat() if row and row.confirmed_at else None,
    )


@router.post("/enroll", response_model=EnrollResponse)
def enroll(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Begin enrolment: generate a fresh secret, store it PENDING (not yet
    enforced), and return the otpauth URI + secret for the user to add to
    their authenticator app. Re-enrolling overwrites any pending secret;
    an already-ACTIVE enrolment must be disabled first."""
    row = get_mfa(db, user)
    if row and row.status == MfaStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA is already active. Disable it first to re-enrol.",
        )

    secret = totp.generate_secret()
    if row is None:
        row = UserMFA(user_id=user.id)
        db.add(row)
    row.secret_enc = crypto.encrypt(secret)   # AES-256-GCM at rest
    row.status = MfaStatus.PENDING
    row.backup_codes_enc = None
    row.confirmed_at = None
    db.commit()

    audit.record(db, action=audit.ACT_MFA_ENROLL_START, outcome="success",
                 username=user.username, source_ip=_source_ip(request))

    return EnrollResponse(
        secret=secret,
        otpauth_uri=totp.provisioning_uri(secret, user.username, settings.MFA_ISSUER),
        issuer=settings.MFA_ISSUER,
        account=user.username,
        note=("Scan the QR (or paste the setup key) into Google Authenticator, "
              "Authy, 1Password or Microsoft Authenticator, then confirm with a "
              "6-digit code to activate. You will receive one-time backup codes."),
    )


@router.post("/confirm", response_model=ConfirmResponse)
def confirm(payload: ConfirmRequest, request: Request,
            db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Finish enrolment: verify the first code, flip to ACTIVE, and issue
    one-time backup codes (shown once, stored only as salted hashes)."""
    row = get_mfa(db, user)
    if row is None or row.status == MfaStatus.DISABLED or not row.secret_enc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No pending enrolment. Call /api/mfa/enroll first.")

    secret = crypto.decrypt(row.secret_enc)
    if not secret or not totp.verify(secret, payload.code, window=settings.MFA_TOTP_WINDOW):
        audit.record(db, action=audit.ACT_MFA_ENROLL_CONFIRM, outcome="failure",
                     username=user.username, source_ip=_source_ip(request),
                     details={"reason": "code_mismatch"})
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="That code did not verify. Check your phone's clock and try the current code.")

    backup_codes = totp.generate_backup_codes(10)
    row.store_backup_hashes([crypto.hash_lookup(c.replace("-", "")) for c in backup_codes])
    row.status = MfaStatus.ACTIVE
    row.confirmed_at = datetime.now(timezone.utc)
    db.commit()

    audit.record(db, action=audit.ACT_MFA_ENROLL_CONFIRM, outcome="success",
                 username=user.username, source_ip=_source_ip(request))

    return ConfirmResponse(
        status=MfaStatus.ACTIVE.value,
        backup_codes=backup_codes,
        note=("Store these backup codes somewhere safe. Each works ONCE if you "
              "lose your authenticator. They are not shown again."),
    )


@router.post("/disable")
def disable(payload: DisableRequest, request: Request,
            db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Turn MFA off. Requires a currently-valid code (TOTP or backup) so a
    hijacked session cannot silently strip the second factor."""
    row = get_mfa(db, user)
    if row is None or row.status != MfaStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="MFA is not active for this account.")

    from app.security.mfa_service import verify_code
    ok, _method = verify_code(db, user, payload.code)
    if not ok:
        audit.record(db, action=audit.ACT_MFA_DISABLE, outcome="failure",
                     username=user.username, source_ip=_source_ip(request),
                     details={"reason": "code_mismatch"})
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Provide a current authenticator or backup code to disable MFA.")

    row.status = MfaStatus.DISABLED
    row.secret_enc = None
    row.backup_codes_enc = None
    row.confirmed_at = None
    db.commit()

    audit.record(db, action=audit.ACT_MFA_DISABLE, outcome="success",
                 username=user.username, source_ip=_source_ip(request))
    return {"ok": True, "detail": "MFA disabled for your account."}
