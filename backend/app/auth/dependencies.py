from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.security import decode_access_token
from app.models.user import User, UserRole
from app.security import session_cookie

# tokenUrl is documentation-only here since /api/auth/login takes a JSON
# body rather than OAuth2 form data (see app/schemas/auth.py) -- this just
# makes the FastAPI /docs "Authorize" button point somewhere sensible.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def get_current_user(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Authenticate by bearer token or by the httpOnly session cookie.

    v3.2 — the cookie is the console's credential (nothing in
    localStorage for an XSS to steal); the bearer header remains the
    credential for API clients, agents and log shippers. A cookie-borne
    request that changes state must also carry the CSRF header, which
    only same-origin script can set — see app/security/session_cookie.py.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if token is None:
        token = session_cookie.token_from_request(request)
        if token is not None:
            # Only cookie-authenticated calls need the anti-forgery check.
            session_cookie.enforce_csrf(request)

    if token is None:
        raise credentials_exception

    payload = decode_access_token(token)
    if payload is None or "sub" not in payload:
        raise credentials_exception

    # A challenge token (issued after the password step but before the
    # TOTP step) must NEVER authenticate a normal request — it is only
    # valid at /api/auth/mfa/verify. Reject it everywhere else.
    if payload.get("mfa_pending"):
        raise credentials_exception

    user = db.query(User).filter(User.username == payload["sub"]).first()
    if user is None:
        raise credentials_exception

    # v3.2 — AC-2: a disabled account authenticates nowhere, even while
    # it still holds an unexpired token.
    if not getattr(user, "is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been disabled.",
        )

    # v3.2 — AC-12 / IA-5(1): every token carries the user's
    # token_version at mint time. A password change (or a forced
    # sign-out) increments the column, so tokens issued before it stop
    # validating immediately instead of living out their remaining TTL.
    # Tokens minted before this claim existed are treated as version 1,
    # matching the default column value.
    if int(payload.get("ver", 1)) != int(getattr(user, "token_version", 1) or 1):
        raise credentials_exception

    # v3.2 — AC-7: a token issued before the account was locked must not
    # outlive the lock.
    from app.security import lockout  # local import: avoids an import cycle
    if lockout.is_locked(user):
        raise credentials_exception

    return user


def require_role(*allowed_roles: UserRole):
    """Dependency factory: Depends(require_role(UserRole.ADMINISTRATOR))
    restricts a route to specific roles, enforcing the RBAC matrix from
    project section 15 (Administrator vs Security Analyst permissions)."""

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )
        return current_user

    return role_checker


def get_enrolling_user(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Authenticate a user who is allowed to SET UP their second factor
    but not yet to use the console (v3.2).

    The problem this solves: with ``MFA_REQUIRED=true`` a user who has
    never enrolled gets only an ``mfa_pending`` challenge token at login,
    and every other endpoint — /api/mfa/enroll included — rejects that
    token. Turning the flag on therefore locked the administrator out of
    their own console: the one action they needed was the one action they
    could not reach. The requirement could be documented but never
    switched on, which is the worst outcome of the three.

    So enrolment (and only enrolment) accepts EITHER credential:

      * a full access token — an already-signed-in user adding MFA, or
      * a challenge token — the password step passed, the second factor
        does not exist yet.

    The challenge token stays useless everywhere else (it is rejected by
    get_current_user and by the WebSocket), it lives five minutes, and it
    cannot read or change a single piece of SOC data. The account state
    checks below are the same ones every other request gets.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if token is None:
        token = session_cookie.token_from_request(request)
        if token is not None:
            session_cookie.enforce_csrf(request)
    if token is None:
        raise credentials_exception

    payload = decode_access_token(token)
    if payload is None or "sub" not in payload:
        raise credentials_exception

    user = db.query(User).filter(User.username == payload["sub"]).first()
    if user is None:
        raise credentials_exception
    if not getattr(user, "is_active", True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="This account has been disabled.")

    from app.security import lockout
    if lockout.is_locked(user):
        raise credentials_exception

    # A full (non-challenge) token must still be current.
    if not payload.get("mfa_pending"):
        if int(payload.get("ver", 1)) != int(getattr(user, "token_version", 1) or 1):
            raise credentials_exception

    return user
