from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.security import decode_access_token
from app.models.user import User, UserRole

# tokenUrl is documentation-only here since /api/auth/login takes a JSON
# body rather than OAuth2 form data (see app/schemas/auth.py) -- this just
# makes the FastAPI /docs "Authorize" button point somewhere sensible.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
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
