import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import get_settings

settings = get_settings()

# bcrypt: passwords are never stored in plaintext (project section 15 /
# build spec section 19). Truncation of inputs over 72 bytes is bcrypt's
# own documented limitation, not something this app introduces.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def create_access_token(subject: str, role: str, token_version: int = 1) -> str:
    """Mint an access token.

    v3.2 claims, all verified on the way back in (see
    ``decode_access_token``):

      iss / aud  — this console, so a token minted by another service
                   that happens to share the secret cannot be replayed
                   here (NIST SP 800-53 IA-5, RFC 7519 §4.1.1/4.1.3).
      iat / nbf  — issue time and not-before, so a token's age is
                   auditable rather than inferred from ``exp``.
      jti        — unique id; gives the audit trail a handle on an
                   individual session (AU-3).
      ver        — the user's ``token_version``. Bumping that column
                   invalidates every token already issued for the user,
                   which is how a stateless JWT design still terminates
                   live sessions on password change (AC-12).
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": subject,
        "role": role,
        "exp": expire,
        "iat": now,
        "nbf": now,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "jti": secrets.token_urlsafe(16),
        "ver": int(token_version or 1),
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_mfa_challenge_token(subject: str) -> str:
    """A short-lived token issued after password verification but BEFORE
    the second factor. It carries ``mfa_pending: true`` so it can never
    be used as a real access token — get_current_user rejects it — and
    expires in 5 minutes so a captured challenge token is useless for
    long. The only endpoint that accepts it is /api/auth/mfa/verify."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=5)
    to_encode = {
        "sub": subject,
        "mfa_pending": True,
        "exp": expire,
        "iat": now,
        "nbf": now,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    """Verify signature, expiry, issuer and audience. Returns None on any
    failure — callers translate that into 401 without echoing the reason,
    so a malformed token never explains itself to the caller.

    ``algorithms`` is pinned to the single configured algorithm: accepting
    a list the token itself chooses is the classic "alg: none" / HS-vs-RS
    confusion attack (OWASP ASVS V3.5.3).
    """
    try:
        return jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
        )
    except JWTError:
        return None
