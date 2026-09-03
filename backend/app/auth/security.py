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


def create_access_token(subject: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": subject, "role": role, "exp": expire}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_mfa_challenge_token(subject: str) -> str:
    """A short-lived token issued after password verification but BEFORE
    the second factor. It carries ``mfa_pending: true`` so it can never
    be used as a real access token — get_current_user rejects it — and
    expires in 5 minutes so a captured challenge token is useless for
    long. The only endpoint that accepts it is /api/auth/mfa/verify."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=5)
    to_encode = {"sub": subject, "mfa_pending": True, "exp": expire}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None
