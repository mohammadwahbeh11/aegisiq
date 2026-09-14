import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, Integer, String, DateTime, Enum
from sqlalchemy.orm import relationship

from app.database import Base


class UserRole(str, enum.Enum):
    """
    Matches the two roles defined in the graduation project's Use Case
    Diagram (3.4.1): Administrator and Security Analyst.
    """
    ADMINISTRATOR = "administrator"
    SECURITY_ANALYST = "security_analyst"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.SECURITY_ANALYST)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime, nullable=True)

    # --- v3.2 accreditation columns ---------------------------------
    # AC-2 (account management): a disabled account keeps its audit
    # history but can no longer authenticate anywhere — REST or
    # WebSocket. Deleting the row would orphan the audit trail.
    is_active = Column(Boolean, nullable=False, default=True, server_default="1")
    # AC-7 (unsuccessful logon attempts): consecutive failures and the
    # instant the temporary lock expires. Reset on a successful login.
    failed_login_count = Column(Integer, nullable=False, default=0, server_default="0")
    locked_until = Column(DateTime, nullable=True)
    # IA-5 / AC-12 (session termination): bumping token_version
    # invalidates every JWT already issued for this user — that is how a
    # password change or a forced sign-out revokes live sessions in a
    # stateless-JWT design.
    token_version = Column(Integer, nullable=False, default=1, server_default="1")
    password_changed_at = Column(DateTime, nullable=True)

    status_changes = relationship("AlertStatusHistory", back_populates="changed_by_user")
