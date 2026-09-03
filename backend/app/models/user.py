import enum
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Enum
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

    status_changes = relationship("AlertStatusHistory", back_populates="changed_by_user")
