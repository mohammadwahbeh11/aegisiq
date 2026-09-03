from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.orm import relationship

from app.database import Base


class Incident(Base):
    """
    Groups multiple related Alerts into one correlated security incident
    (project section 3.4.3 / event correlation: failed logins -> success
    -> privilege escalation = one incident). This table exists from Phase
    2 onward so the schema is stable; the correlation engine that
    populates it is implemented in the detection-engine phase.
    """
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(32), nullable=False, default="open")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    alerts = relationship("Alert", back_populates="incident")
