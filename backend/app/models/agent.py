import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Enum
from sqlalchemy.orm import relationship

from app.database import Base


class AgentStatus(str, enum.Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    WARNING = "warning"


class Agent(Base):
    """
    A monitored endpoint (Layer 1 of the project's 5-layer architecture:
    Windows PCs, Linux servers, web servers, etc.). In the lightweight
    implementation, an "agent" is just an identifier that logs are tagged
    with -- it does not require installing real shipping software, which
    keeps the demo runnable without extra moving parts.
    """
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    hostname = Column(String(255), nullable=False, index=True)
    operating_system = Column(String(64), nullable=False)
    ip_address = Column(String(45), nullable=False)
    status = Column(Enum(AgentStatus), nullable=False, default=AgentStatus.OFFLINE)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    logs = relationship("Log", back_populates="agent")
