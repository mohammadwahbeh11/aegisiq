import enum
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Enum, Text, JSON, ForeignKey, Index
from sqlalchemy.orm import relationship

from app.database import Base


class Severity(str, enum.Enum):
    """Shared by Log and Alert, matching the Severity enum in the project's
    Logs Table / Alerts Table design (section 3.4.4)."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Log(Base):
    """
    The normalized event format described in the project document
    (section 7 of the build spec / normalization pipeline). `event_type`
    is intentionally a plain indexed string rather than a DB-level enum:
    the parsers (Linux auth, Windows-style, generic JSON) each introduce
    their own event types, and a lightweight system should not require a
    schema migration every time a new log source is added. Valid values
    are constrained instead at the API/schema layer.
    """
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    hostname = Column(String(255), nullable=True, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    # Indexed: the Phase B port-scan rule queries "distinct destination
    # ports per source IP in the last N seconds", so this column is on
    # the hot query path, not just a nice-to-have field.
    destination_port = Column(Integer, nullable=True, index=True)
    username = Column(String(128), nullable=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    severity = Column(Enum(Severity), nullable=False, default=Severity.LOW, index=True)
    raw_log = Column(Text, nullable=False)
    normalized_data = Column(JSON, nullable=True)
    source = Column(String(32), nullable=False, default="generic")  # linux / windows / network / generic
    operating_system = Column(String(64), nullable=True)
    # Windows Security Event ID (4625/4624/4672/...), preserved verbatim
    # for forensic value even when it maps to a known event_type.
    event_id = Column(Integer, nullable=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    agent = relationship("Agent", back_populates="logs")
    alerts = relationship("Alert", back_populates="log")

    __table_args__ = (
        # Composite index: the detection engine's core query pattern is
        # "events from this source IP, of this type, in the last N seconds"
        Index("ix_logs_source_ip_event_type_timestamp", "source_ip", "event_type", "timestamp"),
    )
