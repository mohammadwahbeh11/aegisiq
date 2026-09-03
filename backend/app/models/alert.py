import enum
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Enum, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.log import Severity


class AlertStatus(str, enum.Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(Base):
    """Matches the Alerts Table field-for-field from section 3.4.4 of the
    project document, plus log_id/incident_id/status which the build spec
    (sections 6 and 9) adds for investigation and correlation."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    severity = Column(Enum(Severity), nullable=False, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True)
    rule_id = Column(Integer, ForeignKey("detection_rules.id"), nullable=False)
    mitre_id = Column(String(20), nullable=True)
    kill_chain_phase = Column(String(64), nullable=True)
    description = Column(Text, nullable=False)
    status = Column(Enum(AlertStatus), nullable=False, default=AlertStatus.NEW, index=True)
    # What "the same ongoing incident" means for deduplication. For
    # network-borne rules (brute_force, port_scan) this is the source IP,
    # exactly as before. Rules whose events have no source IP set it to
    # whatever actually identifies the target -- the changed file path for
    # file_integrity, the username for privilege_escalation -- so two
    # different files being tampered with raise two alerts instead of the
    # second being swallowed as a duplicate of the first.
    dedup_key = Column(String(255), nullable=True, index=True)
    log_id = Column(Integer, ForeignKey("logs.id"), nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    rule = relationship("DetectionRule")
    log = relationship("Log", back_populates="alerts")
    incident = relationship("Incident", back_populates="alerts")
    status_history = relationship("AlertStatusHistory", back_populates="alert")


class AlertStatusHistory(Base):
    """Audit trail so status changes on the investigation page (section 11)
    are recorded, not just overwritten in place."""
    __tablename__ = "alert_status_history"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False, index=True)
    previous_status = Column(Enum(AlertStatus), nullable=True)
    new_status = Column(Enum(AlertStatus), nullable=False)
    changed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    changed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    alert = relationship("Alert", back_populates="status_history")
    changed_by_user = relationship("User", back_populates="status_changes")
