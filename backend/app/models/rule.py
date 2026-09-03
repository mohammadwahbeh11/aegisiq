from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Enum, Text, Boolean, JSON

from app.database import Base
from app.models.log import Severity


class DetectionRule(Base):
    """
    Executable detection rule row. `rule_type` is the key the detection
    engine (Phase 6 / Monday's work) dispatches on -- e.g. "brute_force",
    "port_scan" -- and threshold/time_window_seconds are read at
    evaluation time, so editing a rule from the UI changes real detection
    behavior without a code change or restart.
    """
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), unique=True, nullable=False)
    description = Column(Text, nullable=False)
    rule_type = Column(String(64), nullable=False, index=True)
    threshold = Column(Integer, nullable=False)
    time_window_seconds = Column(Integer, nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    mitre_id = Column(String(20), nullable=True)
    # Lockheed Martin Cyber Kill Chain phase (project objective O6), e.g.
    # "Credential Access", "Reconnaissance". Free text rather than a DB
    # enum for the same reason as Log.event_type: it's a fixed, small,
    # well-known vocabulary, but there's no benefit to a schema
    # migration if a rule needs a phase name adjusted.
    kill_chain_phase = Column(String(64), nullable=True)
    # Rule-specific tuning that doesn't fit threshold/time_window --
    # e.g. file_integrity's watched paths, privilege_escalation's
    # suspicious command patterns. JSON rather than one column per rule
    # so adding a rule never requires a schema change; every rule
    # documents its own expected keys in its module docstring, and each
    # reads it defensively with a documented fallback default.
    parameters = Column(JSON, nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
