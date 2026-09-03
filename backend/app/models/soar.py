import enum
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Enum, Text, ForeignKey, Boolean
from sqlalchemy.orm import relationship

from app.database import Base


class SoarActionType(str, enum.Enum):
    """The containment playbooks this build knows about. Kept as an enum
    (unlike Log.event_type) because each value corresponds to a specific
    documented playbook in app/soar/engine.py -- an unknown value here
    would mean an action nobody can explain to an auditor."""

    BLOCK_IP = "block_ip"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_ACCOUNT = "disable_account"
    NOTIFY_ANALYST = "notify_analyst"


class SoarActionStatus(str, enum.Enum):
    """
    SIMULATED is the honest default and the only status this build
    produces on its own: the action was decided, recorded, and shown to
    the analyst, but nothing was executed against a real host. See
    app/soar/engine.py and the SOAR_EXECUTE setting -- this project
    deliberately ships no code that runs a firewall command.

    PENDING/EXECUTED/FAILED exist so a real executor can be added later
    without a schema change, and so the console never has to guess what
    a status means.
    """

    SIMULATED = "simulated"
    PENDING = "pending"
    EXECUTED = "executed"
    FAILED = "failed"


class SoarAction(Base):
    """
    One automated-response decision taken in reaction to an Alert
    (project section 3.4.3 -- the "automated response" half of SIEM &
    SOAR). Persisted rather than only broadcast so the console can show
    a containment history, and so every action is auditable after the
    fact: which alert caused it, what it targeted, and whether it was
    actually carried out or only simulated.
    """

    __tablename__ = "soar_actions"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True, default=lambda: datetime.now(timezone.utc))
    action_type = Column(Enum(SoarActionType), nullable=False, index=True)
    target = Column(String(255), nullable=False, index=True)  # IP, hostname or username
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True, index=True)
    rule_name = Column(String(128), nullable=True)
    status = Column(Enum(SoarActionStatus), nullable=False, default=SoarActionStatus.SIMULATED, index=True)
    # Free text explaining, in the analyst's language, what was decided
    # and why -- shown verbatim in the console.
    detail = Column(Text, nullable=True)
    # True only when the deployment opted in via SOAR_EXECUTE. Recorded
    # per-row so a history that spans a config change stays truthful.
    execution_requested = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    alert = relationship("Alert")
