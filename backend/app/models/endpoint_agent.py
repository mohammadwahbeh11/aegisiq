"""
app/models/endpoint_agent.py -- registered response agents and the orders
queued for them (v3.3).

Until now the SOAR layer decided and recorded containment and stopped
there, and `agent/kill_switch_agent_v2.py` polled two endpoints that did
not exist. These two tables are the missing half: which endpoints this
SIEM may act on, and what it has told them to do.

Why a QUEUE and not a direct call: the agent polls the SIEM
(`GET /api/soar/agent/orders`), so a protected host needs no inbound
port, no public address and no firewall exception — it works on a laptop
behind NAT and on a lab VM alike. The SIEM never connects INTO the
estate, which is also the posture an assessor expects from a response
tool (NIST SP 800-53 IR-4(2), SC-7).
"""
import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey, Integer, String, Text,
)

from app.database import Base


class OrderStatus(str, enum.Enum):
    QUEUED = "queued"          # written, not yet collected by the agent
    DELIVERED = "delivered"    # handed to the agent, awaiting its result
    SUCCEEDED = "succeeded"    # the agent applied it
    FAILED = "failed"          # the agent tried and reported an error
    EXPIRED = "expired"        # never collected inside its validity window
    CANCELLED = "cancelled"    # withdrawn by an administrator before delivery


class EndpointAgent(Base):
    """One protected host running the kill-switch agent."""

    __tablename__ = "endpoint_agents"

    id = Column(Integer, primary_key=True, index=True)
    # The agent's own identifier (AEGIS_ENDPOINT_ID). Orders are addressed
    # to this string, so it is the join key with the agent's config.
    endpoint_id = Column(String(64), unique=True, nullable=False, index=True)
    label = Column(String(128), nullable=True)
    hostname = Column(String(255), nullable=True, index=True)
    # Shared HMAC secret, encrypted at rest with the same AES-256-GCM key
    # as MFA material (app/security/crypto.py). A response agent's secret
    # is a remote-command capability: it never sits in the clear.
    secret_enc = Column(Text, nullable=False)
    platform = Column(String(32), nullable=True)      # linux / windows / darwin
    enabled = Column(Boolean, nullable=False, default=True, server_default="1")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime, nullable=True)
    last_seen_ip = Column(String(45), nullable=True)
    # Free-text note for the operator ("Kali attacker VM", "web-01 prod").
    note = Column(Text, nullable=True)


class SoarOrder(Base):
    """One containment command addressed to one agent."""

    __tablename__ = "soar_orders"

    id = Column(Integer, primary_key=True, index=True)
    # Opaque id the agent echoes back with its result.
    order_uid = Column(String(40), unique=True, nullable=False, index=True)
    endpoint_id = Column(String(64), nullable=False, index=True)
    action = Column(String(32), nullable=False)        # block_ip / unblock_ip / …
    target = Column(String(255), nullable=False)
    status = Column(Enum(OrderStatus), nullable=False,
                    default=OrderStatus.QUEUED, index=True)
    # The SOAR action this order carries out, so the console can show the
    # alert → decision → execution chain end to end.
    soar_action_id = Column(Integer, ForeignKey("soar_actions.id"), nullable=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    issued_by = Column(String(64), nullable=True)      # username, or "soar"
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    delivered_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    # An order not collected before this instant is never applied: a
    # containment decision that arrives an hour late is not containment,
    # it is a surprise outage.
    expires_at = Column(DateTime, nullable=True)
    output = Column(Text, nullable=True)               # the agent's own words
