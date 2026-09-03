"""
Monitored endpoints (Layer 1 of the project's 5-layer architecture).

Two sources are merged here:
  * agents registered directly with this SIEM (rows in the `agents`
    table, marked source="local"), and
  * agents pulled live from a Wazuh Manager, when one is configured and
    reachable (app/integrations/wazuh.py, marked source="wazuh").

The response always states which sources contributed and what the Wazuh
integration's actual status is, so the console can say "Wazuh not
configured" or "Wazuh unreachable" instead of silently showing a short
list that looks complete.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.dependencies import get_current_user, require_role
from app.integrations import wazuh
from app.models.agent import Agent, AgentStatus
from app.models.user import UserRole
from app.schemas.agent import AgentCreate, AgentOut

router = APIRouter(prefix="/api/agents", tags=["agents"])


@router.get("", response_model=list[AgentOut])
def list_agents(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    """Locally registered agents only.

    Kept as-is, returning a bare list of AgentOut, because it is the
    existing contract other code and tests already depend on. The merged
    local+Wazuh view lives at /api/agents/overview, which is additive
    rather than a breaking change to this endpoint.
    """
    return db.query(Agent).order_by(Agent.hostname).all()


@router.get("/overview")
def agents_overview(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    local = db.query(Agent).order_by(Agent.hostname).all()
    local_items = [
        {
            "source": "local",
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
            "ip_address": agent.ip_address,
            "operating_system": agent.operating_system,
            "status": agent.status.value,
            "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
            "version": None,
        }
        for agent in local
    ]

    wazuh_items, wazuh_status = wazuh.list_agents()

    return {
        "total": len(local_items) + len(wazuh_items),
        "sources": {
            "local": len(local_items),
            "wazuh": len(wazuh_items),
        },
        "wazuh_integration": wazuh_status,
        "items": local_items + wazuh_items,
    }


@router.post("", response_model=AgentOut, status_code=201)
def register_agent(
    payload: AgentCreate,
    db: Session = Depends(get_db),
    _user=Depends(require_role(UserRole.ADMINISTRATOR)),
):
    agent = Agent(
        hostname=payload.hostname,
        operating_system=payload.operating_system,
        ip_address=payload.ip_address,
        status=AgentStatus.OFFLINE,  # becomes ONLINE once it sends its first log/heartbeat
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent
