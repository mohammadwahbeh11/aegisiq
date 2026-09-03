from datetime import datetime
from pydantic import BaseModel, ConfigDict

from app.models.agent import AgentStatus


class AgentCreate(BaseModel):
    hostname: str
    operating_system: str
    ip_address: str


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    agent_id: str
    hostname: str
    operating_system: str
    ip_address: str
    status: AgentStatus
    last_seen: datetime | None = None
    created_at: datetime
