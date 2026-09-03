"""Wire shapes for stored log events (the search/history view), shared
with the realtime broadcast so a log looks the same whether it arrived
over REST or over the WebSocket."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.log import Severity


class LogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    username: str | None = None
    event_type: str
    event_id: int | None = None
    severity: Severity
    source: str
    operating_system: str | None = None
    raw_log: str
    normalized_data: dict | None = None
    agent_id: int | None = None


class LogListResponse(BaseModel):
    total: int
    items: list[LogOut]
