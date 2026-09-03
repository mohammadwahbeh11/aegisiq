"""
Wire shapes for alerts.

AlertOut is used by BOTH the REST endpoints and the realtime WebSocket
broadcast, so the console never has to handle two different shapes for
the same object depending on how it arrived.
"""
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.alert import AlertStatus
from app.models.log import Severity


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    severity: Severity
    status: AlertStatus
    source_ip: str | None = None
    destination_ip: str | None = None
    rule_id: int
    # Denormalized onto the response so the alerts table renders without
    # a second request per row; filled in by the route (see
    # app/api/routes/alerts.py) from the joined rule.
    rule_name: str | None = None
    rule_type: str | None = None
    mitre_id: str | None = None
    kill_chain_phase: str | None = None
    description: str
    log_id: int | None = None
    incident_id: int | None = None
    created_at: datetime | None = None


class AlertLogContext(BaseModel):
    """The log event that triggered an alert, for the investigation view.
    Includes raw_log verbatim: an analyst deciding whether something is a
    false positive needs the original line, not only our parse of it."""

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


class AlertStatusChange(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    previous_status: AlertStatus | None = None
    new_status: AlertStatus
    changed_by: str | None = None
    changed_at: datetime | None = None


class AlertDetail(AlertOut):
    """Everything the investigation page needs in one request."""

    rule_description: str | None = None
    rule_threshold: int | None = None
    rule_time_window_seconds: int | None = None
    triggering_log: AlertLogContext | None = None
    related_logs: list[AlertLogContext] = []
    status_history: list[AlertStatusChange] = []


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


class AlertListResponse(BaseModel):
    total: int
    items: list[AlertOut]
