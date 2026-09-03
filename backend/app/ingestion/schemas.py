"""
app/ingestion/schemas.py

Request/response contract for POST /api/logs. Accepts a flat set of
known fields rather than nesting raw input in a generic blob, so a
client can submit any of:
  - an already-normalized event (supply event_type directly -- Phase
    A.6, "do not unnecessarily transform it"),
  - a raw Linux log line (supply raw_log, the normalizer parses it),
  - a Windows-style event (supply event_id, optionally alongside
    already-known fields like source_ip/username).
At least one of raw_log / event_type / event_id must be present --
otherwise there is nothing for the normalizer to work with, which is
rejected as invalid input (Phase A.9).
"""
from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.models.log import Severity


def _validate_ip_format(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"'{value}' is not a valid IP address") from exc
    return value


class LogIngestRequest(BaseModel):
    timestamp: datetime | None = None
    hostname: str | None = Field(None, max_length=255)
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(None, ge=0, le=65535)
    destination_port: int | None = Field(None, ge=0, le=65535)
    username: str | None = Field(None, max_length=128)
    event_type: str | None = Field(None, max_length=64)
    severity: Severity | None = None
    source: str | None = Field(None, max_length=64)
    operating_system: str | None = Field(None, max_length=64)
    agent_id: str | None = None
    event_id: int | None = None
    raw_log: str | None = Field(None, max_length=10_000)
    metadata: dict[str, Any] | None = None

    @field_validator("source_ip")
    @classmethod
    def _check_source_ip(cls, value: str | None) -> str | None:
        return _validate_ip_format(value)

    @field_validator("destination_ip")
    @classmethod
    def _check_destination_ip(cls, value: str | None) -> str | None:
        return _validate_ip_format(value)

    @model_validator(mode="after")
    def _require_something_to_normalize(self) -> "LogIngestRequest":
        if not self.raw_log and not self.event_type and self.event_id is None:
            raise ValueError(
                "Provide at least one of: raw_log (to be parsed), "
                "event_type (already normalized), or event_id (Windows Event ID)"
            )
        return self


class LogIngestResponse(BaseModel):
    # int for the relational store (a real row id); str for an external
    # event store (OpenSearch _id / ClickHouse UUID). See app/storage.
    id: int | str | None
    status: str = "accepted"
    normalized: bool
    event_type: str
    # How many detection rules this single event caused to fire, and
    # which Alert rows they created. A log shipper can therefore tell
    # from the ingestion response alone whether it just delivered
    # something that mattered, without polling /api/alerts.
    alerts_generated: int
    alert_ids: list[int]
