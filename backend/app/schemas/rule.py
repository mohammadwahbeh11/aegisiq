"""Wire shapes for detection rules (the Rules page).

Editing a rule here changes real detection behavior on the next ingested
event -- thresholds and windows are read from the database at evaluation
time, not baked into the rule modules (see app/detection/rules/*).
"""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.log import Severity


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    rule_type: str
    threshold: int
    time_window_seconds: int
    severity: Severity
    mitre_id: str | None = None
    kill_chain_phase: str | None = None
    parameters: dict[str, Any] | None = None
    enabled: bool
    created_at: datetime | None = None
    updated_at: datetime | None = None
    # False when this build has no handler for the rule_type, so the UI
    # can say "configured but not executable in this build" instead of
    # implying the rule is running. Filled in by the route.
    implemented: bool = True


class RuleUpdate(BaseModel):
    """Every field optional -- a PATCH may change only the toggle.

    threshold and time_window_seconds are bounded rather than free: a
    threshold of 0 would make a rule fire on literally every matching
    event including the first, and a window of 0 makes the rolling
    window degenerate. Both are user-facing mistakes worth rejecting at
    the API boundary instead of debugging later from alert noise."""

    threshold: int | None = Field(None, ge=1, le=100_000)
    time_window_seconds: int | None = Field(None, ge=1, le=86_400)
    severity: Severity | None = None
    enabled: bool | None = None
    parameters: dict[str, Any] | None = None
