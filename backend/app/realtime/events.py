"""
app/realtime/events.py

The single place that turns a database row into the JSON shape the
console receives. Used by both the REST routes and the WebSocket
broadcast so a log or an alert looks identical to the frontend
regardless of which channel delivered it -- the frontend's live feed
appends broadcast items straight into the same list it filled from
/api/alerts, and that only works if the shapes match exactly.
"""
from __future__ import annotations

from app.models.alert import Alert
from app.models.log import Log
from app.schemas.alert import AlertOut
from app.schemas.log import LogOut


def serialize_alert(alert: Alert) -> dict:
    """Includes the rule's name/type, denormalized, so the alerts table
    can render a row without a follow-up request per alert."""
    payload = AlertOut.model_validate(alert).model_dump(mode="json")
    rule = alert.rule
    payload["rule_name"] = rule.name if rule else None
    payload["rule_type"] = rule.rule_type if rule else None
    return payload


def serialize_log(log: Log) -> dict:
    return LogOut.model_validate(log).model_dump(mode="json")
