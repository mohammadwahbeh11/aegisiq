"""
app/detection/rules/port_scan.py

Port scan detection (Phase B2 -- project objective O3 / Rule 2).
Condition, read from the DetectionRule row rather than hardcoded:

    >= rule.threshold DISTINCT destination ports
    from the same source_ip
    within the previous rule.time_window_seconds
    (a rolling window ending at the triggering log's own timestamp,
    inclusive at both ends -- same convention as brute_force, see
    app/detection/rules/brute_force.py's module docstring)

Only evaluates events already normalized to `port_access` (Phase A's
existing event type for connection-attempt events -- see
app/ingestion/normalizer.py). Failed/accepted-login events also carry a
destination_port (e.g. SSH's port 22) but are a different event_type
and are intentionally NOT counted here -- mixing login attempts into
port-scan counting would conflate two different attack patterns the
project treats as separate rules.

Counts DISTINCT ports via `SELECT COUNT(DISTINCT destination_port)`,
not a row count -- repeated connections to the same port must not
inflate the count (Step 7). Counted with a database query, not
in-memory state, for the same reason as brute_force (Step 3/4).

MITRE ATT&CK technique T1046 (Network Service Scanning) belongs to the
tactic "Discovery" -- documented here for reference (see
MITRE_TACTIC), not a stored column, matching brute_force.py's pattern.
kill_chain_phase is a different framework, stored on the rule/alert:
"Reconnaissance" -- probing which ports/services are open is the
textbook Kill Chain Reconnaissance phase.

Deduplication and Alert-row creation are shared with every other rule
via app.detection.alerting (Step 11/18) -- this module does not
reimplement either.
"""
from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.detection import alerting
from app.ingestion.normalizer import PORT_ACCESS
from app.models.alert import Alert
from app.models.log import Log
from app.models.rule import DetectionRule

# T1046's MITRE ATT&CK tactic, for documentation/reference only -- not a
# database column. Do not confuse this with kill_chain_phase below.
MITRE_TACTIC = "Discovery"

_MIN_VALID_PORT = 0
_MAX_VALID_PORT = 65535


def evaluate(log: Log, rule: DetectionRule, db: Session, store=None) -> Alert | None:
    """Returns the newly created Alert, or None if the rule didn't fire
    (below threshold, missing/invalid port data, or suppressed by
    deduplication). v2.4: distinct-port count via the pluggable LogStore."""
    if log.event_type != PORT_ACCESS or not log.source_ip:
        return None

    # Defensive even though the ingestion schema (app/ingestion/schemas.py)
    # already validates port range at the API boundary (Step 9: "the
    # detector itself should remain defensive") -- a log row reaching
    # here with a missing or out-of-range port simply doesn't
    # contribute, rather than the engine crashing on bad data.
    if log.destination_port is None:
        return None
    if not (_MIN_VALID_PORT <= log.destination_port <= _MAX_VALID_PORT):
        return None

    if store is None:
        from app.storage import get_log_store
        store = get_log_store(db)

    window_start = log.timestamp - timedelta(seconds=rule.time_window_seconds)

    distinct_port_count = store.count_distinct_ports(
        log.source_ip, window_start, log.timestamp
    )

    if distinct_port_count < rule.threshold:
        return None

    if alerting.has_active_alert(rule.id, log.source_ip, window_start, db):
        return None

    description = (
        f"Possible network port scan detected from {log.source_ip}: "
        f"{distinct_port_count} distinct destination ports accessed within {rule.time_window_seconds} seconds."
    )
    return alerting.create_alert(rule, log, description, db)
