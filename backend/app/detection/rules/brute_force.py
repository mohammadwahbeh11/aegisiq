"""
app/detection/rules/brute_force.py

Brute-force authentication detection (Phase B1 -- project objective O3 /
Rule 1). Condition, read from the DetectionRule row rather than
hardcoded (Step 9):

    >= rule.threshold failed authentication events
    from the same source_ip
    within the previous rule.time_window_seconds
    (a rolling window ending at the triggering log's own timestamp)

Window boundary: INCLUSIVE at both ends -- an event exactly
`time_window_seconds` before the triggering event still counts as
"within" the window (timestamp >= window_start, not >). See
tests/test_detection_brute_force.py::test_brute_force_inclusive_window_boundary
for the exact boundary case this produces a different result on. Every
other rule (starting with port_scan in Phase B2) uses this same
convention -- see app/detection/rules/port_scan.py.

MITRE ATT&CK technique T1110 (Brute Force) belongs to the tactic
"Credential Access" -- but a MITRE *tactic* is not a Cyber Kill Chain
*phase*; they're two different frameworks (objective O6 asks for both,
not one relabeled as the other). This project only stores mitre_id and
kill_chain_phase on the rule/alert (no separate mitre_tactic column),
so "Credential Access" is documented here as the technique's tactic for
reference, and kill_chain_phase is set independently to a real Kill
Chain phase name ("Actions on Objectives" -- the point at which the
attacker's repeated credential-guessing constitutes them acting on
their objective against this target).

Counted with a database query (Step 3: "use database timestamps/events
rather than keeping the entire detection state only in Python memory" --
so detection is correct even immediately after a backend restart, with
no in-memory counters to lose).

Deduplication and Alert-row creation are shared with every other rule
via app.detection.alerting (Phase B2 Step 11/18) -- this module no
longer implements its own copy of either.
"""
from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.detection import alerting
from app.ingestion.normalizer import AUTH_FAILURE
from app.models.alert import Alert
from app.models.log import Log
from app.models.rule import DetectionRule

# T1110's MITRE ATT&CK tactic, for documentation/reference only -- not a
# database column. Do not confuse this with kill_chain_phase below.
MITRE_TACTIC = "Credential Access"


def evaluate(log: Log, rule: DetectionRule, db: Session, store=None) -> Alert | None:
    """Returns the newly created Alert, or None if the rule didn't fire
    (below threshold, or suppressed by deduplication).

    v2.4: the historical count is asked of the pluggable LogStore
    (`store`) instead of a hardcoded SQLAlchemy query, so this rule works
    unchanged whether events live in SQLite, PostgreSQL, OpenSearch or
    ClickHouse. `store` defaults to the SQLAlchemy backend for callers
    that predate the parameter."""
    if log.event_type != AUTH_FAILURE or not log.source_ip:
        return None

    if store is None:
        from app.storage import get_log_store
        store = get_log_store(db)

    window_start = log.timestamp - timedelta(seconds=rule.time_window_seconds)

    failure_count = store.count_events(
        AUTH_FAILURE, log.source_ip, window_start, log.timestamp
    )

    if failure_count < rule.threshold:
        return None

    if alerting.has_active_alert(rule.id, log.source_ip, window_start, db):
        return None

    description = (
        f"Brute-force authentication attack detected from {log.source_ip}: "
        f"{failure_count} failed authentication attempts within {rule.time_window_seconds} seconds."
    )
    return alerting.create_alert(rule, log, description, db)
