"""
app/detection/rules/login_after_failure.py

Successful login after repeated failures (Phase C -- project objective
O3 / Rule 3, "login_after_failure" in Table 1). Condition, read from the
DetectionRule row rather than hardcoded:

    a SUCCESSFUL authentication from a source_ip that produced
    >= rule.threshold FAILED authentication events
    within the previous rule.time_window_seconds
    (a rolling window ending at the successful login's own timestamp,
    inclusive at both ends -- same convention as every other rule, see
    app/detection/rules/brute_force.py's module docstring)

This is the rule that distinguishes a *failed* brute-force attempt from
a *successful* account compromise, which is why it is seeded CRITICAL
while brute_force is HIGH: brute_force says someone is knocking,
this rule says someone got in.

Relationship to brute_force (deliberate, not accidental overlap): both
rules count the same failed-login events, so a real credential-stuffing
attack that eventually succeeds raises TWO alerts -- one HIGH the moment
the guessing crosses the threshold, one CRITICAL the moment it works.
They are not deduplicated against each other because they are different
rules with different meanings for the analyst; dedup is per-rule by
design (see app/detection/alerting.py).

Note the window is measured from the SUCCESS backwards. An attacker who
fails 5 times, waits out the window, and then logs in successfully does
not trigger this rule -- by then the failures are no longer evidence
that this particular login was the product of guessing. The window is
the rule's own time_window_seconds (seeded at 300s), editable from the
Rules page.

MITRE ATT&CK technique T1078 (Valid Accounts) belongs to the tactic
"Defense Evasion / Persistence / Privilege Escalation / Initial Access"
-- documented here for reference (see MITRE_TACTIC), not a stored
column, matching the pattern in brute_force.py. kill_chain_phase is the
separate Cyber Kill Chain framework and is stored on the rule/alert:
"Exploitation" -- the moment the credential attack actually lands.
"""
from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.detection import alerting
from app.ingestion.normalizer import AUTH_FAILURE, AUTH_SUCCESS
from app.models.alert import Alert
from app.models.log import Log
from app.models.rule import DetectionRule

# T1078's primary MITRE ATT&CK tactic, for documentation/reference only
# -- not a database column. Do not confuse this with kill_chain_phase.
MITRE_TACTIC = "Initial Access"


def evaluate(log: Log, rule: DetectionRule, db: Session, store=None) -> Alert | None:
    """Returns the newly created Alert, or None if the rule didn't fire
    (not a successful login, too few preceding failures, or suppressed
    by deduplication). v2.4: failure count via the pluggable LogStore."""
    if log.event_type != AUTH_SUCCESS or not log.source_ip:
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

    account = log.username or "an unknown account"
    description = (
        f"Successful login for {account} from {log.source_ip} immediately after "
        f"{failure_count} failed authentication attempts in the preceding "
        f"{rule.time_window_seconds} seconds -- probable credential compromise."
    )
    return alerting.create_alert(rule, log, description, db, dedup_key=log.source_ip)
