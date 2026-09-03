"""
app/detection/rules/credential_stuffing.py

Credential stuffing detection (AegisIQ v2.0 - Rule 7).

Distinct from brute_force in one important way: brute_force counts N
failed attempts against the SAME username; credential stuffing counts
N failed attempts against DISTINCT usernames from the same source IP.
The two attacks look nothing alike from the defender's side:

  brute_force:      attacker knows the username, guesses passwords
                    -> one target account, many passwords
  credential_stuff: attacker has a leaked (user, password) dump from
                    another site and tries each pair against yours
                    -> many target accounts, one password per attempt

A brute-force rule tuned to catch credential stuffing (say, threshold
50 across 60 s) would generate huge false-positive rates during a
routine password-reset outage; a credential-stuffing rule with
DISTINCT username counting stays quiet during those but lights up the
moment somebody starts pushing a leak dump.

MITRE ATT&CK T1110.004 (Brute Force: Credential Stuffing).
Kill Chain phase "Credential Access". Severity CRITICAL because a
positive detection means the attacker has an external data source
(a leak) about your users — a category of threat the analyst wants
to know about before triage on brute-force alerts.

Dedup key = source_ip.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.detection import alerting
from app.ingestion.normalizer import AUTH_FAILURE
from app.models.alert import Alert
from app.models.log import Log
from app.models.rule import DetectionRule

MITRE_TACTIC = "Credential Access"


def evaluate(log: Log, rule: DetectionRule, db: Session, store=None) -> Alert | None:
    if log.event_type != AUTH_FAILURE or not log.source_ip:
        return None

    if store is None:
        from app.storage import get_log_store
        store = get_log_store(db)

    window_start = log.timestamp - timedelta(seconds=rule.time_window_seconds)

    # v2.4: distinct-username count via the pluggable LogStore.
    distinct_users = store.count_distinct_usernames(
        AUTH_FAILURE, log.source_ip, window_start, log.timestamp
    )

    if distinct_users < rule.threshold:
        return None

    if alerting.has_active_alert(rule.id, log.source_ip, window_start, db):
        return None

    description = (
        f"Credential-stuffing attack detected from {log.source_ip}: "
        f"failed logins across {distinct_users} distinct usernames within "
        f"{rule.time_window_seconds} seconds. This is not a brute-force "
        f"against one account; the attacker is trying a list of "
        f"(username, password) pairs -- most likely from a leaked dump."
    )
    return alerting.create_alert(rule, log, description, db)
