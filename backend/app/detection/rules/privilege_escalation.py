"""
app/detection/rules/privilege_escalation.py

Privilege escalation detection (Phase C -- project objective O3 /
Rule 5, "privilege_escalation" in Table 1). Condition:

    >= rule.threshold privilege-related events
    from the same actor (username, else source IP)
    within the previous rule.time_window_seconds,
    at least one of which is SUSPICIOUS (the triggering event)
    (rolling window ending at the triggering log's timestamp, inclusive
    at both ends -- same convention as every other rule)

Seeded threshold is 1: one suspicious `sudo` invocation is an alert on
its own, as the project document specifies. The count is nevertheless
implemented properly so raising the threshold from the Rules page
behaves as an administrator would expect.

What makes an event SUSPICIOUS, and why this rule is not just "any sudo":
`sudo` runs constantly on a healthy server, so alerting on every
privilege_related event would produce an unusable alert queue and would
fail the project's own false-positive objective. This rule instead fires
on the privilege-related events characteristic of escalation rather than
routine administration:

  * the command spawns an interactive root shell (/bin/bash, /bin/sh,
    zsh, `su`) -- the classic post-exploitation escalation step rather
    than a scoped administrative action;
  * the command edits authentication or authorization state (passwd,
    useradd/usermod, visudo, chmod on /etc/shadow, ...);
  * a Windows logon was assigned special/administrative privileges
    (Security Event ID 4672), which the normalizer maps to
    privilege_related WITHOUT asserting it is an escalation -- deciding
    that is exactly this layer's job (see app/ingestion/normalizer.py).

The patterns are read from rule.parameters["suspicious_commands"],
falling back to DEFAULT_SUSPICIOUS_COMMANDS below, so the watched set is
tunable from the Rules page without a code change. Matching is
case-insensitive substring matching against the recorded command.

An event that is privilege_related but matches nothing suspicious is
deliberately NOT an alert -- it is still stored and searchable as a log,
which is the honest outcome: the system saw it and judged it routine.

Deduplication is keyed on the ACTOR (username, or source IP when no
username was parsed), not the source IP alone: sudo events carry a
username but usually no source address, so keying on source IP would
funnel every user on every host into one "no IP" bucket. See
app/detection/alerting.py.

MITRE ATT&CK technique T1548 (Abuse Elevation Control Mechanism)
belongs to the tactic "Privilege Escalation" -- reference only (see
MITRE_TACTIC), not a stored column. kill_chain_phase is the separate
Cyber Kill Chain framework, stored on the rule/alert as "Actions on
Objectives".
"""
from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.detection import alerting
from app.ingestion.normalizer import PRIVILEGE_RELATED
from app.models.alert import Alert
from app.models.log import Log
from app.models.rule import DetectionRule

# T1548's MITRE ATT&CK tactic, documentation/reference only.
MITRE_TACTIC = "Privilege Escalation"

# Used only when the rule row carries no parameters["suspicious_commands"].
DEFAULT_SUSPICIOUS_COMMANDS = [
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "/usr/bin/su",
    "passwd",
    "useradd",
    "usermod",
    "adduser",
    "visudo",
    "/etc/sudoers",
    "/etc/shadow",
    "chmod 777",
    "chown root",
    "setuid",
    "nc -e",
]

# Windows Security Event IDs that are themselves the suspicious signal,
# with no command string to match against.
_SUSPICIOUS_EVENT_IDS = {4672}

_COMMAND_KEYS = ("command", "cmd", "process", "command_line")


def _extract_command(log: Log) -> str | None:
    """The normalizer stores a sudo command in normalized_data["command"].
    The other key names are accepted because a client submitting an
    already-normalized event (permitted by app/ingestion/schemas.py) may
    reasonably use any of them; an unrecognized shape yields None and the
    rule simply does not fire, rather than the engine raising."""
    data = log.normalized_data or {}
    if not isinstance(data, dict):
        return None
    for key in _COMMAND_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _suspicious_patterns(rule: DetectionRule) -> list[str]:
    params = rule.parameters if isinstance(rule.parameters, dict) else {}
    configured = params.get("suspicious_commands")
    if isinstance(configured, list):
        patterns = [p for p in configured if isinstance(p, str) and p.strip()]
        if patterns:
            return patterns
    return DEFAULT_SUSPICIOUS_COMMANDS


def matched_pattern(log: Log, rule: DetectionRule) -> str | None:
    """The specific reason this event is considered suspicious, or None.
    Returned (rather than a bare bool) so the alert description can tell
    the analyst exactly what tripped the rule instead of just asserting
    that something did."""
    if log.event_id in _SUSPICIOUS_EVENT_IDS:
        return f"Windows Event ID {log.event_id} (special privileges assigned)"

    command = _extract_command(log)
    if command is None:
        return None

    lowered = command.lower()
    for pattern in _suspicious_patterns(rule):
        if pattern.strip().lower() in lowered:
            return pattern.strip()
    return None


def evaluate(log: Log, rule: DetectionRule, db: Session, store=None) -> Alert | None:
    """Returns the newly created Alert, or None if the rule didn't fire
    (not a privilege-related event, nothing suspicious about it, below
    threshold, or suppressed by deduplication). v2.4: the per-actor count
    is asked of the pluggable LogStore."""
    if log.event_type != PRIVILEGE_RELATED:
        return None

    pattern = matched_pattern(log, rule)
    if pattern is None:
        return None

    actor = log.username or log.source_ip
    if not actor:
        return None

    if store is None:
        from app.storage import get_log_store
        store = get_log_store(db)

    window_start = log.timestamp - timedelta(seconds=rule.time_window_seconds)

    # Counts privilege-related events from the same actor in the window.
    # Unlike the suspicion test above, this count is intentionally NOT
    # re-filtered by pattern: once an actor has done one clearly
    # suspicious thing, their surrounding privileged activity in the same
    # window is context for the same incident.
    event_count = store.count_events_by_actor(
        PRIVILEGE_RELATED, log.username, log.source_ip, window_start, log.timestamp
    )

    if event_count < rule.threshold:
        return None

    if alerting.has_active_alert(rule.id, actor, window_start, db):
        return None

    command = _extract_command(log)
    detail = f' Command: "{command}".' if command else ""
    where = f" on {log.hostname}" if log.hostname else ""
    description = (
        f"Possible privilege escalation by {actor}{where}: matched suspicious "
        f"pattern '{pattern}'.{detail}"
    )
    return alerting.create_alert(rule, log, description, db, dedup_key=actor)
