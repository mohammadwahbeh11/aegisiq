"""
app/detection/rules/file_integrity.py

Critical file integrity monitoring (Phase C -- project objective O3 /
Rule 4, "file_integrity_change" in Table 1). Condition:

    >= rule.threshold modifications of the SAME watched critical file
    within the previous rule.time_window_seconds
    (rolling window ending at the triggering log's timestamp, inclusive
    at both ends -- same convention as every other rule)

Seeded threshold is 1, i.e. a single modification of /etc/passwd or
/etc/shadow is an alert on its own, which is what the project document
specifies. The count is still implemented properly rather than
hardcoded to "any single event", so raising the threshold from the
Rules page does what an administrator would expect.

WHICH files count as critical is read from rule.parameters
["critical_paths"] (see app/models/rule.py), falling back to
DEFAULT_CRITICAL_PATHS below when the rule row has no parameters -- so
the watched set is editable without a code change, and a rule row
created before this column existed still behaves sensibly.

A path matches if it equals a watched entry exactly, or sits underneath
a watched entry that names a directory (trailing "/"). Comparison is
case-insensitive on the Windows entries only in the sense that Windows
paths are normalized to backslashes; Linux paths are matched
case-sensitively, because on Linux "/etc/Passwd" genuinely is a
different file from "/etc/passwd" and treating them as equal would be
wrong, not lenient.

Deduplication is keyed on the PATH, not on the source IP: file
integrity events frequently carry no source IP at all (the normalizer's
"File integrity violation: <path> modified by <user>" pattern has no
address in it), so keying on source IP would collapse every watched
file into one "no IP" bucket and let a single alert about /etc/passwd
silently suppress the alert about /etc/shadow. See
app/detection/alerting.py.

MITRE ATT&CK technique T1098 (Account Manipulation) belongs to the
tactic "Persistence" -- reference only (see MITRE_TACTIC), not a stored
column. kill_chain_phase is stored on the rule/alert as "Installation":
tampering with the account database is how an attacker installs durable
access.
"""
from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.detection import alerting
from app.ingestion.normalizer import FILE_INTEGRITY_CHANGE
from app.models.alert import Alert
from app.models.log import Log
from app.models.rule import DetectionRule

# T1098's MITRE ATT&CK tactic, documentation/reference only.
MITRE_TACTIC = "Persistence"

# Used only when the rule row carries no parameters["critical_paths"].
# Entries ending in "/" (or "\\") are treated as directory prefixes;
# everything else must match the path exactly.
DEFAULT_CRITICAL_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d/",
    "/etc/ssh/sshd_config",
    "/root/.ssh/",
    r"C:\Windows\System32\config\SAM",
    r"C:\Windows\System32\drivers\etc\hosts",
]

_PATH_KEYS = ("path", "file_path", "file", "target_file")


def _extract_path(log: Log) -> str | None:
    """The normalizer stores the changed path in normalized_data["path"].
    The other key names are accepted because a client submitting an
    already-normalized event (permitted by app/ingestion/schemas.py) may
    reasonably use any of them; an unrecognized shape yields None and the
    rule simply does not fire, rather than the engine raising."""
    data = log.normalized_data or {}
    if not isinstance(data, dict):
        return None
    for key in _PATH_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _watched_paths(rule: DetectionRule) -> list[str]:
    params = rule.parameters if isinstance(rule.parameters, dict) else {}
    configured = params.get("critical_paths")
    if isinstance(configured, list):
        paths = [p for p in configured if isinstance(p, str) and p.strip()]
        if paths:
            return paths
    return DEFAULT_CRITICAL_PATHS


def is_critical_path(path: str, rule: DetectionRule) -> bool:
    normalized = path.replace("\\", "/")
    for watched in _watched_paths(rule):
        watched_normalized = watched.replace("\\", "/")
        if watched_normalized.endswith("/"):
            if normalized.startswith(watched_normalized):
                return True
        elif normalized == watched_normalized:
            return True
    return False


def evaluate(log: Log, rule: DetectionRule, db: Session, store=None) -> Alert | None:
    """Returns the newly created Alert, or None if the rule didn't fire
    (not a file-integrity event, path missing or not watched, below
    threshold, or suppressed by deduplication). v2.4: the per-path count
    is asked of the pluggable LogStore (each backend implements the
    normalized_data.path match in its own dialect)."""
    if log.event_type != FILE_INTEGRITY_CHANGE:
        return None

    path = _extract_path(log)
    if path is None or not is_critical_path(path, rule):
        return None

    if store is None:
        from app.storage import get_log_store
        store = get_log_store(db)

    window_start = log.timestamp - timedelta(seconds=rule.time_window_seconds)

    change_count = store.count_by_normalized_path(
        FILE_INTEGRITY_CHANGE, path, window_start, log.timestamp
    )

    if change_count < rule.threshold:
        return None

    if alerting.has_active_alert(rule.id, path, window_start, db):
        return None

    actor = log.username or "an unidentified user"
    where = f" on {log.hostname}" if log.hostname else ""
    if change_count > 1:
        description = (
            f"Critical system file {path} was modified {change_count} times within "
            f"{rule.time_window_seconds} seconds by {actor}{where}."
        )
    else:
        description = f"Critical system file {path} was modified by {actor}{where}."
    return alerting.create_alert(rule, log, description, db, dedup_key=path)
