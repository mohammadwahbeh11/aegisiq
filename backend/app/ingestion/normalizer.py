"""
app/ingestion/normalizer.py

Converts a validated log-ingestion payload into the canonical
NormalizedEvent used across the SIEM (project section 7 / build-spec
Phase A.3).

Deliberately takes a plain dict, not the Pydantic LogIngestRequest --
zero dependency on FastAPI/Pydantic/SQLAlchemy, only the standard
library. This is what lets the logic in this file be executed and
verified directly (see tests/test_ingestion_normalizer.py), independent
of whether the web framework is even installed. app/ingestion/service.py
is the only caller, and it's responsible for turning a validated
LogIngestRequest into the dict shape this module expects.

Precedence rule (Phase A.6 -- "if an event is already normalized, do
not unnecessarily transform it"):
  1. Any field the client explicitly supplied is trusted as-is.
  2. A Windows Event ID fills event_type/severity ONLY if the client
     didn't already supply an explicit event_type.
  3. If event_type is still missing and raw_log is present, the line is
     parsed as a Linux auth/system log to fill remaining gaps.
  4. Anything still missing gets a safe, honestly-labeled default
     (severity="low", event_type="unparsed") -- never invented.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

AUTH_FAILURE = "authentication_failure"
AUTH_SUCCESS = "authentication_success"
PRIVILEGE_RELATED = "privilege_related"
FILE_INTEGRITY_CHANGE = "file_integrity_change"
PORT_ACCESS = "port_access"
WEB_REQUEST = "web_request"          # v2.0 - HTTP access-log lines
UNPARSED = "unparsed"

# 4672 maps to "privilege_related", not "privilege_escalation": deciding
# something IS an escalation is a detection-engine judgment (Phase B),
# not something the normalization layer should assert on ingestion.
#
# v2.3: extended so a Windows Security Event export parses into a real
# event_type instead of falling through to "unparsed". The severity here
# is only a floor — the detection engine applies CONTEXT (a SYSTEM
# account doing 4672 is normal; a real user doing it is not) before it
# decides the finding severity.
_WINDOWS_EVENT_MAP: dict[int, tuple[str, str]] = {
    4624: (AUTH_SUCCESS, "low"),      # successful logon
    4625: (AUTH_FAILURE, "medium"),   # failed logon
    4634: (AUTH_SUCCESS, "low"),      # logoff (treated as a benign auth event)
    4648: (AUTH_SUCCESS, "low"),      # logon with explicit credentials
    4672: (PRIVILEGE_RELATED, "low"), # special privileges assigned
    4720: (PRIVILEGE_RELATED, "medium"),  # user account created
    4726: (PRIVILEGE_RELATED, "medium"),  # user account deleted
    4732: (PRIVILEGE_RELATED, "medium"),  # member added to security group
    4756: (PRIVILEGE_RELATED, "medium"),  # member added to universal group
    4740: (AUTH_FAILURE, "medium"),   # account locked out
    4776: (AUTH_FAILURE, "medium"),   # credential validation
    1102: (PRIVILEGE_RELATED, "high"),    # audit log cleared
    7045: (PRIVILEGE_RELATED, "medium"),  # service installed
}

# Windows built-in / service accounts. Privilege and logon activity by
# these is routine — the OS itself runs as them. Used by the detection
# engine to keep 4672/4624 for these from being called an attack.
WINDOWS_SERVICE_ACCOUNTS = {
    "system", "local service", "network service", "localsystem",
    "nt authority\\system", "nt authority", "-", "null sid",
}


@dataclass
class NormalizedEvent:
    timestamp: datetime
    event_type: str
    severity: str  # "low" | "medium" | "high" | "critical"
    source: str | None
    operating_system: str | None
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    username: str | None = None
    event_id: int | None = None
    raw_log: str | None = None
    normalized_data: dict[str, Any] = field(default_factory=dict)


def normalize(fields: dict[str, Any]) -> NormalizedEvent:
    """
    `fields` is expected to contain (all optional except at least one of
    raw_log/event_type/event_id, enforced by the schema layer):
    timestamp, hostname, source_ip, destination_ip, source_port,
    destination_port, username, event_type, severity, source,
    operating_system, event_id, raw_log, metadata.
    """
    extra: dict[str, Any] = dict(fields.get("metadata") or {})

    event_type = fields.get("event_type")
    severity = fields.get("severity")
    username = fields.get("username")
    source_ip = fields.get("source_ip")
    destination_port = fields.get("destination_port")

    event_id = fields.get("event_id")
    if event_type is None and event_id is not None and event_id in _WINDOWS_EVENT_MAP:
        mapped_type, mapped_severity = _WINDOWS_EVENT_MAP[event_id]
        event_type = mapped_type
        severity = severity or mapped_severity

    raw_log = fields.get("raw_log")

    # v2.3 — Windows Security Event export (Event Viewer CSV / evtx-to-text).
    # Recognised by an "Event ID" token in the row and parsed into a real
    # event_type + the fields that matter (account, logon type, source
    # address), so these rows stop showing up as 100% "unparsed".
    if event_type is None and raw_log and _looks_like_windows_event(raw_log):
        w = _parse_windows_event(raw_log)
        if w is not None:
            w_type, w_sev, w_user, w_ip, w_eid, w_extra = w
            event_type = w_type
            severity = severity or w_sev
            username = username or w_user
            source_ip = source_ip or w_ip
            event_id = event_id or w_eid
            extra = {**w_extra, **extra}

    if event_type is None and raw_log:
        parsed = _parse_linux_line(raw_log)
        if parsed is not None:
            p_event_type, p_severity, p_username, p_source_ip, p_extra = parsed
            event_type = p_event_type
            severity = severity or p_severity
            username = username or p_username
            source_ip = source_ip or p_source_ip
            if destination_port is None and "destination_port" in p_extra:
                destination_port = p_extra.pop("destination_port")
            # Client-supplied metadata wins over parser-derived extras.
            extra = {**p_extra, **extra}

    if event_type is None:
        event_type = UNPARSED
    if severity is None:
        severity = "low"

    if not raw_log:
        # No literal raw log was submitted (e.g. a fully pre-normalized
        # JSON event). Rather than store an empty string and lose the
        # submission entirely, the whole payload is preserved as JSON --
        # forensic investigation should never come up empty-handed
        # (Phase A.8 / Task 8).
        raw_log = json.dumps({k: v for k, v in fields.items() if v is not None}, default=str)

    # A parser-derived event time (e.g. the Windows "Date and Time" field)
    # takes effect only when the caller didn't supply one. Popped so it
    # doesn't linger as a private key in normalized_data.
    parsed_time = extra.pop("_event_time", None)

    return NormalizedEvent(
        timestamp=fields.get("timestamp") or parsed_time or datetime.now(timezone.utc),
        event_type=event_type,
        severity=severity,
        source=fields.get("source"),
        operating_system=fields.get("operating_system"),
        hostname=fields.get("hostname"),
        source_ip=source_ip,
        destination_ip=fields.get("destination_ip"),
        source_port=fields.get("source_port"),
        destination_port=destination_port,
        username=username,
        event_id=event_id,
        raw_log=raw_log,
        normalized_data=extra,
    )


def _looks_like_windows_event(raw_log: str) -> bool:
    """Cheap guard so we only run the (heavier) Windows parser on rows
    that actually are Windows events. Matches the 'Event ID' token that a
    Security Event export always carries, in either '=' (CSV row) or ':'
    (evtx-to-text) form."""
    return bool(re.search(r"Event\s*ID\s*[=:]\s*\d+", raw_log, re.IGNORECASE))


# The Account/Logon fields appear TWICE in some events (a "Subject" block
# and a target block). For a FAILED logon (4625) the meaningful account
# is the one under "Account For Which Logon Failed" / the target block,
# not the SYSTEM subject that reported it — so we prefer the LAST
# Account Name match, which is the target in every Windows template.
def _parse_windows_event(
    raw_log: str,
) -> tuple[str, str, str | None, str | None, int | None, dict[str, Any]] | None:
    """Parse a Windows Security Event export row.

    Returns (event_type, severity, username, source_ip, event_id, extra)
    where `extra` carries logon_type, account_domain, security_id and a
    flag telling the detection engine whether the account is a Windows
    service account (so it can judge context). Returns None if no Event
    ID is present.
    """
    m = re.search(r"Event\s*ID\s*[=:]\s*(\d+)", raw_log, re.IGNORECASE)
    if not m:
        return None
    try:
        event_id = int(m.group(1))
    except ValueError:
        return None

    event_type, severity = _WINDOWS_EVENT_MAP.get(event_id, (PRIVILEGE_RELATED, "low"))

    # Account name: prefer the last occurrence (the target account in
    # dual-block templates like 4625/4648). Tabs/spaces vary by export.
    accounts = re.findall(r"Account Name:\s*([^\r\n\t|]+)", raw_log)
    username = accounts[-1].strip() if accounts else None
    if username in ("", "-"):
        username = None

    # Logon type (2 = interactive, 3 = network, 5 = service, 10 = RDP…).
    logon_type = None
    lt = re.search(r"Logon Type:\s*(\d+)", raw_log)
    if lt:
        try:
            logon_type = int(lt.group(1))
        except ValueError:
            logon_type = None

    # Source network address, when the event carries one (network logons).
    source_ip = None
    sa = re.search(r"Source Network Address:\s*([0-9a-fA-F:.]+)", raw_log)
    if sa:
        candidate = sa.group(1).strip()
        if candidate not in ("-", "::1", "127.0.0.1", ""):
            source_ip = candidate

    domain = None
    dm = re.findall(r"Account Domain:\s*([^\r\n\t|]+)", raw_log)
    if dm:
        domain = dm[-1].strip()

    # Is the acting account a Windows service/built-in account? A machine
    # account ends in "$". These make privilege/logon activity routine.
    acct_l = (username or "").strip().lower()
    is_service_account = (
        acct_l in WINDOWS_SERVICE_ACCOUNTS
        or acct_l.endswith("$")
        or not username
    )

    extra: dict[str, Any] = {
        "platform": "windows",
        "windows_event_id": event_id,
        "is_service_account": is_service_account,
    }
    if logon_type is not None:
        extra["logon_type"] = logon_type
    if domain:
        extra["account_domain"] = domain

    # Best-effort event timestamp so the report timeline and first/last-seen
    # reflect when the events actually happened, not when the file was
    # analyzed. Failure is silent — normalize() falls back to now().
    ts = _parse_windows_datetime(raw_log)
    if ts is not None:
        extra["_event_time"] = ts

    return event_type, severity, username, source_ip, event_id, extra


def _parse_windows_datetime(raw_log: str) -> datetime | None:
    """Parse the 'Date and Time=…' field of a Windows event export.

    Handles day-first and month-first numeric dates and both Arabic
    (ص/م) and English (AM/PM) meridiems, plus 24-hour times. Returns a
    timezone-aware UTC datetime, or None if nothing parses — the caller
    then keeps the default (analysis time)."""
    m = re.search(r"Date and Time\s*[=:]\s*([0-9]{1,4}[/\-][0-9]{1,2}[/\-][0-9]{1,4}[^|\r\n]*)", raw_log)
    if not m:
        return None
    blob = m.group(1).strip()

    # Normalise Arabic meridiem markers to AM/PM.
    blob = blob.replace("ص", "AM").replace("م", "PM")
    # Split date and the rest.
    parts = blob.split()
    if not parts:
        return None
    date_part = parts[0]
    time_part = " ".join(parts[1:]) if len(parts) > 1 else ""

    sep = "/" if "/" in date_part else "-"
    nums = date_part.split(sep)
    if len(nums) != 3:
        return None
    try:
        a, b, c = (int(x) for x in nums)
    except ValueError:
        return None
    # Decide which field is the year (4-digit), then day-first vs month-first.
    if c >= 1000:      # DD/MM/YYYY or MM/DD/YYYY
        year = c
        if a > 12:     # a must be the day
            day, month = a, b
        elif b > 12:   # b must be the day
            month, day = a, b
        else:          # ambiguous — Windows exports are locale DD/MM most often
            day, month = a, b
    elif a >= 1000:    # YYYY/MM/DD
        year, month, day = a, b, c
    else:
        return None

    hour = minute = second = 0
    tm = re.search(r"(\d{1,2}):(\d{2})(?::(\d{2}))?", time_part)
    if tm:
        hour = int(tm.group(1))
        minute = int(tm.group(2))
        second = int(tm.group(3)) if tm.group(3) else 0
        up = time_part.upper()
        if "PM" in up and hour < 12:
            hour += 12
        elif "AM" in up and hour == 12:
            hour = 0
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None


def _parse_linux_line(
    raw_log: str,
) -> tuple[str, str, str | None, str | None, dict[str, Any]] | None:
    """Returns (event_type, severity, username, source_ip, extra), or
    None if raw_log doesn't match any recognized Linux pattern. The port
    in the "from <ip> port <n>" suffix is optional -- the project's own
    example ("Failed password for admin from 192.168.1.50") omits it."""

    m = re.search(
        r"Failed password for (?:invalid user )?(?P<username>\S+) "
        r"from (?P<source_ip>[\d.]+)(?: port (?P<port>\d+))?",
        raw_log,
    )
    if m:
        extra = {"destination_port": int(m.group("port"))} if m.group("port") else {}
        return AUTH_FAILURE, "medium", m.group("username"), m.group("source_ip"), extra

    m = re.search(
        r"Accepted password for (?P<username>\S+) from (?P<source_ip>[\d.]+)(?: port (?P<port>\d+))?",
        raw_log,
    )
    if m:
        extra = {"destination_port": int(m.group("port"))} if m.group("port") else {}
        return AUTH_SUCCESS, "low", m.group("username"), m.group("source_ip"), extra

    m = re.search(
        r"authentication failure;.*user=(?P<username>\S+).*rhost=(?P<source_ip>[\d.]+)",
        raw_log,
    )
    if m:
        return AUTH_FAILURE, "medium", m.group("username"), m.group("source_ip"), {}

    # PAM logs don't guarantee field order (rhost= often precedes user=),
    # so this is matched with two independent lookups rather than one
    # ordered regex.
    if "authentication failure" in raw_log:
        user_match = re.search(r"\buser=(?P<username>\S+)", raw_log)
        host_match = re.search(r"\brhost=(?P<source_ip>[\d.]+)", raw_log)
        if user_match or host_match:
            return (
                AUTH_FAILURE,
                "medium",
                user_match.group("username") if user_match else None,
                host_match.group("source_ip") if host_match else None,
                {},
            )

    m = re.search(r"sudo:\s*(?P<username>\S+)\s*:.*COMMAND=(?P<command>.+)", raw_log)
    if m:
        return PRIVILEGE_RELATED, "medium", m.group("username"), None, {"command": m.group("command").strip()}

    m = re.search(
        r"File integrity violation:\s*(?P<path>\S+)\s+modified by\s+(?P<username>\S+)",
        raw_log,
    )
    if m:
        return FILE_INTEGRITY_CHANGE, "high", m.group("username"), None, {"path": m.group("path")}

    m = re.search(r"Connection attempt from (?P<source_ip>[\d.]+) to port (?P<port>\d+)", raw_log)
    if m:
        return PORT_ACCESS, "low", None, m.group("source_ip"), {"destination_port": int(m.group("port"))}

    # v2.0 - HTTP access log (nginx / apache combined format), e.g.
    #   192.0.2.1 - - [21/Aug/2026:14:30:00 +0000] "GET /?id=1 UNION SELECT * HTTP/1.1" 200 213 "-" "sqlmap/1.7"
    #
    # The URL uses `.+?` (non-greedy) rather than `\S+` so attack payloads
    # with LITERAL spaces (unusual on legit traffic but common on lab
    # attack lines and on real logs where the attacker sent the URL
    # un-encoded) still parse. The trailing ` HTTP/x.y"` acts as the
    # anchor that stops the non-greedy match.
    m = re.search(
        r'(?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"'
        r'(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<url>.+?)\s+HTTP/[0-9.]+"'
        r'\s+(?P<status>\d+)\s+\S+(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?',
        raw_log,
    )
    if m:
        extra: dict[str, Any] = {
            "method": m.group("method"),
            "url": m.group("url"),
            "http_status": int(m.group("status")),
            "request_line": f"{m.group('method')} {m.group('url')}",
        }
        if m.group("ua"):
            extra["user_agent"] = m.group("ua")
        return WEB_REQUEST, "low", None, m.group("source_ip"), extra

    return None
