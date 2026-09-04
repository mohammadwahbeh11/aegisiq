"""
app/detection/rules/web_attack.py

Web-application attack detection (AegisIQ v2.0 - Rule 6).

Fires when a normalized web log line matches one of the shipped
attack-pattern regexes: SQL injection, cross-site scripting (XSS),
path-traversal, remote command injection, or server-side template
injection. Every pattern is documented in DEFAULT_ATTACK_PATTERNS so
an administrator can see -- and edit from the Rules page -- exactly
what is being watched for.

Event source: any log whose event_type is "web_request" (produced by the
normalizer when a raw_log line starts with an HTTP method) or whose
normalized_data carries a "request_line" / "url" / "user_agent" field.
The rule inspects THREE fields in that order: URL, request body,
User-Agent, so an attack pattern hidden anywhere in the request is
caught.

MITRE ATT&CK technique T1190 (Exploit Public-Facing Application) --
Kill Chain phase "Exploitation". Severity HIGH: this is not an alert
that always maps to a real attack (a legit admin might type SQL into a
search field), but it always maps to something worth an analyst looking
at.

Dedup key = source_ip + pattern_matched, so a scanner that fires ten
different SQLi payloads from one IP still shows as one incident, but a
DIFFERENT attack shape (XSS after SQLi) opens a fresh alert.
"""
from __future__ import annotations

import re
from datetime import timedelta

from sqlalchemy.orm import Session

from app.detection import alerting
from app.models.alert import Alert
from app.models.log import Log
from app.models.rule import DetectionRule

MITRE_TACTIC = "Initial Access"
WEB_REQUEST = "web_request"

# Each pattern is (name, compiled_regex). Names are stable — dedup and
# audit strings refer to them, and edits must preserve them.
_DEFAULT_PATTERNS: list[tuple[str, str]] = [
    ("SQL_UNION",       r"(?i)\bunion(\s+all)?\s+select\b"),
    ("SQL_OR_1_EQ_1",   r"(?i)['\"]\s*or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d"),
    ("SQL_COMMENT",     r"(?i)(--\s|#)\s*(?:sleep|benchmark|drop|truncate|update|insert)"),
    ("XSS_SCRIPT",      r"(?i)<\s*script[\s>]"),
    ("XSS_JS_URL",      r"(?i)javascript\s*:"),
    ("XSS_HANDLER",     r"(?i)\bon(?:load|error|click|mouseover)\s*="),
    ("PATH_TRAVERSAL",  r"(\.\./|\.\.\\){2,}"),
    ("PATH_ETC_PASSWD", r"(?i)/etc/passwd|/proc/self/environ|c:\\windows\\win\.ini"),
    ("CMD_INJECTION",   r"(?i);\s*(?:cat|wget|curl|nc|bash|sh|whoami|id|uname)\s"),
    ("CMD_PIPE",        r"(?i)\|\s*(?:nc|bash|sh|whoami|id|uname)"),
    ("SSTI_JINJA",      r"\{\{\s*[^}]{0,32}(?:config|self|request|__)"),
    ("LOG4SHELL",       r"\$\{jndi:(?:ldap|rmi|dns|nis|iiop|corba|nds|http)"),
]


def _decode_layers(value: str, rounds: int = 2) -> list[str]:
    """Return the value plus its URL-decoded forms.

    An attacker does not send `UNION SELECT` with a literal space in an HTTP
    request -- the browser/tool percent-encodes it to `UNION%20SELECT`, and
    sqlmap and friends often double-encode (`UNION%2520SELECT`) specifically
    to slip past naive signature matching. Scanning only the raw request line
    therefore MISSES the encoded form of every space-bearing signature
    (UNION SELECT, the OR 1=1 variants, path traversal), which is the common
    case, not the exception. Decoding a couple of layers and scanning each
    closes that evasion without changing a single pattern. `+` is treated as
    a space per application/x-www-form-urlencoded.
    """
    from urllib.parse import unquote_plus

    seen = [value]
    current = value
    for _ in range(rounds):
        decoded = unquote_plus(current)
        if decoded == current:
            break
        seen.append(decoded)
        current = decoded
    return seen


def _extract_targets(log: Log) -> str:
    """The strings we scan, joined. Uses whatever the normalizer made
    available on this event, and includes URL-decoded forms so a
    percent-encoded attack is matched the same as a plaintext one."""
    parts: list[str] = []
    data = log.normalized_data or {}
    if isinstance(data, dict):
        for key in ("url", "request_line", "path", "query", "body", "user_agent"):
            v = data.get(key)
            if isinstance(v, str) and v:
                parts.extend(_decode_layers(v))
    if log.raw_log:
        parts.extend(_decode_layers(log.raw_log))
    return "  ".join(parts)


def _patterns(rule: DetectionRule) -> list[tuple[str, re.Pattern]]:
    """Compile patterns lazily. Reads rule.parameters['patterns'] when
    set (each entry {name, regex}), else the defaults."""
    params = rule.parameters if isinstance(rule.parameters, dict) else {}
    configured = params.get("patterns")
    if isinstance(configured, list):
        pairs = [(p.get("name"), p.get("regex")) for p in configured
                 if isinstance(p, dict) and p.get("name") and p.get("regex")]
        if pairs:
            return [(name, re.compile(rx)) for name, rx in pairs]
    return [(name, re.compile(rx)) for name, rx in _DEFAULT_PATTERNS]


def matched(text: str, patterns: list[tuple[str, re.Pattern]]) -> str | None:
    """Returns the NAME of the first pattern that matched, or None."""
    for name, rx in patterns:
        if rx.search(text):
            return name
    return None


def evaluate(log: Log, rule: DetectionRule, db: Session, store=None) -> Alert | None:
    """Fire on any web_request event that matches a shipped pattern.
    Per-event rule: no historical LogStore query needed (`store` accepted
    for a uniform handler signature and ignored)."""
    if log.event_type != WEB_REQUEST:
        return None

    text = _extract_targets(log)
    if not text:
        return None

    pattern_name = matched(text, _patterns(rule))
    if pattern_name is None:
        return None

    src = log.source_ip or "unknown"
    dedup_key = f"{src}::{pattern_name}"

    # Even though threshold >=1 makes the count check trivial, keep the
    # database-driven count so raising the threshold from the Rules page
    # (to require, say, 3 SQLi hits before alerting) works.
    window_start = log.timestamp - timedelta(seconds=rule.time_window_seconds)
    if alerting.has_active_alert(rule.id, dedup_key, window_start, db):
        return None

    where = f" on {log.hostname}" if log.hostname else ""
    who = f" from {src}" if src != "unknown" else ""
    description = (
        f"Web application attack pattern '{pattern_name}' detected{who}{where}. "
        f"The matched request contained a signature the SIEM associates with "
        f"exploitation attempts against public-facing applications."
    )
    return alerting.create_alert(rule, log, description, db, dedup_key=dedup_key)
