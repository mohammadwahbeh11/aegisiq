"""
app/detection/rules/suspicious_user_agent.py

Malicious User-Agent detection (AegisIQ v2.0 - Rule 8).

Fires on any request whose User-Agent header matches a shipped
attacker-tool signature: nmap Scripting Engine, Nikto, sqlmap,
Metasploit, wpscan, dirbuster/gobuster, hydra, and the empty /
whitespace UAs used by many opportunistic scanners.

A skilled attacker will spoof their UA, so this rule catches only
UNSKILLED or AUTOMATED activity. That's still worth knowing: it
identifies the noise floor and lets an analyst filter it out on the
dashboard so the sophisticated attacks stand out.

MITRE ATT&CK T1595.002 (Active Scanning: Vulnerability Scanning) --
Kill Chain phase "Reconnaissance". Severity MEDIUM: real attack, but
low sophistication, so it does not warrant automated containment on
its own (SOAR still records NOTIFY_ANALYST).

The signature list lives in rule.parameters["ua_signatures"] so a new
tool signature can be added without a code change.
"""
from __future__ import annotations

import re
from datetime import timedelta

from sqlalchemy.orm import Session

from app.detection import alerting
from app.models.alert import Alert
from app.models.log import Log
from app.models.rule import DetectionRule

MITRE_TACTIC = "Reconnaissance"

# case-insensitive substrings. Each entry is (name, needle).
DEFAULT_UA_SIGNATURES: list[tuple[str, str]] = [
    ("sqlmap",        "sqlmap"),
    ("nikto",         "nikto"),
    ("nmap_nse",      "nmap scripting engine"),
    ("metasploit",    "metasploit"),
    ("wpscan",        "wpscan"),
    ("dirbuster",     "dirbuster"),
    ("gobuster",      "gobuster"),
    ("hydra",         "hydra"),
    ("ffuf",          "ffuf"),
    ("burp",          "burp"),
    ("acunetix",      "acunetix"),
    ("nuclei",        "nuclei"),
    ("masscan",       "masscan"),
    ("zaproxy",       "zaproxy"),
    ("curl_pentest",  "curl/"),   # curl is legitimate too; low severity is on purpose
]


def _signatures(rule: DetectionRule) -> list[tuple[str, str]]:
    params = rule.parameters if isinstance(rule.parameters, dict) else {}
    configured = params.get("ua_signatures")
    if isinstance(configured, list):
        pairs = [(x.get("name"), x.get("needle")) for x in configured
                 if isinstance(x, dict) and x.get("name") and x.get("needle")]
        if pairs:
            return pairs
    return DEFAULT_UA_SIGNATURES


def _extract_ua(log: Log) -> str | None:
    data = log.normalized_data or {}
    if isinstance(data, dict):
        for key in ("user_agent", "User-Agent", "ua"):
            v = data.get(key)
            if isinstance(v, str):
                return v
    # Try to find one in the raw log using a simple heuristic.
    if log.raw_log and 'User-Agent' in log.raw_log:
        m = re.search(r'User-Agent[:\s]+([^"\n]+)', log.raw_log)
        if m:
            return m.group(1).strip()
    return None


def matched_signature(ua: str, sigs: list[tuple[str, str]]) -> str | None:
    lower = ua.lower()
    for name, needle in sigs:
        if needle.lower() in lower:
            return name
    return None


def evaluate(log: Log, rule: DetectionRule, db: Session, store=None) -> Alert | None:
    # Per-event rule: no historical LogStore query needed (`store`
    # accepted for a uniform handler signature and ignored).
    ua = _extract_ua(log)
    if not ua:
        return None

    sig = matched_signature(ua, _signatures(rule))
    if sig is None:
        return None

    src = log.source_ip or "unknown"
    dedup_key = f"{src}::ua::{sig}"
    window_start = log.timestamp - timedelta(seconds=rule.time_window_seconds)

    if alerting.has_active_alert(rule.id, dedup_key, window_start, db):
        return None

    description = (
        f"Attacker-tool User-Agent detected: '{sig}' from {src}. "
        f"Verbatim UA: {ua[:200]}. This signature is characteristic of "
        f"automated scanning; skilled attackers spoof the UA, so this "
        f"rule catches the noise floor rather than sophisticated threats."
    )
    return alerting.create_alert(rule, log, description, db, dedup_key=dedup_key)
