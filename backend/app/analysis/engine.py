"""
app/analysis/engine.py -- run the detection engine over an uploaded
log file in memory.

Contract: given raw bytes (typically the contents of an uploaded file)
and a database session for reading configured rules, returns a
dict-shaped `raw_results` that report.py turns into a structured
Report + HTML export.

Design decisions:
  * IN-MEMORY ONLY. Parsed events are held in a list, never inserted
    into `logs`. Analyzing a customer's own historic logs must not
    pollute the SIEM's own operational data set.
  * Same normalizer + rule dispatcher as the live path. If the normal
    live ingestion catches a line, the analysis catches the same line
    -- no rule drift between the two paths.
  * Bounded input. MAX_LINES enforces a hard ceiling so an upload of
    a 5-GB apache log doesn't OOM the backend. The report notes when
    the ceiling was hit.
  * Multiple input formats. Plain text (one log line per row),
    JSON-lines (one JSON object per row), and CSV (raw_log column
    detected from the header).

v2.2 enrichment: alongside the rule findings, the engine now extracts
Indicators of Compromise (unique IPs, ports, users, hostnames, URLs),
an hourly event timeline, and up to five verbatim sample events per
finding — so the report renders detailed vulnerability context rather
than a naked verdict. Everything is derived from the same parsed
event stream; no extra passes.

Dedup is deliberately disabled in this offline path: the analyst
uploading a file wants to see EVERY matching event, not the live
deduplicated console view.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.detection.rules import (
    file_integrity, privilege_escalation, suspicious_user_agent, web_attack,
)
from app.ingestion.normalizer import normalize
from app.models.rule import DetectionRule

logger = logging.getLogger(__name__)

MAX_LINES = 100_000            # hard ceiling per upload
MAX_BYTES = 50 * 1024 * 1024   # 50 MB
_SAMPLE_LINES_PER_FINDING = 5  # verbatim raw_log excerpts per finding


# ─────────────────────────────────────────────────────────────────────
# Static enrichment: MITRE ATT&CK technique blurbs + CVE hints for the
# well-known web-attack patterns. Kept as data so a rule editor can
# override without a code change (rule.parameters["cve_hints"]).
# ─────────────────────────────────────────────────────────────────────
_MITRE_BLURBS: dict[str, str] = {
    "T1110":    "Brute Force — adversaries try many passwords for one account.",
    "T1110.004": "Brute Force: Credential Stuffing — reuses known-leaked pairs.",
    "T1046":    "Network Service Scanning — pre-attack reconnaissance of open ports.",
    "T1078":    "Valid Accounts — attacker logs in with legitimate credentials, often after guessing.",
    "T1098":    "Account Manipulation — persistence via /etc/passwd, /etc/shadow, sudoers.",
    "T1548":    "Abuse Elevation Control — sudo, setuid, or shell escapes to gain root.",
    "T1190":    "Exploit Public-Facing Application — SQLi, RCE, path traversal, deserialization.",
    "T1595.002": "Vulnerability Scanning — automated tools probing for known CVEs.",
}

_WEB_ATTACK_CVE_HINTS: dict[str, list[str]] = {
    "SQL_UNION":       ["OWASP A03:2021", "CWE-89"],
    "SQL_OR_1_EQ_1":   ["OWASP A03:2021", "CWE-89"],
    "SQL_COMMENT":     ["OWASP A03:2021", "CWE-89"],
    "XSS_SCRIPT":      ["OWASP A03:2021", "CWE-79"],
    "XSS_JS_URL":      ["OWASP A03:2021", "CWE-79"],
    "XSS_HANDLER":     ["OWASP A03:2021", "CWE-79"],
    "PATH_TRAVERSAL":  ["OWASP A01:2021", "CWE-22"],
    "PATH_ETC_PASSWD": ["OWASP A01:2021", "CWE-22"],
    "CMD_INJECTION":   ["OWASP A03:2021", "CWE-77"],
    "CMD_PIPE":        ["OWASP A03:2021", "CWE-77"],
    "SSTI_JINJA":      ["OWASP A03:2021", "CWE-1336"],
    "LOG4SHELL":       ["CVE-2021-44228", "CVE-2021-45046", "CWE-502"],
}


def _classify_batch(events: list[dict], rules: list[DetectionRule]) -> list[dict]:
    """Returns one 'finding' dict per (rule, dedup_key) that matched,
    with the count, verbatim sample lines, and enrichment.

    We do NOT reuse the live detection engine because it depends on
    live db-queries over the `logs` table, which the analysis path
    deliberately doesn't populate. Instead we replicate each rule's
    condition against the in-memory event stream — pure Python, no
    database, no dedup so the analyst sees everything.
    """
    findings: list[dict] = []
    if not rules:
        return findings

    def _samples(indexes: list[int]) -> list[str]:
        out: list[str] = []
        for i in indexes[:_SAMPLE_LINES_PER_FINDING]:
            raw = events[i].get("raw_log")
            if isinstance(raw, str) and raw.strip():
                out.append(raw.strip()[:500])
        return out

    def _timeline(indexes: list[int]) -> tuple[str | None, str | None]:
        ts = [events[i].get("timestamp") for i in indexes if events[i].get("timestamp")]
        return (ts[0] if ts else None, ts[-1] if ts else None)

    # Bucketed views for the rules that need them
    by_source_type: dict[tuple[str, str], list[int]] = defaultdict(list)
    for idx, ev in enumerate(events):
        by_source_type[(ev.get("source_ip") or "", ev.get("event_type") or "")].append(idx)

    def _make_finding(
        rule: DetectionRule, source: str, count: int, reason: str,
        indexes: list[int], extra: dict | None = None,
    ) -> dict:
        first_ts, last_ts = _timeline(indexes)
        f = {
            "rule": rule.name,
            "rule_type": rule.rule_type,
            "mitre": rule.mitre_id,
            "mitre_blurb": _MITRE_BLURBS.get(rule.mitre_id or "", ""),
            "kill_chain": rule.kill_chain_phase,
            "severity": rule.severity.value,
            "source": source,
            "count": count,
            "reason": reason,
            "first_seen": first_ts,
            "last_seen": last_ts,
            "sample_events": _samples(indexes),
            "sample_indexes": indexes[:_SAMPLE_LINES_PER_FINDING],
        }
        if extra:
            f.update(extra)
        return f

    for rule in rules:
        if not rule.enabled:
            continue
        rt = rule.rule_type

        if rt == "brute_force":
            for (src, et), idxs in by_source_type.items():
                if et != "authentication_failure" or not src:
                    continue
                if len(idxs) >= rule.threshold:
                    users = sorted({events[i].get("username") for i in idxs if events[i].get("username")})[:5]
                    findings.append(_make_finding(
                        rule, src, len(idxs),
                        f"{len(idxs)} failed authentication events from {src}",
                        idxs,
                        {"targeted_usernames": users},
                    ))

        elif rt == "port_scan":
            for (src, et), idxs in by_source_type.items():
                if et != "port_access" or not src:
                    continue
                distinct_ports = sorted({events[i].get("destination_port") for i in idxs
                                         if events[i].get("destination_port") is not None})
                if len(distinct_ports) >= rule.threshold:
                    findings.append(_make_finding(
                        rule, src, len(distinct_ports),
                        f"{len(distinct_ports)} distinct destination ports from {src}",
                        idxs,
                        {"scanned_ports": distinct_ports[:50]},
                    ))

        elif rt == "login_after_failure":
            for idx, ev in enumerate(events):
                if ev.get("event_type") != "authentication_success" or not ev.get("source_ip"):
                    continue
                src = ev["source_ip"]
                fail_idxs = [i for i, e in enumerate(events[:idx])
                             if e.get("event_type") == "authentication_failure" and e.get("source_ip") == src]
                if len(fail_idxs) >= rule.threshold:
                    findings.append(_make_finding(
                        rule, src, len(fail_idxs),
                        f"Successful login for {ev.get('username') or 'unknown'} from {src} "
                        f"immediately after {len(fail_idxs)} failed attempts",
                        [idx] + fail_idxs,
                        {"compromised_account": ev.get("username")},
                    ))

        elif rt == "credential_stuffing":
            by_ip: dict[str, list[int]] = defaultdict(list)
            by_ip_users: dict[str, set[str]] = defaultdict(set)
            for i, ev in enumerate(events):
                if ev.get("event_type") == "authentication_failure":
                    ip, u = ev.get("source_ip"), ev.get("username")
                    if ip and u:
                        by_ip[ip].append(i)
                        by_ip_users[ip].add(u)
            for src, idxs in by_ip.items():
                if len(by_ip_users[src]) >= rule.threshold:
                    findings.append(_make_finding(
                        rule, src, len(by_ip_users[src]),
                        f"Failed logins across {len(by_ip_users[src])} distinct usernames from {src}",
                        idxs,
                        {"targeted_usernames": sorted(by_ip_users[src])[:10]},
                    ))

        elif rt == "file_integrity":
            paths_seen: dict[str, list[int]] = defaultdict(list)
            for i, ev in enumerate(events):
                if ev.get("event_type") == "file_integrity_change":
                    p = (ev.get("normalized_data") or {}).get("path")
                    if p and file_integrity.is_critical_path(p, rule):
                        paths_seen[p].append(i)
            for p, idxs in paths_seen.items():
                if len(idxs) >= rule.threshold:
                    findings.append(_make_finding(
                        rule, p, len(idxs),
                        f"Critical file {p} modified {len(idxs)} time(s)",
                        idxs,
                    ))

        elif rt == "privilege_escalation":
            for i, ev in enumerate(events):
                if ev.get("event_type") != "privilege_related":
                    continue
                fake_log = type("L", (), {
                    "normalized_data": ev.get("normalized_data") or {},
                    "event_id": ev.get("event_id"),
                    "username": ev.get("username"),
                    "hostname": ev.get("hostname"),
                    "source_ip": ev.get("source_ip"),
                })()
                pattern = privilege_escalation.matched_pattern(fake_log, rule)
                if pattern:
                    findings.append(_make_finding(
                        rule,
                        ev.get("username") or ev.get("source_ip") or "unknown",
                        1,
                        f"Suspicious command pattern '{pattern}' by {ev.get('username') or 'unknown'}",
                        [i],
                        {"matched_pattern": pattern,
                         "command": (ev.get("normalized_data") or {}).get("command")},
                    ))

        elif rt == "web_attack":
            patterns = [(name, re.compile(rx)) for name, rx in web_attack._DEFAULT_PATTERNS]
            # Group hits by (src, pattern_name) so the analyst gets a
            # single line per attack shape per source, with sample count.
            groups: dict[tuple[str, str], list[int]] = defaultdict(list)
            for i, ev in enumerate(events):
                if ev.get("event_type") != "web_request":
                    continue
                data = ev.get("normalized_data") or {}
                text = " ".join(str(data.get(k, "")) for k in
                                ("url", "request_line", "path", "query", "body", "user_agent")) \
                       + " " + (ev.get("raw_log") or "")
                match = web_attack.matched(text, patterns)
                if match:
                    groups[(ev.get("source_ip") or "unknown", match)].append(i)
            for (src, pat), idxs in groups.items():
                findings.append(_make_finding(
                    rule, src, len(idxs),
                    f"Web attack pattern '{pat}' from {src} ({len(idxs)} request(s))",
                    idxs,
                    {"pattern": pat,
                     "cwe_owasp": _WEB_ATTACK_CVE_HINTS.get(pat, [])},
                ))

        elif rt == "suspicious_user_agent":
            sigs = suspicious_user_agent.DEFAULT_UA_SIGNATURES
            groups: dict[tuple[str, str], list[int]] = defaultdict(list)
            for i, ev in enumerate(events):
                data = ev.get("normalized_data") or {}
                ua = data.get("user_agent")
                if not ua:
                    continue
                sig = suspicious_user_agent.matched_signature(ua, sigs)
                if sig:
                    groups[(ev.get("source_ip") or "unknown", sig)].append(i)
            for (src, sig), idxs in groups.items():
                findings.append(_make_finding(
                    rule, src, len(idxs),
                    f"Attacker-tool UA '{sig}' from {src} ({len(idxs)} request(s))",
                    idxs,
                    {"ua_signature": sig},
                ))

    return findings


# ═══════════════════════════════════════════════════════════════════════
# BUILT-IN ANOMALY HEURISTICS — run WITHOUT requiring a DetectionRule row
# ═══════════════════════════════════════════════════════════════════════
#
# The 8 rules above are Linux/network oriented. Real customers upload
# WINDOWS logs, application logs, and structured event exports that never
# trigger any of them — yet still contain clear evidence of compromise
# (bulk HRESULT failures, Windows Update / servicing store corruption,
# repeated integrity errors, Windows Security event IDs indicating
# escalation). These heuristics detect that class of anomaly directly
# from the parsed content, without a rule row. They run every analysis
# and produce findings alongside the rule-based ones.
#
# Kept in a separate function so they can be extended (e.g. Windows
# Defender events, Sysmon signals) without touching _classify_batch.

# HRESULTs that shouldn't appear in bulk on a healthy Windows system.
_DANGEROUS_HRESULTS: dict[str, tuple[str, str]] = {
    # code (lowercase) -> (short_name, severity)
    "0x800f080d": ("CBS_E_MANIFEST_INVALID_ITEM", "high"),
    "0x800f0805": ("CBS_E_NOT_APPLICABLE",       "medium"),
    "0x80070005": ("E_ACCESSDENIED",             "high"),
    "0x8007052e": ("ERROR_LOGON_FAILURE",        "high"),
    "0x80070032": ("ERROR_NOT_SUPPORTED",        "medium"),
    "0x80004005": ("E_FAIL",                     "medium"),
    "0x80070001": ("ERROR_INVALID_FUNCTION",     "medium"),
    "0x800705aa": ("ERROR_NO_SYSTEM_RESOURCES",  "high"),
    "0x8009030d": ("SEC_E_UNKNOWN_CREDENTIALS",  "high"),
}

# Windows Security Event IDs and how to judge them.
#
# Each entry: (short_name, base_severity, description, mitre, kill_chain,
# context_sensitive). `context_sensitive=True` means the finding is only
# raised — or is downgraded to informational — depending on the acting
# account: a SYSTEM / service / machine account doing this is ROUTINE
# (the OS runs as those), so the event is expected and not, by itself, an
# incident. Only a REAL user account, or an abnormal volume, is worth an
# analyst's time. This is the fix for "4672 for SYSTEM flagged as HIGH".
_SECURITY_EVENT_IDS: dict[int, tuple[str, str, str, str, str, bool]] = {
    # id -> (name, severity, description, mitre, kill_chain, context_sensitive)
    4625:  ("Failed logon", "medium", "Failed logon attempt",
            "T1110", "Credential Access", False),
    4624:  ("Successful logon", "low", "Successful logon",
            "T1078", "Initial Access", True),
    4672:  ("Special privileges", "medium",
            "Special privileges assigned to a new logon",
            "T1078", "Privilege Escalation", True),
    4648:  ("Explicit-credential logon", "low",
            "A logon was attempted using explicit credentials",
            "T1078", "Lateral Movement", True),
    4720:  ("Account created", "high", "A user account was created",
            "T1136.001", "Persistence", False),
    4726:  ("Account deleted", "medium", "A user account was deleted",
            "T1531", "Impact", False),
    4732:  ("Added to security group", "high",
            "Member added to a security-enabled local group",
            "T1098", "Persistence", False),
    4756:  ("Added to universal group", "high",
            "Member added to a security-enabled universal group",
            "T1098", "Persistence", False),
    4740:  ("Account locked out", "medium", "A user account was locked out",
            "T1110", "Credential Access", False),
    4776:  ("Credential validation", "low",
            "Credential validation attempt",
            "T1110", "Credential Access", False),
    1102:  ("Audit log cleared", "critical", "The security audit log was cleared",
            "T1070.001", "Defense Evasion", False),
    1116:  ("Defender: malware", "critical", "Windows Defender detected malware",
            "T1059", "Execution", False),
    1117:  ("Defender: action", "critical", "Windows Defender acted on malware",
            "T1059", "Execution", False),
    7045:  ("Service installed", "high", "A service was installed on the system",
            "T1543.003", "Persistence", False),
}

# Anomaly thresholds — kept conservative so a healthy log stays clean.
_FAILURE_RATE_HIGH = 0.10      # >10% failure lines = suspicious
_FAILURE_RATE_CRITICAL = 0.25  # >25% failure lines = critical
_MIN_EVENTS_FOR_RATE = 100     # don't flag tiny logs on rate alone


def _fake_severity(value: str):
    """Duck-typed severity for _make_finding when we synthesise a finding
    without a real DetectionRule row."""
    class S:
        pass
    s = S()
    s.value = value
    return s


def _fake_rule(rule_type: str, name: str, mitre: str, kill_chain: str, severity: str):
    class R:
        pass
    r = R()
    r.name = name
    r.rule_type = rule_type
    r.mitre_id = mitre
    r.kill_chain_phase = kill_chain
    r.severity = _fake_severity(severity)
    return r


_FAILURE_MARKERS_RE = re.compile(
    r"\b(failed|failure|error|E_FAIL|HRESULT\s*=\s*0x[89a-f])",
    re.IGNORECASE,
)


def _detect_windows_anomalies(events: list[dict]) -> list[dict]:
    """Heuristic findings that don't need a DetectionRule row.

    Currently detects:
      * Bulk failure-marker rate (any log format): >10% high, >25% critical
      * Dangerous HRESULT codes in Windows logs
      * Windows Security Event IDs that indicate compromise
      * Windows CBS / servicing-store integrity anomalies
    """
    findings: list[dict] = []
    if not events:
        return findings

    total = len(events)

    def _samples(indexes: list[int]) -> list[str]:
        out: list[str] = []
        for i in indexes[:_SAMPLE_LINES_PER_FINDING]:
            raw = events[i].get("raw_log")
            if isinstance(raw, str) and raw.strip():
                out.append(raw.strip()[:500])
        return out

    def _timeline(indexes: list[int]) -> tuple[str | None, str | None]:
        ts = [events[i].get("timestamp") for i in indexes if events[i].get("timestamp")]
        return (ts[0] if ts else None, ts[-1] if ts else None)

    def _make(rule, source: str, count: int, reason: str, idxs: list[int], extra: dict | None = None) -> dict:
        first_ts, last_ts = _timeline(idxs)
        out = {
            "rule": rule.name,
            "rule_type": rule.rule_type,
            "mitre": rule.mitre_id,
            "mitre_blurb": _MITRE_BLURBS.get(rule.mitre_id or "", ""),
            "kill_chain": rule.kill_chain_phase,
            "severity": rule.severity.value,
            "source": source,
            "count": count,
            "reason": reason,
            "first_seen": first_ts,
            "last_seen": last_ts,
            "sample_events": _samples(idxs),
            "sample_indexes": idxs[:_SAMPLE_LINES_PER_FINDING],
        }
        if extra:
            out.update(extra)
        return out

    # ── 1. HRESULT dangerous-code scan ────────────────────────────────
    hresult_hits: dict[str, list[int]] = defaultdict(list)
    hresult_re = re.compile(r"HRESULT\s*=\s*(0x[0-9a-fA-F]+)")
    for i, ev in enumerate(events):
        raw = ev.get("raw_log") or ""
        for m in hresult_re.finditer(raw):
            code = m.group(1).lower()
            if code in _DANGEROUS_HRESULTS:
                hresult_hits[code].append(i)

    for code, idxs in hresult_hits.items():
        name, severity = _DANGEROUS_HRESULTS[code]
        # Bulk of the same failure code is more suspicious than one-off.
        if len(idxs) >= 50 and severity != "critical":
            severity = "critical"
        rule = _fake_rule(
            "windows_hresult_anomaly",
            f"Windows HRESULT anomaly · {name}",
            "T1562",  # Impair Defenses — corrupted servicing store is impair-defenses adjacent
            "Defense Evasion",
            severity,
        )
        findings.append(_make(
            rule, code, len(idxs),
            f"Windows returned {name} ({code}) {len(idxs)} time(s) — a bulk of this "
            f"error indicates a corrupted or tampered servicing / security state.",
            idxs,
            {"hresult_code": code, "hresult_name": name},
        ))

    # ── 2. Windows Security Event ID scan (CONTEXT-AWARE) ─────────────
    # Group each event ID by whether the acting account is a Windows
    # service/built-in account or a real user, so we can judge context:
    # 4672/4624 by SYSTEM is routine; by a real user it's worth a look.
    def _is_service(ev: dict) -> bool:
        data = ev.get("normalized_data") or {}
        if isinstance(data, dict) and "is_service_account" in data:
            return bool(data["is_service_account"])
        # Fallback for events that weren't structured: treat unknown as
        # service (conservative — avoids crying wolf on machine noise).
        return True

    event_id_hits: dict[tuple[int, bool], list[int]] = defaultdict(list)
    for i, ev in enumerate(events):
        eid = ev.get("event_id")
        if eid is None:
            raw = ev.get("raw_log") or ""
            m = re.search(r"\bEvent\s*ID\s*[:=]?\s*(\d{3,5})\b", raw, re.IGNORECASE)
            if m:
                try:
                    eid = int(m.group(1))
                except ValueError:
                    eid = None
        if eid is not None and eid in _SECURITY_EVENT_IDS:
            event_id_hits[(eid, _is_service(ev))].append(i)

    for (eid, is_service), idxs in event_id_hits.items():
        name, base_sev, desc, mitre, kill_chain, ctx_sensitive = _SECURITY_EVENT_IDS[eid]

        # Context downgrade: a context-sensitive event by a service/built-in
        # account is EXPECTED operating-system behaviour. Report it as
        # informational context (low), never as a HIGH "attack".
        severity = base_sev
        account_note = ""
        if ctx_sensitive and is_service:
            severity = "low"
            account_note = (
                " Actor is a Windows service / built-in / machine account "
                "(SYSTEM, LOCAL SERVICE, or a computer account) — this is "
                "routine OS activity, shown for context, not an attack on its own."
            )
        elif ctx_sensitive and not is_service:
            # A real user account doing this is what actually matters.
            severity = "high" if eid == 4672 else base_sev
            account_note = (
                " Actor is a REAL user account (not a service account) — "
                "worth correlating with surrounding logon activity."
            )

        # Bulk of failed logons is more interesting than a couple.
        if eid == 4625 and len(idxs) >= 20:
            severity = "high"

        actor_label = "service/built-in account" if is_service else "real user account"
        rule = _fake_rule(
            "windows_security_event",
            f"Windows Security Event {eid} · {name}"
            + (" (service account — informational)" if (ctx_sensitive and is_service) else ""),
            mitre, kill_chain, severity,
        )
        findings.append(_make(
            rule, f"EventID {eid} ({actor_label})", len(idxs),
            f"{desc} ({name}) — {len(idxs)} event(s).{account_note}",
            idxs,
            {"event_id": eid, "event_name": name,
             "actor_is_service_account": is_service},
        ))

    # ── 3. Bulk failure-marker rate (any log format) ──────────────────
    if total >= _MIN_EVENTS_FOR_RATE:
        fail_idxs: list[int] = [
            i for i, ev in enumerate(events)
            if _FAILURE_MARKERS_RE.search(ev.get("raw_log") or "")
        ]
        rate = len(fail_idxs) / total if total else 0.0
        if rate >= _FAILURE_RATE_CRITICAL:
            rule = _fake_rule(
                "log_failure_burst",
                "Bulk failure / error events",
                "T1499",  # Endpoint Denial of Service — proxy for system stress
                "Impact",
                "critical",
            )
            findings.append(_make(
                rule, f"{rate*100:.1f}% of events", len(fail_idxs),
                f"{len(fail_idxs):,} failure / error markers across {total:,} events "
                f"({rate*100:.1f}%). A healthy system rarely produces failures at this "
                f"rate — investigate whether the host is under attack, running degraded, "
                f"or has been tampered with.",
                fail_idxs,
                {"failure_rate_pct": round(rate * 100, 1)},
            ))
        elif rate >= _FAILURE_RATE_HIGH:
            rule = _fake_rule(
                "log_failure_burst",
                "Elevated failure / error rate",
                "T1499",
                "Impact",
                "high",
            )
            findings.append(_make(
                rule, f"{rate*100:.1f}% of events", len(fail_idxs),
                f"{len(fail_idxs):,} failure / error markers across {total:,} events "
                f"({rate*100:.1f}%). This is above the noise floor for a healthy system.",
                fail_idxs,
                {"failure_rate_pct": round(rate * 100, 1)},
            ))

    # ── 4. Windows CBS / servicing-store integrity anomaly ────────────
    cbs_re = re.compile(r"\bCBS_E_(?:MANIFEST_INVALID_ITEM|MANIFEST_MISSING|INTEGRITY|CORRUPT)")
    cbs_idxs = [i for i, ev in enumerate(events) if cbs_re.search(ev.get("raw_log") or "")]
    if len(cbs_idxs) >= 20:
        rule = _fake_rule(
            "windows_servicing_integrity",
            "Windows servicing-store integrity anomaly",
            "T1553",  # Subvert Trust Controls
            "Defense Evasion",
            "high" if len(cbs_idxs) < 100 else "critical",
        )
        findings.append(_make(
            rule, "CBS / servicing store", len(cbs_idxs),
            f"{len(cbs_idxs):,} CBS manifest / integrity errors detected. Repeated "
            f"CBS_E_MANIFEST_INVALID_ITEM at this volume points to a damaged Windows "
            f"Update / servicing state — possible tampering, disk corruption, or a "
            f"rootkit interfering with the trust store. Run SFC /scannow and DISM "
            f"/RestoreHealth; verify code-signing on servicing binaries.",
            cbs_idxs,
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════
# THREAT SIGNATURE CATALOG — 120+ patterns across every log family
# ═══════════════════════════════════════════════════════════════════════
#
# Each signature is (name, regex, mitre_id, kill_chain, severity, description).
# The scanner runs each pattern against every event's raw_log +
# normalized_data (URL, command, UA, request_line). Matches are grouped
# by (signature_name, source_ip-or-hostname-or-username) so a scanner
# firing 500 identical XSS payloads shows as ONE finding with count=500
# and 5 sample events attached.
#
# Design principles:
#   * Every pattern maps to a MITRE ATT&CK technique and Kill Chain phase.
#   * Severity conservative — a legit admin can trip a signature (curl,
#     PowerShell base64), so LOW/MEDIUM by default; only clear-attack
#     patterns are HIGH/CRITICAL.
#   * Ordered by attack category so the report groups naturally.
#   * `re.IGNORECASE` is applied at compile time via inline (?i) so a
#     future editor can override the flag per pattern.
#   * Patterns anchored on distinctive tokens to keep false-positive
#     rate low. Any signature that fires more than once in a real
#     production log is either a real attack, an operational habit
#     worth documenting, or a signature that needs to be tuned.

_THREAT_SIGNATURES: list[tuple[str, str, str, str, str, str]] = [
    # ─── Web application attacks (extends web_attack rule with more coverage)
    ("SQLI_TIME_BLIND",
     r"(?i)(?:sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+|waitfor\s+delay|pg_sleep)",
     "T1190", "Exploitation", "high",
     "Time-based blind SQL injection payload (SLEEP/BENCHMARK/WAITFOR)."),
    ("SQLI_BOOLEAN",
     r"(?i)['\"]\s*(?:or|and)\s+['\"]?\d+['\"]?\s*(?:=|<|>|<>)\s*['\"]?\d",
     "T1190", "Exploitation", "high",
     "Boolean-based SQL injection ('1=1', 'a'='a', etc.)."),
    ("SQLI_STACKED",
     r"(?i);\s*(?:drop|truncate|delete|insert|update)\s+(?:table|from|into)\b",
     "T1190", "Exploitation", "critical",
     "Stacked SQL query injecting DDL/DML operations."),
    ("XXE_ATTACK",
     r"(?i)<!ENTITY\s+\w+\s+SYSTEM\s+['\"](?:file|http|ftp|expect|php|jar):",
     "T1190", "Exploitation", "high",
     "XML External Entity (XXE) payload attempting to read files or SSRF."),
    ("SSRF_LOCAL",
     r"(?i)(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|metadata\.google|metadata\.azure)",
     "T1190", "Exploitation", "medium",
     "Server-Side Request Forgery target — cloud metadata or localhost pivot."),
    ("SSTI_JINJA_2",
     r"\{\{\s*(?:config|request|application|url_for|self|__class__|__globals__|__builtins__|import_module)",
     "T1190", "Exploitation", "high",
     "Server-Side Template Injection targeting Jinja/Flask/Twig internals."),
    ("NOSQL_INJECTION",
     r"(?i)\$(?:where|ne|gt|lt|regex|elemMatch|nin)\s*[:=]",
     "T1190", "Exploitation", "high",
     "NoSQL (MongoDB) injection operator abuse."),
    ("LDAP_INJECTION",
     r"(?i)\(\s*(?:\|\s*)?\(?\s*(?:cn|uid|sAMAccountName|memberOf)\s*=\s*\*[^)]*\)",
     "T1190", "Exploitation", "high",
     "LDAP injection payload — wildcard on identity attributes."),
    ("XPATH_INJECTION",
     r"(?i)['\"]\s*or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?\s+or\s+['\"]?\w+['\"]?\s*=",
     "T1190", "Exploitation", "medium",
     "XPath injection — chained OR conditions."),
    ("PATH_TRAVERSAL_ENC",
     r"(?i)(?:%2e%2e[\\/]|%252e%252e|\.\.%2f|\.\.%5c)",
     "T1190", "Exploitation", "high",
     "URL-encoded path traversal (%2e%2e/, double-encoded)."),
    ("PHP_LFI",
     r"(?i)php://(?:filter|input|expect|memory)",
     "T1190", "Exploitation", "critical",
     "PHP local file inclusion via wrapper (php://filter, php://input)."),
    ("RFI_EXTERNAL",
     r"(?i)(?:include|require)(?:_once)?\s*\(\s*['\"]https?://",
     "T1190", "Exploitation", "critical",
     "Remote file inclusion — including code from a remote URL."),
    ("OGNL_INJECTION",
     r"(?i)\$\{\s*[@#]?(?:ognl\.|@java\.lang|Runtime\.getRuntime|ProcessBuilder)",
     "T1190", "Exploitation", "critical",
     "OGNL expression injection (Struts, Confluence CVE-2022-26134)."),
    ("SPEL_INJECTION",
     r"(?i)\$\{T\(java\.lang\.Runtime\)|T\(\s*java\.lang\.ProcessBuilder\s*\)",
     "T1190", "Exploitation", "critical",
     "Spring Expression Language injection (Spring4Shell CVE-2022-22965 style)."),
    ("PROTOTYPE_POLLUTION",
     r"(?i)(?:__proto__|constructor\.prototype)\s*[\[.]",
     "T1190", "Exploitation", "high",
     "JavaScript prototype pollution attempt."),
    ("HTTP_REQUEST_SMUGGLING",
     r"(?i)transfer-encoding\s*:\s*chunked.*content-length\s*:\s*\d+",
     "T1190", "Exploitation", "high",
     "HTTP request smuggling — conflicting Transfer-Encoding and Content-Length."),
    ("GRAPHQL_INTROSPECTION",
     r"(?i)__schema\s*\{\s*(?:queryType|types)",
     "T1595", "Reconnaissance", "medium",
     "GraphQL introspection query — enumerating the schema."),
    ("JWT_NONE_ALG",
     r'(?i)"alg"\s*:\s*"(?:none|None|NONE)"',
     "T1550.001", "Defense Evasion", "critical",
     "JWT with 'none' algorithm — signature-bypass attempt."),

    # ─── Known-CVE indicators
    ("LOG4SHELL_JNDI",
     r"\$\{jndi:(?:ldap|rmi|dns|nis|iiop|corba|nds|http)",
     "T1190", "Exploitation", "critical",
     "Log4Shell (CVE-2021-44228 / 45046) JNDI lookup."),
    ("PROXYSHELL",
     r"(?i)/autodiscover/autodiscover\.json\?@[^&\s]*&Email=autodiscover/",
     "T1190", "Exploitation", "critical",
     "Exchange ProxyShell exploit path (CVE-2021-34473)."),
    ("PROXYLOGON",
     r"(?i)/ecp/[^\s]*/[^\s]*\.js\?[^\s]*x-anonresource",
     "T1190", "Exploitation", "critical",
     "Exchange ProxyLogon exploit path (CVE-2021-26855)."),
    ("PRINTNIGHTMARE",
     r"(?i)(?:AddPrinterDriverEx|Point\s+and\s+Print).*(?:UNIDRV|kernelmode)",
     "T1068", "Privilege Escalation", "critical",
     "PrintNightmare (CVE-2021-34527) exploitation attempt."),
    ("PETITPOTAM",
     r"(?i)EfsRpcOpenFileRaw|EfsRpcEncryptFileSrv",
     "T1187", "Credential Access", "critical",
     "PetitPotam NTLM-relay coercion (CVE-2021-36942)."),
    ("ZEROLOGON",
     r"(?i)NetrServerAuthenticate.*(?:zero|\\x00{8,})",
     "T1210", "Lateral Movement", "critical",
     "Zerologon (CVE-2020-1472) authentication bypass indicator."),
    ("HEARTBLEED",
     r"(?i)heartbeat.*(?:overrun|out of bounds)",
     "T1040", "Credential Access", "high",
     "Heartbleed (CVE-2014-0160) memory-disclosure indicator."),
    ("SHELLSHOCK",
     r"\(\s*\)\s*\{\s*:;\s*\}\s*;",
     "T1190", "Exploitation", "critical",
     "Shellshock (CVE-2014-6271) bash function-definition exploit."),
    ("SPRING4SHELL",
     r"(?i)class\.module\.classLoader\.resources\.context\.parent\.pipeline",
     "T1190", "Exploitation", "critical",
     "Spring4Shell (CVE-2022-22965) exploit indicator."),
    ("CITRIX_BLEED",
     r"(?i)/oauth/idp/\.well-known/openid-configuration.*(?:host:\s*[^\s]{2000,}|A{1000,})",
     "T1190", "Exploitation", "critical",
     "Citrix Bleed (CVE-2023-4966) session-token disclosure attempt."),
    ("MOVEIT_TRANSFER",
     r"(?i)/moveitisapi/moveitisapi\.dll|/api/v1/folders/[0-9]+/files",
     "T1190", "Exploitation", "high",
     "MOVEit Transfer suspicious path (CVE-2023-34362 was widely exploited)."),

    # ─── Reverse shells & post-exploitation payloads
    ("REVERSE_SHELL_BASH",
     r"(?i)bash\s+-i\s*>\s*&\s*/dev/tcp/[\d.]+/\d+\s+0>&1",
     "T1059.004", "Command and Control", "critical",
     "Bash reverse shell — /dev/tcp redirection."),
    ("REVERSE_SHELL_PYTHON",
     r"(?i)python[23]?\s+-c\s+['\"]import\s+socket.*subprocess.*(?:call|Popen)",
     "T1059.006", "Command and Control", "critical",
     "Python reverse shell one-liner."),
    ("REVERSE_SHELL_NC",
     r"(?i)\bnc(?:\.exe)?\s+(?:-[el]+|--exec)\s+(?:/bin/sh|/bin/bash|cmd(?:\.exe)?)",
     "T1059", "Command and Control", "critical",
     "netcat used as a shell backdoor (-e or --exec option)."),
    ("REVERSE_SHELL_PERL",
     r"(?i)perl\s+-e\s+['\"]use\s+Socket.*connect.*exec",
     "T1059", "Command and Control", "critical",
     "Perl reverse shell socket + exec."),
    ("REVERSE_SHELL_POWERSHELL",
     r"(?i)powershell.*(?:\.DownloadString|IEX|Invoke-Expression).*(?:net\.sockets|tcpclient)",
     "T1059.001", "Command and Control", "critical",
     "PowerShell reverse-shell — TcpClient + Invoke-Expression."),
    ("MSF_METERPRETER",
     r"(?i)(?:meterpreter|metasploit|msfvenom|windows/x64/shell_reverse_tcp)",
     "T1105", "Command and Control", "critical",
     "Metasploit / Meterpreter framework signature."),
    ("COBALTSTRIKE_BEACON",
     r"(?i)(?:cobaltstrike|beacon\.dll|malleable_c2|cobalt\s*strike|CS-Team-Server)",
     "T1071.001", "Command and Control", "critical",
     "Cobalt Strike beacon indicator."),
    ("SLIVER_C2",
     r"(?i)(?:sliverc2|BishopFox/sliver)",
     "T1071.001", "Command and Control", "critical",
     "Sliver C2 framework signature."),

    # ─── PowerShell abuse (Windows post-exploitation)
    ("PS_ENCODED_COMMAND",
     r"(?i)powershell(?:\.exe)?\s+[-/](?:e|enc|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{40,}",
     "T1059.001", "Execution", "high",
     "PowerShell with -EncodedCommand (base64 payload) — common obfuscation."),
    ("PS_DOWNLOADSTRING",
     r"(?i)(?:Net\.WebClient|IWR|Invoke-WebRequest).*(?:DownloadString|DownloadFile).*IEX",
     "T1059.001", "Command and Control", "critical",
     "PowerShell download-and-execute cradle (IEX + DownloadString)."),
    ("PS_BYPASS_EXECUTION",
     r"(?i)-(?:ExecutionPolicy|ep)\s+(?:Bypass|Unrestricted|RemoteSigned)\s+-(?:NoProfile|nop)",
     "T1562.001", "Defense Evasion", "high",
     "PowerShell execution-policy bypass — classic malware invocation."),
    ("PS_HIDDEN_WINDOW",
     r"(?i)-WindowStyle\s+Hidden|-w\s+hidden",
     "T1564", "Defense Evasion", "medium",
     "PowerShell run with hidden window — evading user visibility."),
    ("PS_AMSI_BYPASS",
     r"(?i)(?:System\.Management\.Automation\.AmsiUtils|amsiInitFailed|amsiScanBuffer)",
     "T1562.001", "Defense Evasion", "critical",
     "AMSI bypass technique — disabling Windows Defender scanning."),
    ("PS_INVOKE_REFLECTION",
     r"(?i)\[Reflection\.Assembly\]::Load\(",
     "T1620", "Defense Evasion", "high",
     "In-memory .NET assembly load via reflection — fileless execution."),
    ("PS_ADD_PERSISTENCE",
     r"(?i)New-ScheduledTask.*-Action.*powershell|schtasks\s+/create.*powershell",
     "T1053.005", "Persistence", "high",
     "Scheduled task creation running PowerShell — persistence."),

    # ─── LOLBAS / living-off-the-land binaries
    ("LOLBAS_CERTUTIL",
     r"(?i)certutil(?:\.exe)?\s+.*(?:-urlcache|-decode|-decodehex|-encode)\s",
     "T1105", "Command and Control", "high",
     "certutil misuse as download/encode tool — LOLBAS."),
    ("LOLBAS_MSHTA",
     r"(?i)mshta(?:\.exe)?\s+(?:https?://|javascript:|vbscript:)",
     "T1218.005", "Defense Evasion", "high",
     "mshta executing remote or scripted payload — LOLBAS."),
    ("LOLBAS_RUNDLL32",
     r"(?i)rundll32(?:\.exe)?\s+(?:javascript:|https?://|shell32\.dll,ShellExec_RunDLL)",
     "T1218.011", "Defense Evasion", "high",
     "rundll32 executing script or remote content — LOLBAS."),
    ("LOLBAS_REGSVR32",
     r"(?i)regsvr32(?:\.exe)?\s+.*(?:/i:https?://|/s\s+/n\s+/u)",
     "T1218.010", "Defense Evasion", "high",
     "regsvr32 loading remote scriptlet — Squiblydoo LOLBAS."),
    ("LOLBAS_WMIC_EXEC",
     r"(?i)wmic(?:\.exe)?\s+.*process\s+call\s+create",
     "T1047", "Execution", "high",
     "WMIC process spawn — remote/local execution channel."),
    ("LOLBAS_BITSADMIN",
     r"(?i)bitsadmin(?:\.exe)?\s+.*(?:/transfer|/create).*https?://",
     "T1197", "Defense Evasion", "high",
     "BITS admin download — LOLBAS covert transfer."),

    # ─── Credential dumping
    ("MIMIKATZ_CMD",
     r"(?i)(?:mimikatz|sekurlsa::(?:logonpasswords|pth)|lsadump::|kerberos::(?:tgt|golden|purge))",
     "T1003.001", "Credential Access", "critical",
     "Mimikatz command — LSASS credential dumping."),
    ("LSASS_DUMP",
     r"(?i)(?:procdump.*lsass|comsvcs\.dll,\s*MiniDump|out-minidump)",
     "T1003.001", "Credential Access", "critical",
     "LSASS memory dump — credential extraction."),
    ("SAM_HIVE_ACCESS",
     r"(?i)(?:reg\s+save\s+HKLM\\SAM|copy\s+.*SYSTEM32\\config\\SAM)",
     "T1003.002", "Credential Access", "critical",
     "SAM registry hive extraction — offline credential attack."),
    ("KERBEROASTING",
     r"(?i)(?:GetUserSPNs\.py|Rubeus\.exe.*kerberoast|Invoke-Kerberoast)",
     "T1558.003", "Credential Access", "critical",
     "Kerberoasting tooling — extracting SPN service tickets."),
    ("ASREPROAST",
     r"(?i)(?:GetNPUsers\.py|Rubeus\.exe.*asreproast)",
     "T1558.004", "Credential Access", "critical",
     "AS-REP roasting — accounts without pre-auth."),
    ("DCSYNC",
     r"(?i)lsadump::dcsync|dsreplicagetnc",
     "T1003.006", "Credential Access", "critical",
     "DCSync — replicating credentials from a domain controller."),
    ("GOLDEN_TICKET",
     r"(?i)kerberos::(?:golden|silver)\s+/user:",
     "T1558.001", "Credential Access", "critical",
     "Golden / Silver ticket forgery."),

    # ─── Ransomware indicators
    ("VSS_DELETE_SHADOWS",
     r"(?i)vssadmin(?:\.exe)?\s+delete\s+shadows",
     "T1490", "Impact", "critical",
     "Volume Shadow Copy deletion — pre-ransomware step."),
    ("WBADMIN_DELETE_BACKUP",
     r"(?i)wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup|backup)",
     "T1490", "Impact", "critical",
     "Windows backup catalog deletion — pre-ransomware step."),
    ("BCDEDIT_RECOVERY_OFF",
     r"(?i)bcdedit(?:\.exe)?\s+.*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)",
     "T1490", "Impact", "critical",
     "Boot configuration disabling recovery — ransomware signature."),
    ("WMIC_SHADOWCOPY_DELETE",
     r"(?i)wmic(?:\.exe)?\s+shadowcopy\s+delete",
     "T1490", "Impact", "critical",
     "WMIC deleting shadow copies — ransomware."),
    ("RANSOM_NOTE",
     r"(?i)(?:_readme\.txt|HOW_TO_DECRYPT|DECRYPT_INSTRUCTIONS|YOUR_FILES_ARE_ENCRYPTED)",
     "T1486", "Impact", "critical",
     "Ransom note filename detected — post-infection indicator."),

    # ─── Data exfiltration
    ("DNS_TUNNEL",
     r"(?i)\b[a-f0-9]{40,}\.(?:dns2tcp|dnscat|iodine)\.",
     "T1071.004", "Command and Control", "high",
     "DNS tunneling toolchain — data exfiltration."),
    ("BASE64_LARGE_BLOB",
     r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{200,}={0,2}(?![A-Za-z0-9+/=])",
     "T1132.001", "Command and Control", "medium",
     "Large inline base64 blob — likely obfuscated payload or exfil."),
    ("CLOUD_METADATA_ACCESS",
     r"169\.254\.169\.254/(?:latest|computeMetadata|metadata)",
     "T1552.005", "Credential Access", "critical",
     "Cloud instance-metadata endpoint access — IAM credential theft."),
    ("AWS_KEY_LEAK",
     r"\b(?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16}\b",
     "T1552.001", "Credential Access", "critical",
     "AWS access key ID pattern in log — likely credential leak."),
    ("GCP_KEY_LEAK",
     r'"type"\s*:\s*"service_account".*"private_key"',
     "T1552.001", "Credential Access", "critical",
     "GCP service-account JSON key in log — credential leak."),
    ("PRIVATE_KEY_BLOCK",
     r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----",
     "T1552.004", "Credential Access", "critical",
     "Private-key PEM block in log — credential leak."),

    # ─── Persistence
    ("CRONTAB_MODIFY",
     r"(?i)(?:crontab\s+-[el]\s+|/etc/cron\.(?:d|hourly|daily|weekly|monthly)/)",
     "T1053.003", "Persistence", "medium",
     "cron job modification — potential persistence."),
    ("SSH_AUTHORIZED_KEYS",
     r"(?i)\.ssh/authorized_keys",
     "T1098.004", "Persistence", "high",
     "Access to ~/.ssh/authorized_keys — potential backdoor key install."),
    ("SUDOERS_MODIFY",
     r"(?i)/etc/sudoers(?:\.d)?/",
     "T1548.003", "Privilege Escalation", "high",
     "Sudoers file access/modification — privilege change."),
    ("SYSTEMD_SERVICE_ADD",
     r"(?i)systemctl\s+enable\s+.*\.service|/etc/systemd/system/.*\.service",
     "T1543.002", "Persistence", "medium",
     "systemd unit installation — persistence."),
    ("REG_RUN_KEY",
     r"(?i)HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
     "T1547.001", "Persistence", "high",
     "Registry Run key modification — Windows persistence."),
    ("REG_SCHEDULED_TASK",
     r"(?i)HKLM\\Software\\Microsoft\\Windows\\NT\\CurrentVersion\\Schedule\\TaskCache",
     "T1053.005", "Persistence", "medium",
     "Scheduled Task registry cache access — persistence indicator."),

    # ─── Lateral movement
    ("PSEXEC_INDICATOR",
     r"(?i)(?:psexec(?:svc)?\.exe|\\\\[^\\]+\\ADMIN\$\\PSEXESVC)",
     "T1021.002", "Lateral Movement", "high",
     "PsExec service artifact — remote administration or lateral movement."),
    ("SMB_ADMIN_SHARE",
     r"(?i)\\\\[^\\]+\\(?:ADMIN|C|IPC)\$",
     "T1021.002", "Lateral Movement", "medium",
     "Windows admin share access — potential lateral movement."),
    ("WINRM_MOVEMENT",
     r"(?i)(?:winrm|Enter-PSSession|Invoke-Command\s+-ComputerName)",
     "T1021.006", "Lateral Movement", "high",
     "WinRM / PSRemoting — lateral movement via Windows Remote Management."),
    ("PASS_THE_HASH",
     r"(?i)(?:sekurlsa::pth|/ntlm:[a-f0-9]{32}\s+/domain:)",
     "T1550.002", "Lateral Movement", "critical",
     "Pass-the-Hash technique invocation."),

    # ─── Defense evasion / anti-forensics
    ("EVENT_LOG_CLEAR",
     r"(?i)(?:wevtutil\s+cl|Clear-EventLog|Remove-EventLog|auditpol\s+/clear)",
     "T1070.001", "Defense Evasion", "critical",
     "Windows event-log clearing — anti-forensics."),
    ("BASH_HISTORY_CLEAR",
     r"(?i)(?:history\s+-c|>\s*~/\.bash_history|unset\s+HISTFILE)",
     "T1070.003", "Defense Evasion", "high",
     "Bash history tampering — anti-forensics."),
    ("DEFENDER_DISABLE",
     r"(?i)(?:Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true|sc\s+stop\s+windefend|Uninstall-WindowsFeature.*Windows-Defender)",
     "T1562.001", "Defense Evasion", "critical",
     "Windows Defender being disabled."),
    ("FIREWALL_DISABLE",
     r"(?i)(?:netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off|Set-NetFirewallProfile\s+-Enabled\s+False)",
     "T1562.004", "Defense Evasion", "critical",
     "Host firewall disabled."),

    # ─── Suspicious commands / recon
    ("RECON_WHOAMI_ALL",
     r"(?i)whoami\s+/(?:all|priv|groups)",
     "T1033", "Discovery", "low",
     "whoami /all — enumeration of current user privileges."),
    ("RECON_NET_USER",
     r"(?i)net\s+(?:user|group|localgroup|accounts)\s+/domain",
     "T1087.002", "Discovery", "medium",
     "AD account enumeration via net commands."),
    ("RECON_QUSER",
     r"(?i)(?:quser|qwinsta|tasklist\s+/v)",
     "T1033", "Discovery", "low",
     "Session / process enumeration — reconnaissance."),
    ("BLOODHOUND",
     r"(?i)(?:bloodhound|SharpHound(?:\.exe)?|-CollectionMethod\s+All)",
     "T1087", "Discovery", "high",
     "BloodHound / SharpHound — AD attack-path enumeration."),

    # ─── Malware / crypto-miner
    ("CRYPTO_MINER_XMR",
     r"(?i)(?:xmrig|coinhive|cryptonight|stratum\+tcp://|monero(?:hash|pool))",
     "T1496", "Impact", "critical",
     "Crypto-miner (XMRig / Monero) signature."),
    ("SUSPICIOUS_ONION",
     r"(?i)[a-z2-7]{16,56}\.onion(?:/|\b)",
     "T1090.003", "Command and Control", "high",
     "Tor .onion URL in log — likely C2 or exfiltration."),
    ("BITCOIN_ADDRESS",
     r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z0-9]{25,34})\b",
     "T1657", "Impact", "medium",
     "Bitcoin address in log — possibly a ransom demand or wallet."),

    # ─── Web-shell indicators
    ("WEBSHELL_PHP",
     r"(?i)\?(?:cmd|c|exec|shell)=(?:system|passthru|shell_exec|exec|proc_open|eval)\s*\(",
     "T1505.003", "Persistence", "critical",
     "PHP web-shell parameter — RCE via eval/system/passthru."),
    ("WEBSHELL_JSP",
     r"(?i)<%\s*(?:Runtime|ProcessBuilder|Process|exec)",
     "T1505.003", "Persistence", "critical",
     "JSP web-shell — inline Java exec code."),
    ("WEBSHELL_ASPX",
     r"(?i)<%@\s*Page.*(?:System\.Diagnostics\.Process|CreateObject\(\s*['\"]WScript\.Shell)",
     "T1505.003", "Persistence", "critical",
     "ASPX web-shell — inline .NET exec code."),
    ("CHINA_CHOPPER",
     r"(?i)eval\s*\(\s*base64_decode\s*\(",
     "T1505.003", "Persistence", "critical",
     "China Chopper style web-shell (base64+eval)."),

    # ─── SSH abuse
    ("SSH_KEY_INJECTION",
     r"(?i)echo\s+['\"]?ssh-(?:rsa|ed25519|dss|ecdsa)\s+[A-Za-z0-9+/=]{100,}[\"']?\s*>>\s*.*authorized_keys",
     "T1098.004", "Persistence", "critical",
     "SSH key injection into authorized_keys."),
    ("SSH_PORT_FORWARD",
     r"(?i)ssh\s+.*-[RL]\s+\d+:[^\s]+:\d+",
     "T1572", "Command and Control", "medium",
     "SSH port forwarding — tunnel setup."),

    # ─── Container / Kubernetes
    ("K8S_TOKEN_ACCESS",
     r"/var/run/secrets/kubernetes\.io/serviceaccount/token",
     "T1552.007", "Credential Access", "high",
     "Kubernetes service-account token access — cluster credential theft."),
    ("DOCKER_ESCAPE",
     r"(?i)(?:--privileged|--pid=host|--net=host|/var/run/docker\.sock)",
     "T1611", "Privilege Escalation", "high",
     "Container escape indicators — privileged container or host socket."),

    # ─── Suspicious network patterns
    ("SUSPICIOUS_PORT",
     r":(?:4444|5555|6666|7777|8888|9999|31337|1337|1234|54321)\b",
     "T1571", "Command and Control", "medium",
     "Common malware/backdoor port number in connection."),
    ("MASSCAN_UA",
     r"(?i)User-Agent[:\s]+(?:masscan|zgrab|zmap)",
     "T1595.001", "Reconnaissance", "medium",
     "Mass-scanner User-Agent (masscan/zgrab/zmap)."),

    # ─── Linux SSH / PAM auth attack patterns (fire without DB rules)
    ("SSHD_INVALID_USER",
     r"(?i)(?:invalid user|user unknown|input_userauth_request:\s*invalid user)",
     "T1110", "Credential Access", "high",
     "SSH login attempt for an unknown / invalid username — enumeration."),
    ("SSHD_ROOT_LOGIN_ATTEMPT",
     r"(?i)authentication failure;.*user=root|Failed password for root from",
     "T1110", "Credential Access", "high",
     "Direct SSH login attempt as root — brute-force target."),
    ("SSHD_AUTH_FAILURE_PAM",
     r"pam_unix\([^)]*\):\s*authentication failure",
     "T1110", "Credential Access", "medium",
     "PAM authentication failure — repeated hits indicate brute force."),
    ("SSHD_CHECK_PASS_UNKNOWN",
     r"(?i)check pass;\s*user unknown",
     "T1087.001", "Discovery", "medium",
     "SSH user-enumeration attempt (check pass / user unknown)."),
    ("SSHD_MAX_AUTH_TRIES",
     r"(?i)maximum authentication attempts exceeded|Too many authentication failures",
     "T1110", "Credential Access", "high",
     "SSH client exceeded max auth tries — active brute-force campaign."),
    ("SSHD_PREAUTH_DROP",
     r"(?i)disconnected from .+ \[preauth\]|Received disconnect from .+ \[preauth\]",
     "T1595", "Reconnaissance", "low",
     "SSH pre-authentication disconnect — bulk hits indicate scanning."),
    ("LINUX_SU_ROOT",
     r"(?i)(?:su(?:do)?\[[0-9]+\]|session opened for user root)",
     "T1548.003", "Privilege Escalation", "low",
     "Root session opened via su/sudo — routine, but a burst is suspicious."),
    ("LINUX_UMASK_WORLD_WRITABLE",
     r"(?i)chmod\s+(?:777|666|a\+w|o\+w)\s+/(?:etc|usr|bin|sbin|root)",
     "T1222.002", "Defense Evasion", "high",
     "chmod making critical directory world-writable."),
    ("LINUX_MODPROBE_BLACKLIST",
     r"(?i)modprobe\s+(?:-r\s+)?(?:audit|apparmor|selinux)",
     "T1562.001", "Defense Evasion", "high",
     "Unloading security kernel modules (audit / apparmor / selinux)."),
    ("LINUX_SYSLOG_STOP",
     r"(?i)systemctl\s+(?:stop|disable|mask)\s+(?:rsyslog|syslog|auditd|systemd-journald)",
     "T1562.008", "Defense Evasion", "critical",
     "Stopping the logging daemon — anti-forensics."),
    ("LINUX_LD_PRELOAD",
     r"(?i)LD_PRELOAD\s*=\s*/[^\s]+\.so",
     "T1574.006", "Persistence", "high",
     "LD_PRELOAD hijack — library injection persistence."),
    ("LINUX_HISTFILE_UNSET",
     r"(?i)(?:unset\s+HISTFILE|HISTFILE\s*=\s*/dev/null|HISTSIZE\s*=\s*0)",
     "T1070.003", "Defense Evasion", "high",
     "Shell history disabled — evasion."),
    ("LINUX_CRON_HOURLY_WRITE",
     r"/etc/cron\.(?:d|hourly|daily|weekly|monthly)/[^/\s]+\s*(?:written|created|installed)",
     "T1053.003", "Persistence", "medium",
     "New file dropped in /etc/cron.* — persistence."),
    ("LINUX_BASHRC_EDIT",
     r"(?i)(?:>>|echo)\s+.*/\.(?:bashrc|profile|zshrc|bash_profile)",
     "T1546.004", "Persistence", "medium",
     "Shell rc file edited via redirect — user-level persistence."),
    ("LINUX_TMP_BINARY_EXEC",
     r"(?:^|\s)/(?:tmp|dev/shm|var/tmp)/[^\s]{1,60}\s+(?:executing|running)",
     "T1036.005", "Defense Evasion", "high",
     "Executable running from /tmp or /dev/shm — malware staging area."),

    # ─── Additional generic recon signatures
    ("PORT_SCAN_TCP_FLAGS",
     r"(?i)tcp\s+flag(?:s)?\s*=?\s*(?:S|SYN)\b.*port\s+\d+",
     "T1046", "Reconnaissance", "low",
     "Bare-SYN packets — TCP port scan probe."),
    ("SLOW_LORIS",
     r"(?i)partial\s+http\s+request|slow\s+read|X-a:\s*b\r\n",
     "T1499.001", "Impact", "medium",
     "Slowloris / slow-HTTP DoS pattern."),
]


# Compile once for the lifetime of the process. If regex compilation
# fails for a signature we drop it with a log rather than crashing —
# a single bad pattern must not block the whole analyzer.
_COMPILED_SIGNATURES: list[tuple[str, "re.Pattern", str, str, str, str]] = []
for _name, _rx, _mitre, _kc, _sev, _desc in _THREAT_SIGNATURES:
    try:
        _COMPILED_SIGNATURES.append((_name, re.compile(_rx), _mitre, _kc, _sev, _desc))
    except re.error as _exc:  # pragma: no cover - defensive
        logger.warning("threat signature %s compile failed: %s", _name, _exc)


# ─────────────────────────────────────────────────────────────────────
# CONTEXT GATING — web-only signatures must not fire on non-web logs
# ─────────────────────────────────────────────────────────────────────
#
# THE SSRF FALSE-POSITIVE FIX. Signatures whose whole meaning is HTTP
# (SSRF, SQLi, XSS, path traversal, web CVEs, web-shells…) must only be
# evaluated against events that are actually web traffic. Otherwise the
# literal string "localhost" inside a Windows logon event trips
# SSRF_LOCAL — exactly the false positive seen in report #16, where 78
# Windows 4624/4648 events were mislabelled as SSRF.
#
# These signatures fire ONLY on an event that looks like a web request.
_WEB_CONTEXT_SIGNATURES: frozenset[str] = frozenset({
    "SQLI_TIME_BLIND", "SQLI_BOOLEAN", "SQLI_STACKED", "XXE_ATTACK",
    "SSRF_LOCAL", "SSTI_JINJA_2", "NOSQL_INJECTION", "LDAP_INJECTION",
    "XPATH_INJECTION", "PATH_TRAVERSAL_ENC", "PHP_LFI", "RFI_EXTERNAL",
    "OGNL_INJECTION", "SPEL_INJECTION", "PROTOTYPE_POLLUTION",
    "HTTP_REQUEST_SMUGGLING", "GRAPHQL_INTROSPECTION", "JWT_NONE_ALG",
    "LOG4SHELL_JNDI", "PROXYSHELL", "PROXYLOGON", "SPRING4SHELL",
    "CITRIX_BLEED", "MOVEIT_TRANSFER", "WEBSHELL_PHP", "WEBSHELL_JSP",
    "WEBSHELL_ASPX", "CHINA_CHOPPER", "MASSCAN_UA", "SLOW_LORIS",
    "CLOUD_METADATA_ACCESS",
})

# Recognises an HTTP request in free text: a method + path, an HTTP
# version token, a URL scheme, or a User-Agent header.
_WEB_INDICATOR_RE = re.compile(
    r"(?:\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/)"
    r"|(?:HTTP/\d)"
    r"|(?:https?://)"
    r"|(?:User-Agent\s*[:=])",
    re.IGNORECASE,
)


def _event_is_web(ev: dict, text: str) -> bool:
    """True when an event is web traffic — the only context in which a
    web-only signature may fire."""
    if ev.get("event_type") == "web_request":
        return True
    data = ev.get("normalized_data") or {}
    if isinstance(data, dict) and (data.get("url") or data.get("request_line")
                                   or data.get("user_agent")):
        return True
    # A Windows/structured event is explicitly NOT web, even if its body
    # happens to contain the word "localhost".
    if isinstance(data, dict) and data.get("platform") == "windows":
        return False
    return bool(_WEB_INDICATOR_RE.search(text))


def _detect_threat_signatures(events: list[dict]) -> list[dict]:
    """Scan every event's raw_log + selected normalized_data fields
    against every compiled threat signature. Groups by (name, actor)
    so a scanner firing 500 identical payloads shows as one finding.

    Runs in one pass over the events per signature — O(events × sigs)
    but each check is a cheap regex. On a 100k-event upload this
    completes in a couple of seconds.
    """
    findings: list[dict] = []
    if not events:
        return findings

    def _samples(indexes: list[int]) -> list[str]:
        out: list[str] = []
        for i in indexes[:_SAMPLE_LINES_PER_FINDING]:
            raw = events[i].get("raw_log")
            if isinstance(raw, str) and raw.strip():
                out.append(raw.strip()[:500])
        return out

    def _timeline(indexes: list[int]) -> tuple[str | None, str | None]:
        ts = [events[i].get("timestamp") for i in indexes if events[i].get("timestamp")]
        return (ts[0] if ts else None, ts[-1] if ts else None)

    # Pre-materialize the scannable text per event so each signature
    # doesn't re-concatenate. Includes raw_log + selected normalized
    # fields so URL, request_line, command, user_agent all count.
    scan_text: list[str] = []
    for ev in events:
        raw = ev.get("raw_log") or ""
        data = ev.get("normalized_data") or {}
        extras: list[str] = []
        if isinstance(data, dict):
            for key in ("url", "request_line", "path", "query", "body",
                        "user_agent", "command", "cmd", "process", "command_line"):
                v = data.get(key)
                if isinstance(v, str) and v:
                    extras.append(v)
        scan_text.append(raw if not extras else raw + "  " + "  ".join(extras))

    # Group hits by (signature_name, actor) — where actor is source_ip,
    # else hostname, else username, else "-".
    def _actor(ev: dict) -> str:
        return (ev.get("source_ip")
                or ev.get("hostname")
                or ev.get("username")
                or "-")

    # Precompute which events are web traffic, so the web-only gate is
    # O(1) per (signature, event) instead of re-scanning.
    is_web_event = [_event_is_web(ev, scan_text[i]) for i, ev in enumerate(events)]

    for name, rx, mitre, kc, sev, desc in _COMPILED_SIGNATURES:
        web_only = name in _WEB_CONTEXT_SIGNATURES
        groups: dict[tuple[str, str], list[int]] = defaultdict(list)
        for i, text in enumerate(scan_text):
            # Web-only signatures never fire on non-web events — this is
            # what stops "localhost" in a Windows logon becoming SSRF.
            if web_only and not is_web_event[i]:
                continue
            if rx.search(text):
                groups[(name, _actor(events[i]))].append(i)

        for (sig_name, actor), idxs in groups.items():
            # Escalate severity when a MEDIUM/HIGH signature fires in
            # bulk — 100 hits of an XSS payload is worse than 1.
            eff_sev = sev
            if len(idxs) >= 100 and sev == "medium":
                eff_sev = "high"
            elif len(idxs) >= 100 and sev == "high":
                eff_sev = "critical"

            rule = _fake_rule(
                f"threat_signature",
                f"Threat signature · {sig_name}",
                mitre,
                kc,
                eff_sev,
            )
            first_ts, last_ts = _timeline(idxs)
            findings.append({
                "rule": rule.name,
                "rule_type": "threat_signature",
                "mitre": mitre,
                "mitre_blurb": _MITRE_BLURBS.get(mitre, ""),
                "kill_chain": kc,
                "severity": eff_sev,
                "source": actor,
                "count": len(idxs),
                "reason": f"{desc} (×{len(idxs)})",
                "first_seen": first_ts,
                "last_seen": last_ts,
                "sample_events": _samples(idxs),
                "sample_indexes": idxs[:_SAMPLE_LINES_PER_FINDING],
                "signature": sig_name,
                "signature_description": desc,
            })

    return findings


# ═══════════════════════════════════════════════════════════════════════
# CORRELATION — turn related events into ONE meaningful finding
# ═══════════════════════════════════════════════════════════════════════
#
# Raw event counts are not incidents. A SOC analyst correlates: "failed
# logons for account X *followed by a success* for X" is the signal that
# matters, not "there were 10 failures somewhere". This pass links
# events per account and only raises a finding when the *pattern* is
# present — and labels it honestly, because on a personal desktop a few
# failures then a success is just someone who mistyped their password.

# Thresholds are conservative on purpose.
_CORR_BRUTE_MIN_FAILURES = 5       # failures for one account to call it brute-force-ish
_CORR_COMPROMISE_MIN_FAILURES = 5  # failures-then-success to flag possible compromise


def _detect_correlations(events: list[dict]) -> list[dict]:
    """Account-centric correlation over the parsed auth events.

    Produces:
      * credential_compromise_pattern — N+ failures for a REAL user
        account and then a success for the same account (order = file
        order, which is chronological in every export). HIGH, but the
        description states plainly it may be a user who forgot their
        password, so a human still decides.
      * brute_force_attempt — N+ failures for one account with NO
        success. MEDIUM/HIGH by volume.
    """
    findings: list[dict] = []
    if not events:
        return findings

    def _acct(ev: dict) -> str | None:
        u = ev.get("username")
        return u.strip() if isinstance(u, str) and u.strip() else None

    def _is_service(ev: dict) -> bool:
        data = ev.get("normalized_data") or {}
        return bool(isinstance(data, dict) and data.get("is_service_account"))

    # Per real-user account: indices of failures and successes, in order.
    fails: dict[str, list[int]] = defaultdict(list)
    succs: dict[str, list[int]] = defaultdict(list)
    for i, ev in enumerate(events):
        et = ev.get("event_type")
        acct = _acct(ev)
        if not acct or _is_service(ev):
            continue
        if et == "authentication_failure":
            fails[acct].append(i)
        elif et == "authentication_success":
            succs[acct].append(i)

    def _samples(indexes: list[int]) -> list[str]:
        out: list[str] = []
        for i in indexes[:_SAMPLE_LINES_PER_FINDING]:
            raw = events[i].get("raw_log")
            if isinstance(raw, str) and raw.strip():
                out.append(raw.strip()[:500])
        return out

    for acct, fail_idxs in fails.items():
        if len(fail_idxs) < _CORR_BRUTE_MIN_FAILURES:
            continue
        first_fail = fail_idxs[0]
        # A success for this account that occurs AFTER the failures began.
        later_success = [i for i in succs.get(acct, []) if i > first_fail]

        if later_success and len(fail_idxs) >= _CORR_COMPROMISE_MIN_FAILURES:
            idxs = fail_idxs + later_success[:1]
            rule = _fake_rule(
                "credential_compromise_pattern",
                "Correlated: failed logons followed by a successful logon",
                "T1110", "Credential Access", "high",
            )
            findings.append({
                "rule": rule.name,
                "rule_type": "credential_compromise_pattern",
                "mitre": "T1110", "mitre_blurb": _MITRE_BLURBS.get("T1110", ""),
                "kill_chain": "Credential Access", "severity": "high",
                "source": acct, "count": len(fail_idxs),
                "reason": (
                    f"Account '{acct}' had {len(fail_idxs)} failed logon(s) and then a "
                    f"SUCCESSFUL logon. This is the shape of a successful password-guessing "
                    f"attack — but it is also what a legitimate user who forgot and then "
                    f"remembered their password looks like. Correlate: is '{acct}' expected "
                    f"to log in here? Did the failures come from one source in a short burst? "
                    f"Confirm before treating as compromise."
                ),
                "first_seen": None, "last_seen": None,
                "sample_events": _samples(idxs),
                "sample_indexes": idxs[:_SAMPLE_LINES_PER_FINDING],
                "correlated_account": acct,
                "failed_count": len(fail_idxs),
                "succeeded_after": True,
            })
        else:
            sev = "high" if len(fail_idxs) >= 20 else "medium"
            rule = _fake_rule(
                "brute_force_attempt",
                "Correlated: repeated failed logons for one account",
                "T1110", "Credential Access", sev,
            )
            findings.append({
                "rule": rule.name,
                "rule_type": "brute_force_attempt",
                "mitre": "T1110", "mitre_blurb": _MITRE_BLURBS.get("T1110", ""),
                "kill_chain": "Credential Access", "severity": sev,
                "source": acct, "count": len(fail_idxs),
                "reason": (
                    f"Account '{acct}' had {len(fail_idxs)} failed logon(s) with no observed "
                    f"success. Consistent with a brute-force attempt — or a misconfigured "
                    f"service / a user locked out. Check whether the attempts came from one "
                    f"source and in a tight time window."
                ),
                "first_seen": None, "last_seen": None,
                "sample_events": _samples(fail_idxs),
                "sample_indexes": fail_idxs[:_SAMPLE_LINES_PER_FINDING],
                "correlated_account": acct,
                "failed_count": len(fail_idxs),
                "succeeded_after": False,
            })

    return findings


# ═══════════════════════════════════════════════════════════════════════
# SIGMA — analyst-authored / community YAML detections (config, not code)
# ═══════════════════════════════════════════════════════════════════════
_SIGMA_RULES_CACHE: list | None = None


def _load_sigma_rules() -> list:
    """Load (and cache for the process) the Sigma rules from the
    configured directory. Cached because parsing YAML on every upload
    would be wasteful; a restart picks up new rules."""
    global _SIGMA_RULES_CACHE
    if _SIGMA_RULES_CACHE is not None:
        return _SIGMA_RULES_CACHE
    try:
        from app.config import get_settings
        from app.detection import sigma
        settings = get_settings()
        if not getattr(settings, "SIGMA_ENABLED", True):
            _SIGMA_RULES_CACHE = []
        else:
            _SIGMA_RULES_CACHE = sigma.load_rules(settings.SIGMA_RULES_DIR)
    except Exception:  # noqa: BLE001 - Sigma is optional; never block analysis
        logger.exception("Sigma: failed to load rules")
        _SIGMA_RULES_CACHE = []
    return _SIGMA_RULES_CACHE


def _detect_sigma(events: list[dict]) -> list[dict]:
    """Evaluate every loaded Sigma rule against every event. Groups hits
    per (rule, actor) like the other detectors."""
    rules = _load_sigma_rules()
    if not rules:
        return []

    from app.detection import sigma

    findings: list[dict] = []

    def _actor(ev: dict) -> str:
        return (ev.get("source_ip") or ev.get("hostname")
                or ev.get("username") or "-")

    def _samples(indexes: list[int]) -> list[str]:
        out: list[str] = []
        for i in indexes[:_SAMPLE_LINES_PER_FINDING]:
            raw = events[i].get("raw_log")
            if isinstance(raw, str) and raw.strip():
                out.append(raw.strip()[:500])
        return out

    def _timeline(indexes: list[int]) -> tuple[str | None, str | None]:
        ts = [events[i].get("timestamp") for i in indexes if events[i].get("timestamp")]
        return (ts[0] if ts else None, ts[-1] if ts else None)

    for rule in rules:
        groups: dict[str, list[int]] = defaultdict(list)
        for i, ev in enumerate(events):
            raw = ev.get("raw_log") or ""
            try:
                if sigma.rule_matches(rule, ev, raw):
                    groups[_actor(ev)].append(i)
            except Exception:  # noqa: BLE001 - a bad rule must not crash analysis
                continue
        for actor, idxs in groups.items():
            first_ts, last_ts = _timeline(idxs)
            findings.append({
                "rule": f"Sigma · {rule.title}",
                "rule_type": "sigma",
                "mitre": rule.mitre,
                "mitre_blurb": _MITRE_BLURBS.get(rule.mitre or "", rule.description[:160]),
                "kill_chain": rule.kill_chain,
                "severity": rule.severity,
                "source": actor,
                "count": len(idxs),
                "reason": (rule.description or rule.title)[:300] + f" (×{len(idxs)})",
                "first_seen": first_ts,
                "last_seen": last_ts,
                "sample_events": _samples(idxs),
                "sample_indexes": idxs[:_SAMPLE_LINES_PER_FINDING],
                "sigma_id": rule.rule_id,
                "sigma_level": rule.level,
            })
    return findings


# ─────────────────────────────────────────────────────────────────────
# Input format detection
# ─────────────────────────────────────────────────────────────────────
def _first_nonempty(text: str) -> str:
    for line in text.splitlines():
        s = line.strip()
        if s:
            return s
    return ""


def _parse_lines(raw: bytes) -> tuple[list[str], str]:
    """Detect format and return the list of individual log lines + a
    string naming the format ('text', 'json-lines', 'csv')."""
    text = raw.decode("utf-8", errors="replace")
    if not text.strip():
        return [], "text"

    first = _first_nonempty(text)

    # ── JSON-lines: first non-empty line starts with { and parses.
    if first.startswith("{"):
        lines_out: list[str] = []
        any_json = False
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    any_json = True
                    lines_out.append(
                        obj.get("raw_log")
                        or obj.get("message")
                        or obj.get("log")
                        or obj.get("msg")
                        or json.dumps(obj)
                    )
                else:
                    lines_out.append(line)
            except json.JSONDecodeError:
                lines_out.append(line)
        if any_json:
            return lines_out, "json-lines"

    # ── CSV with a recognizable "log content" column.
    # Accepts the SIEM's own raw_log/message/log/msg names AND the
    # column names commonly found in exported logs from Windows event
    # viewers, Zeek, Sysmon, and dataset dumps (Content, Description,
    # Details, Info, Text).
    #
    # CRITICAL for Windows Event Viewer exports: the Event ID, Level/
    # Keywords, Date and Time and Source are SEPARATE columns from the
    # message body. If we returned only the body column we would drop the
    # Event ID and every event would fall through to "unparsed" (the
    # exact bug seen in report #16). So when the CSV carries identifying
    # columns, we PREFIX them onto the content so the Windows parser sees
    # "Event ID=<n>" and the account/date fields.
    if "," in first:
        try:
            reader = csv.DictReader(io.StringIO(text))
            fieldnames = reader.fieldnames or []
            cols_l = [c.lower() for c in fieldnames]
            preferred = ("raw_log", "message", "log", "msg",
                         "content", "description", "details", "info", "text")

            # Columns worth preserving in front of the content, if present.
            id_cols = [fieldnames[i] for i, c in enumerate(cols_l)
                       if c in ("event id", "eventid", "id", "level", "keywords",
                                "date and time", "timecreated", "source",
                                "task category", "account", "account name")]

            content_col = None
            for candidate in preferred:
                if candidate in cols_l:
                    content_col = fieldnames[cols_l.index(candidate)]
                    break

            if content_col is not None:
                rows = []
                for row in reader:
                    body = row.get(content_col) or ""
                    prefix = " | ".join(f"{c}={row[c]}" for c in id_cols if row.get(c))
                    combined = (prefix + " | " + body).strip(" |") if prefix else body
                    if combined:
                        rows.append(combined)
                if rows:
                    return rows, "csv"

            # No known content column — concatenate the whole row so both
            # the Windows parser and the keyword heuristics still fire.
            reader = csv.DictReader(io.StringIO(text))
            rows = []
            for row in reader:
                if not row:
                    continue
                pieces = [f"{k}={v}" for k, v in row.items() if v]
                rows.append(" | ".join(pieces))
            if rows:
                return rows, "csv"
        except csv.Error:
            pass

    # ── Plain text (one log line per row)
    return [ln for ln in text.splitlines() if ln.strip()], "text"


# ─────────────────────────────────────────────────────────────────────
# Aggregation helpers used by the report
# ─────────────────────────────────────────────────────────────────────
def _timeline_buckets(events: list[dict]) -> list[dict]:
    """Group events by hour (UTC) for the report's activity chart. Each
    bucket returns {hour, total, by_severity} so the renderer can draw
    a stacked bar."""
    buckets: dict[str, dict] = {}
    for ev in events:
        ts = ev.get("timestamp")
        if not ts:
            continue
        # ISO8601 down to the hour
        try:
            bucket = ts[:13]  # "YYYY-MM-DDTHH"
        except Exception:
            continue
        b = buckets.setdefault(bucket, {"hour": bucket, "total": 0, "by_severity": {}})
        b["total"] += 1
        sev = ev.get("severity") or "low"
        b["by_severity"][sev] = b["by_severity"].get(sev, 0) + 1
    return [buckets[k] for k in sorted(buckets)]


def _iocs(events: list[dict]) -> dict[str, list]:
    """Extract Indicators of Compromise the SOC would pin into a
    ticketing system. Small, capped, sorted."""
    ips = Counter(e["source_ip"] for e in events if e.get("source_ip"))
    users = Counter(e["username"] for e in events if e.get("username"))
    hosts = Counter(e["hostname"] for e in events if e.get("hostname"))
    ports = Counter(e["destination_port"] for e in events if e.get("destination_port"))
    urls = Counter(
        (e.get("normalized_data") or {}).get("url")
        for e in events
        if (e.get("normalized_data") or {}).get("url")
    )
    uas = Counter(
        (e.get("normalized_data") or {}).get("user_agent")
        for e in events
        if (e.get("normalized_data") or {}).get("user_agent")
    )
    return {
        "source_ips":    ips.most_common(20),
        "usernames":     users.most_common(20),
        "hostnames":     hosts.most_common(10),
        "ports":         ports.most_common(20),
        "urls":          urls.most_common(15),
        "user_agents":   uas.most_common(10),
    }


# ─────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────
def analyze(raw: bytes, db: Session) -> dict[str, Any]:
    """Main entry point. Returns a dict shaped for report.build_summary()."""
    start = time.monotonic()
    truncated = False
    if len(raw) > MAX_BYTES:
        raw = raw[:MAX_BYTES]
        truncated = True

    lines, fmt = _parse_lines(raw)
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES]
        truncated = True

    events: list[dict] = []
    parse_errors = 0
    for line in lines:
        try:
            ev = normalize({"raw_log": line})
            events.append({
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                "event_type": ev.event_type,
                "severity": ev.severity,
                "source_ip": ev.source_ip,
                "destination_ip": ev.destination_ip,
                "destination_port": ev.destination_port,
                "username": ev.username,
                "hostname": ev.hostname,
                "event_id": ev.event_id,
                "raw_log": ev.raw_log,
                "normalized_data": ev.normalized_data,
            })
        except Exception:  # noqa: BLE001
            parse_errors += 1

    # Aggregations
    event_type_counts = Counter(e["event_type"] for e in events)
    severity_counts = Counter(e["severity"] for e in events)
    source_counts = Counter(e["source_ip"] for e in events if e["source_ip"])
    user_counts = Counter(e["username"] for e in events if e["username"])

    # Rule matching (the 8 DB-backed detection rules)
    rules = db.query(DetectionRule).filter(DetectionRule.enabled.is_(True)).all()
    findings = _classify_batch(events, rules)

    # v2.2 --- built-in heuristics that don't need a DB rule row:
    # Windows HRESULT / event-ID / CBS integrity / bulk-failure detection.
    # These catch Windows and structured logs the 8 network-oriented
    # rules were never designed to see.
    findings.extend(_detect_windows_anomalies(events))

    # v2.2 --- threat-signature catalog (140+ patterns across every log
    # family: web attacks, CVE indicators, reverse shells, PowerShell
    # abuse, LOLBAS, credential dumping, ransomware, exfil, persistence,
    # lateral movement, defense evasion, malware, container escapes,
    # Linux SSH auth attacks). Fires on any raw_log or normalized_data
    # field match; no DB rule required. Web-only signatures are gated to
    # web-context events so "localhost" in a Windows logon is not SSRF.
    findings.extend(_detect_threat_signatures(events))

    # v2.3 --- correlation: link failed→successful logons per account so a
    # real pattern (not a raw count) drives the finding.
    findings.extend(_detect_correlations(events))

    # v2.3 --- Sigma rules: analyst-authored / community YAML detections,
    # loaded from the Sigma directory. Detections as config, not code.
    findings.extend(_detect_sigma(events))

    findings_by_severity = Counter(f["severity"] for f in findings)
    findings_by_rule = Counter(f["rule_type"] for f in findings)

    elapsed_ms = int((time.monotonic() - start) * 1000)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_ms": elapsed_ms,
        "format": fmt,
        "truncated": truncated,
        "total_bytes": len(raw),
        "total_lines": len(lines),
        "parsed_events": len(events),
        "parse_errors": parse_errors,
        "unparsed_events": sum(1 for e in events if e["event_type"] == "unparsed"),
        "event_type_counts": dict(event_type_counts),
        "severity_counts": dict(severity_counts),
        "top_sources": source_counts.most_common(10),
        "top_users": user_counts.most_common(10),
        "findings": findings,
        "findings_by_severity": dict(findings_by_severity),
        "findings_by_rule": dict(findings_by_rule),
        "first_event_ts": events[0]["timestamp"] if events else None,
        "last_event_ts": events[-1]["timestamp"] if events else None,
        # v2.2 enrichment
        "iocs": _iocs(events),
        "timeline": _timeline_buckets(events),
    }
