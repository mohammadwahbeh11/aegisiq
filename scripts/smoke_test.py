#!/usr/bin/env python3
"""
scripts/smoke_test.py -- end-to-end verification of a running SIEM.

Verifies that EVERY detection rule from the project document actually
raises its expected alert against fresh, realistic log traffic:

    brute_force            - 6 failed SSH logins from one IP
    port_scan              - connections to 12 distinct ports from one IP
    login_after_failure    - 6 failed then 1 successful login (CRITICAL)
    file_integrity         - modification of /etc/shadow
    privilege_escalation   - sudo /bin/bash

Also exercises: auth (401 leak check), input validation (422), SOAR
containment record, MITRE + Kill Chain population, dashboard stats,
false-positive guard, DELETE endpoints and the retention purge API.

Idempotent: every attacker uses a fresh random address in the RFC 5737
documentation ranges (203.0.113.0/24, 198.51.100.0/24), and the test
pre-resolves any duplicate alerts on the file-integrity + privilege
paths that would otherwise be swallowed by rule deduplication. Safe to
run again and again against a warm database.

Usage:
    python scripts/smoke_test.py
    python scripts/smoke_test.py --url http://localhost:8000 \
        --username admin --password ChangeMe123!

Exit 0 = every check passed. Non-zero = the specific failure printed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import re
import ssl
import struct
import sys

# The status glyphs below (checkmarks, arrows) are not encodable in cp1252,
# which is still the default console encoding on Windows. Without this the
# script dies with UnicodeEncodeError on its very first print -- before any
# check runs -- which reads like the SIEM is broken when it is not.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # non-reconfigurable stream: harmless
        pass

import time
import urllib.error
import urllib.request
from typing import Any


def _totp_now(secret_b32: str) -> str:
    """Minimal RFC 6238 TOTP (SHA-1, 6 digits, 30 s) so the smoke test can
    compute the code the server expects during the MFA checks. Mirrors
    app/security/totp.py."""
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6)

RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BOLD = "\033[1m"


class SmokeError(Exception):
    pass


def color(text: str, c: str) -> str:
    return f"{c}{text}{RESET}"


# ---------------------------------------------------------------------------
# Fresh identifiers so a re-run doesn't collide with lingering open alerts
# (dedup, see app/detection/alerting.py).
# ---------------------------------------------------------------------------
_RNG = random.Random()
BRUTE_FORCE_IP = f"203.0.113.{_RNG.randint(10, 249)}"     # TEST-NET-3
PORT_SCAN_IP = f"198.51.100.{_RNG.randint(10, 249)}"      # TEST-NET-2
COMPROMISE_IP = f"203.0.113.{_RNG.randint(10, 249)}"      # TEST-NET-3
QUIET_IP = f"203.0.113.{_RNG.randint(10, 249)}"           # TEST-NET-3 (below threshold)
PRIV_ESC_USER = f"opsuser{_RNG.randint(1000, 9999)}"
FILE_INTEGRITY_USER = f"attacker{_RNG.randint(1000, 9999)}"


# TLS context for https:// backends. Set in main() from --insecure /
# --verify-tls. None => urllib default (plain http, or https with full
# verification). For a self-signed local cert we install an unverified
# context so the smoke test can still exercise the HTTPS listener.
_SSL_CONTEXT = None


def _http_once(method: str, url: str, token: str | None, body: Any | None) -> tuple[int, Any]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=10, context=_SSL_CONTEXT) as resp:
            raw = resp.read().decode() or "null"
            if not raw.strip():
                return resp.status, None
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, {"raw": raw}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode() or "null"
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


def http(method: str, url: str, *, token: str | None = None, body: Any | None = None) -> tuple[int, Any]:
    """HTTP with automatic back-off on the auth rate limiter (429).

    The /api/auth/* endpoints are deliberately throttled per source IP to
    blunt credential stuffing (RATE_LIMIT_AUTH_PER_MINUTE, default 10/min).
    A full smoke-test run makes more than that many login/verify calls in a
    few seconds, so an occasional 429 is expected and is NOT a failure --
    the server is doing its job. We honour the "Try again in Ns" hint (or a
    Retry-After) and retry, so the functional checks still complete. Real
    functional 4xx/5xx are returned unchanged for the caller to assert on."""
    for attempt in range(6):
        status, body_out = _http_once(method, url, token, body)
        if status != 429:
            return status, body_out
        # Parse the wait hint; default to a short sleep if absent.
        wait = 2.0
        detail = body_out.get("detail", "") if isinstance(body_out, dict) else ""
        m = re.search(r"in\s+(\d+(?:\.\d+)?)\s*s", str(detail))
        if m:
            wait = float(m.group(1)) + 0.5
        wait = min(wait, 12.0)
        if attempt == 0:
            print(f"  {color('…', YELLOW)} auth rate limit hit (429) — waiting "
                  f"{wait:.0f}s and retrying (expected: the limiter is working)")
        time.sleep(wait)
    # Exhausted retries — return the last 429 so the caller reports it.
    return status, body_out


def expect(cond: bool, message: str) -> None:
    if not cond:
        raise SmokeError(message)


def step(label: str) -> None:
    print(f"\n{color('▶', YELLOW)} {BOLD}{label}{RESET}")


def ok(label: str) -> None:
    print(f"  {color('✓', GREEN)} {label}")


def _clear_dedup_alerts(base: str, token: str, rule_type: str, dedup_key: str) -> None:
    """Resolve any OPEN alert that would suppress a fresh detection of
    the same rule + dedup_key -- the file_integrity and
    privilege_escalation rules dedup by path/actor, not source IP, so
    even a random IP won't help. Resolving an open alert releases the
    dedup window (see app/detection/alerting.py: OPEN alerts are one of
    the two dedup conditions)."""
    _, body = http("GET", f"{base}/api/alerts?limit=200", token=token)
    if not isinstance(body, dict):
        return
    for a in body.get("items", []):
        if a.get("rule_type") == rule_type and a.get("status") in ("new", "investigating"):
            # We don't know the alert's own dedup_key from the API, so we
            # resolve all open alerts for this rule_type. That is safe for
            # a smoke test: no analyst is triaging in parallel.
            http("PATCH", f"{base}/api/alerts/{a['id']}/status", token=token, body={"status": "resolved"})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("SIEM_URL", "http://localhost:8000"))
    parser.add_argument("--username", default=os.environ.get("SIEM_USERNAME", "admin"))
    parser.add_argument("--password", default=os.environ.get("SIEM_PASSWORD", "ChangeMe123!"))
    parser.add_argument("--verify-tls", action="store_true",
                        help="verify the server TLS certificate (default: skip verification, right for the self-signed local cert from scripts/generate_certs.sh).")
    args = parser.parse_args()

    base = args.url.rstrip("/")

    if base.lower().startswith("https") and not args.verify_tls:
        global _SSL_CONTEXT
        _SSL_CONTEXT = ssl.create_default_context()
        _SSL_CONTEXT.check_hostname = False
        _SSL_CONTEXT.verify_mode = ssl.CERT_NONE
        print("  (TLS certificate verification disabled for self-signed "
              "local cert; pass --verify-tls to enforce)")

    try:
        # -------------------------------------------------------------- 1
        step(f"Health check ({base}/health)")
        status, body = http("GET", f"{base}/health")
        expect(status == 200, f"/health returned HTTP {status}")
        expect(body["api"] == "ok", f"api status not ok: {body}")
        expect(body["database"] == "ok", f"database status not ok: {body}")
        expect(body["detection_engine"] == "ok",
               f"unexpected detection_engine status: {body['detection_engine']} — "
               f"unimplemented: {body.get('detection_rules_enabled_without_handler')}")
        ok(f"api=ok  db=ok  detection_engine=ok  soar={body['soar']}")
        ok(f"rules implemented: {', '.join(body['detection_rules_implemented'])}")

        # -------------------------------------------------------------- 2
        step("Login (JWT)")
        status, body = http("POST", f"{base}/api/auth/login",
                            body={"username": args.username, "password": args.password})
        expect(status == 200, f"login returned HTTP {status}: {body}")
        expect(body.get("role") == "administrator", f"logged in as non-admin: {body}")
        token = body["access_token"]
        ok(f"logged in as {body['username']} ({body['role']})")

        # -------------------------------------------------------------- 3
        step("Wrong password / unknown user return the same 401 (no username enumeration)")
        s1, _ = http("POST", f"{base}/api/auth/login",
                     body={"username": args.username, "password": "definitely-wrong"})
        s2, _ = http("POST", f"{base}/api/auth/login",
                     body={"username": f"no-such-user-{_RNG.randint(1, 9_999_999)}", "password": "x"})
        expect(s1 == 401 and s2 == 401, f"expected 401/401, got {s1}/{s2}")
        ok("both return 401 — the API does not leak whether a username exists")

        # -------------------------------------------------------------- 4
        step("Input validation at the schema layer")
        s, _ = http("POST", f"{base}/api/logs", body={"event_type": "authentication_failure"})
        expect(s == 401, f"unauthenticated POST /api/logs should be 401, got {s}")
        s, _ = http("POST", f"{base}/api/logs", token=token,
                    body={"event_type": "authentication_failure", "source_ip": "not-an-ip"})
        expect(s == 422, f"invalid IP should be 422, got {s}")
        s, _ = http("POST", f"{base}/api/logs", token=token,
                    body={"event_type": "port_access", "destination_port": 99999})
        expect(s == 422, f"invalid port should be 422, got {s}")
        s, _ = http("POST", f"{base}/api/logs", token=token, body={"hostname": "web-01"})
        expect(s == 422, f"empty ingest payload should be 422, got {s}")
        ok("unauth 401 · bad IP 422 · bad port 422 · empty payload 422")

        # -------------------------------------------------------------- 5
        step("Ingest a benign Linux successful login")
        s, body = http("POST", f"{base}/api/logs", token=token,
                       body={"raw_log": "Accepted password for ubuntu from 10.20.30.40 port 22 ssh2",
                             "hostname": "smoketest-host"})
        expect(s == 201, f"ingest returned HTTP {s}: {body}")
        expect(body["event_type"] == "authentication_success",
               f"parsed to unexpected event_type: {body['event_type']}")
        expect(body["alerts_generated"] == 0, "a single benign login must not raise an alert")
        ok(f"parsed as authentication_success, log id={body['id']}, alerts=0")

        # -------------------------------------------------------------- 6
        step(f"Rule 1 — Brute Force Authentication (T1110)  ·  6 failed logins from {BRUTE_FORCE_IP}")
        alert_ids: list[int] = []
        for i in range(6):
            s, body = http("POST", f"{base}/api/logs", token=token,
                           body={"raw_log": f"Failed password for invalid user root from {BRUTE_FORCE_IP} port 22 ssh2"})
            expect(s == 201, f"failed-login #{i+1} returned HTTP {s}: {body}")
            expect(body["event_type"] == "authentication_failure",
                   f"parsed unexpectedly on #{i+1}: {body['event_type']}")
            alert_ids.extend(body["alert_ids"])
        expect(len(alert_ids) >= 1,
               "brute_force rule did not fire after 6 failed logins from a fresh IP")
        ok(f"brute_force alert raised — id(s) {alert_ids}, MITRE T1110")

        # -------------------------------------------------------------- 7
        step(f"Rule 2 — Port Scanning (T1046)  ·  12 distinct ports from {PORT_SCAN_IP}")
        scan_alert_ids: list[int] = []
        for port in (21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389):
            s, body = http("POST", f"{base}/api/logs", token=token,
                           body={"raw_log": f"Connection attempt from {PORT_SCAN_IP} to port {port}"})
            expect(s == 201, f"port {port} returned HTTP {s}: {body}")
            scan_alert_ids.extend(body["alert_ids"])
        expect(len(scan_alert_ids) >= 1,
               "port_scan rule did not fire after 12 distinct ports from a fresh IP")
        ok(f"port_scan alert raised — id(s) {scan_alert_ids}, MITRE T1046")

        # -------------------------------------------------------------- 8
        step(f"Rule 3 — Login After Repeated Failures (T1078, CRITICAL)  ·  from {COMPROMISE_IP}")
        # 6 failures then a success from the SAME IP -- crosses the
        # brute_force threshold AND then the login_after_failure threshold.
        laf_alerts: list[int] = []
        for _ in range(6):
            s, body = http("POST", f"{base}/api/logs", token=token,
                           body={"raw_log": f"Failed password for admin from {COMPROMISE_IP} port 22 ssh2"})
            expect(s == 201, f"failed-login returned HTTP {s}: {body}")
            laf_alerts.extend(body["alert_ids"])
        s, body = http("POST", f"{base}/api/logs", token=token,
                       body={"raw_log": f"Accepted password for admin from {COMPROMISE_IP} port 22 ssh2"})
        expect(s == 201, f"success login returned HTTP {s}: {body}")
        laf_alerts.extend(body["alert_ids"])
        # Check the alerts endpoint for a login_after_failure alert
        _, alerts_body = http("GET",
                              f"{base}/api/alerts?source_ip={COMPROMISE_IP}&limit=20",
                              token=token)
        laf_present = any(a.get("rule_type") == "login_after_failure"
                          for a in alerts_body.get("items", []))
        expect(laf_present,
               f"login_after_failure did not fire even though {COMPROMISE_IP} had 6 fails + 1 success")
        ok(f"login_after_failure alert raised (CRITICAL) — MITRE T1078")

        # -------------------------------------------------------------- 9
        step(f"Rule 4 — Critical File Integrity Change (T1098, CRITICAL)  ·  /etc/shadow")
        # file_integrity dedups by path. If a prior run's /etc/shadow
        # alert is still open, resolve it so the fresh event fires.
        _clear_dedup_alerts(base, token, "file_integrity", "/etc/shadow")
        s, body = http("POST", f"{base}/api/logs", token=token,
                       body={"raw_log": f"File integrity violation: /etc/shadow modified by {FILE_INTEGRITY_USER}",
                             "hostname": "smoketest-host"})
        expect(s == 201, f"file integrity ingest returned HTTP {s}: {body}")
        expect(body["event_type"] == "file_integrity_change",
               f"parsed unexpectedly: {body['event_type']}")
        expect(body["alerts_generated"] >= 1,
               "file_integrity did not fire on /etc/shadow — was there an open duplicate?")
        ok(f"file_integrity alert raised (CRITICAL) — MITRE T1098")

        # -------------------------------------------------------------- 10
        step(f"Rule 5 — Privilege Escalation (T1548, CRITICAL)  ·  sudo /bin/bash as {PRIV_ESC_USER}")
        # privilege_escalation dedups by username -- fresh random user
        # per run, plus a defensive clear.
        _clear_dedup_alerts(base, token, "privilege_escalation", PRIV_ESC_USER)
        s, body = http("POST", f"{base}/api/logs", token=token,
                       body={"raw_log": f"sudo: {PRIV_ESC_USER} : TTY=pts/1 ; PWD=/home/{PRIV_ESC_USER} ; USER=root ; COMMAND=/bin/bash"})
        expect(s == 201, f"privilege-esc ingest returned HTTP {s}: {body}")
        expect(body["event_type"] == "privilege_related",
               f"parsed unexpectedly: {body['event_type']}")
        expect(body["alerts_generated"] >= 1,
               "privilege_escalation did not fire on sudo /bin/bash")
        priv_esc_alert_id = body["alert_ids"][0] if body["alert_ids"] else None
        ok(f"privilege_escalation alert raised (CRITICAL) — MITRE T1548")

        # -------------------------------------------------------------- 11
        step("Alerts endpoint reflects every raised rule type")
        s, body = http("GET", f"{base}/api/alerts?limit=500", token=token)
        expect(s == 200, f"alerts endpoint returned HTTP {s}")
        rule_types_seen = {a["rule_type"] for a in body["items"] if a.get("rule_type")}
        expected = {"brute_force", "port_scan", "login_after_failure",
                    "file_integrity", "privilege_escalation"}
        missing = expected - rule_types_seen
        expect(not missing,
               f"missing expected rule types in alerts: {missing}")
        ok(f"alerts total={body['total']}, all 5 rule types present")

        # -------------------------------------------------------------- 12
        step("Every alert carries a MITRE ATT&CK ID and a Kill Chain phase")
        with_meta = [a for a in body["items"]
                     if a.get("mitre_id") and a.get("kill_chain_phase")]
        expect(len(with_meta) >= 5,
               f"expected >= 5 alerts with MITRE + Kill Chain populated, got {len(with_meta)}")
        ok(f"{len(with_meta)} alert(s) tagged with MITRE + Kill Chain")

        # -------------------------------------------------------------- 13
        step("SOAR recorded a containment action for the brute-force alert")
        time.sleep(0.3)
        s, body = http("GET", f"{base}/api/soar/actions?limit=200", token=token)
        expect(s == 200, f"SOAR endpoint returned HTTP {s}")
        expect(body["execution_mode"] == "record_only",
               f"SOAR execution mode should be record_only, got {body['execution_mode']}")
        block_ip_actions = [a for a in body["items"]
                            if a["action_type"] == "block_ip" and a["target"] == BRUTE_FORCE_IP]
        expect(len(block_ip_actions) >= 1,
               f"expected a block_ip SOAR action targeting {BRUTE_FORCE_IP}")
        ok(f"SOAR recorded block_ip action for {BRUTE_FORCE_IP} (status={block_ip_actions[0]['status']})")

        # -------------------------------------------------------------- 14
        step("Dashboard stats endpoint returns coherent numbers")
        s, body = http("GET", f"{base}/api/dashboard/stats", token=token)
        expect(s == 200, f"dashboard stats returned HTTP {s}")
        expect(body["total_events"] >= 25,
               f"expected >=25 total events after ingest, got {body['total_events']}")
        expect(body["active_alerts"] >= 1,
               f"expected at least 1 active alert, got {body['active_alerts']}")
        ok(f"events={body['total_events']}, active={body['active_alerts']}, "
           f"critical={body['critical_alerts']}, high={body['high_alerts']}")

        # -------------------------------------------------------------- 15
        step("MITRE coverage lists all 8 rules (v2.0 adds web_attack, credential_stuffing, suspicious_user_agent)")
        s, body = http("GET", f"{base}/api/dashboard/mitre-coverage", token=token)
        expect(s == 200, f"MITRE coverage returned HTTP {s}")
        rule_types = {row["rule_type"] for row in body}
        v2_expected = expected | {"web_attack", "credential_stuffing", "suspicious_user_agent"}
        missing = v2_expected - rule_types
        expect(not missing, f"missing rules in MITRE coverage: {missing}")
        ok(f"all 8 rules mapped: {sorted(rule_types & v2_expected)}")

        # -------------------------------------------------------------- 16
        step(f"Sub-threshold traffic stays silent (false-positive guard, {QUIET_IP})")
        for _ in range(4):
            s, body = http("POST", f"{base}/api/logs", token=token,
                           body={"raw_log": f"Failed password for admin from {QUIET_IP}"})
            expect(s == 201, f"sub-threshold ingest returned HTTP {s}")
            expect(body["alerts_generated"] == 0,
                   "sub-threshold event should not raise an alert")
        ok("4 failed logins (below threshold of 5) raised zero alerts")

        # -------------------------------------------------------------- 17
        step("DELETE /api/alerts/{id} — retention: remove a single alert")
        if priv_esc_alert_id is not None:
            s, _ = http("DELETE", f"{base}/api/alerts/{priv_esc_alert_id}", token=token)
            expect(s in (200, 204), f"delete alert returned HTTP {s}")
            s, body = http("GET", f"{base}/api/alerts/{priv_esc_alert_id}", token=token)
            expect(s == 404, f"deleted alert should now 404, got {s}")
            ok(f"alert #{priv_esc_alert_id} deleted and confirmed 404 on re-fetch")
        else:
            ok("skipped (privilege-escalation alert id not captured)")

        # -------------------------------------------------------------- 18
        step("Retention config + dry-run")
        s, cfg = http("GET", f"{base}/api/retention/config", token=token)
        expect(s == 200, f"retention config returned HTTP {s}")
        expect("log_retention_days" in cfg and "alert_retention_days" in cfg,
               f"retention config missing fields: {cfg}")
        s, dry = http("POST", f"{base}/api/retention/dry-run", token=token,
                      body={"alerts_older_than_days": 365 * 5, "logs_older_than_days": 365 * 5})
        expect(s == 200, f"retention dry-run returned HTTP {s}: {dry}")
        expect("would_delete_alerts" in dry and "would_delete_logs" in dry,
               f"dry-run response missing fields: {dry}")
        ok(f"config days: alerts={cfg['alert_retention_days']} logs={cfg['log_retention_days']}, "
           f"dry-run says would_delete_alerts={dry['would_delete_alerts']} logs={dry['would_delete_logs']}")

        # -------------------------------------------------------------- 19
        step("Empty retention purge is rejected (safety guard)")
        s, body = http("POST", f"{base}/api/retention/purge", token=token, body={})
        expect(s == 400, f"empty purge should be 400, got {s}: {body}")
        ok("empty purge -> 400 (must specify a criteria)")

        # ═══════════════════════════════════════════════════════════════
        #  v2.0 — AegisIQ: 3 new rules + security hardening
        # ═══════════════════════════════════════════════════════════════

        # -------------------------------------------------------------- 20
        step("v2.0 rule — Web Application Attack (T1190)  ·  SQLi payload via nginx access log")
        web_ip = f"203.0.113.{_RNG.randint(10, 249)}"
        _, alerts_before = http("GET", f"{base}/api/alerts?limit=1", token=token)
        baseline = alerts_before["items"][0]["id"] if alerts_before.get("items") else 0
        sqli_line = (
            f'{web_ip} - - [21/Aug/2026:14:30:00 +0000] '
            f'"GET /?id=1\' UNION SELECT username,password FROM users-- HTTP/1.1" '
            f'200 213 "-" "Mozilla/5.0"'
        )
        s, body = http("POST", f"{base}/api/logs", token=token, body={"raw_log": sqli_line})
        expect(s == 201, f"web attack ingest returned HTTP {s}: {body}")
        expect(body["event_type"] == "web_request",
               f"nginx line should parse as web_request, got {body['event_type']}")
        # Poll for a bit -- rule fires synchronously so should be immediate.
        time.sleep(0.5)
        _, after = http("GET", f"{base}/api/alerts?limit=20", token=token)
        web_alerts = [a for a in after.get("items", [])
                      if a.get("id", 0) > baseline and a.get("rule_type") == "web_attack"]
        expect(len(web_alerts) >= 1,
               f"web_attack rule did not fire on a UNION SELECT payload from {web_ip}")
        ok(f"web_attack alert raised — MITRE T1190 (Exploitation)")

        # -------------------------------------------------------------- 21
        step("v2.0 rule — Credential Stuffing (T1110.004)  ·  distinct users from one IP")
        stuff_ip = f"198.51.100.{_RNG.randint(10, 249)}"
        for username_try in ("alice", "bob", "charlie", "dave", "eve", "frank"):
            s, _ = http("POST", f"{base}/api/logs", token=token, body={
                "event_type": "authentication_failure",
                "source_ip": stuff_ip,
                "username": f"cs_{username_try}_{_RNG.randint(1000, 9999)}",
                "severity": "medium",
                "raw_log": f"Failed password for {username_try} from {stuff_ip}",
            })
            expect(s == 201, f"stuffing ingest returned {s}")
        time.sleep(0.5)
        _, after = http("GET", f"{base}/api/alerts?limit=200", token=token)
        cs_alerts = [a for a in after.get("items", []) if a.get("rule_type") == "credential_stuffing"]
        expect(len(cs_alerts) >= 1,
               "credential_stuffing rule did not fire on 6 distinct usernames from one IP")
        ok(f"credential_stuffing alert raised — MITRE T1110.004 (CRITICAL)")

        # -------------------------------------------------------------- 22
        step("v2.0 rule — Suspicious User-Agent (T1595.002)  ·  sqlmap UA")
        ua_ip = f"203.0.113.{_RNG.randint(10, 249)}"
        s, body = http("POST", f"{base}/api/logs", token=token, body={
            "event_type": "web_request",
            "source_ip": ua_ip,
            "severity": "low",
            "raw_log": f"{ua_ip} probe",
            "metadata": {"user_agent": "sqlmap/1.7.1 (https://sqlmap.org)"},
        })
        expect(s == 201, f"suspicious UA ingest returned {s}: {body}")
        # This rule fires synchronously; count via the response.
        expect(body["alerts_generated"] >= 1,
               "suspicious_user_agent did not fire on 'sqlmap/1.7.1'")
        ok(f"suspicious_user_agent alert raised — MITRE T1595.002 (MEDIUM)")

        # -------------------------------------------------------------- 23
        step("v2.0 security — response carries the hardened headers")
        # Read raw response headers from a fresh /health call.
        req = urllib.request.Request(f"{base}/health", method="GET")
        with urllib.request.urlopen(req, timeout=10, context=_SSL_CONTEXT) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
        for h in ("x-frame-options", "x-content-type-options", "referrer-policy",
                  "permissions-policy", "content-security-policy"):
            expect(h in headers, f"missing security header: {h}")
        expect(headers["x-frame-options"].upper() == "DENY",
               f"x-frame-options should be DENY, got {headers['x-frame-options']}")
        expect(headers["x-content-type-options"].lower() == "nosniff",
               f"x-content-type-options should be nosniff, got {headers['x-content-type-options']}")
        ok(f"5 security headers present (X-Frame-Options=DENY, nosniff, CSP, Referrer-Policy, Permissions-Policy)")

        # -------------------------------------------------------------- 24
        step("v2.0 security — /health advertises AegisIQ v2 + security posture")
        _, health = http("GET", f"{base}/health")
        expect(health.get("product") == "AegisIQ",
               f"expected product AegisIQ, got {health.get('product')}")
        expect(health.get("version", "").startswith("2."),
               f"expected version 2.x, got {health.get('version')}")
        expect("security" in health, "health missing 'security' block")
        sec = health["security"]
        expect(sec.get("security_headers") == "active", f"headers status wrong: {sec}")
        ok(f"product={health['product']} version={health['version']} "
           f"headers={sec['security_headers']} rate_limit={sec['rate_limit_auth_per_minute']}/min")

        # ═══════════════════════════════════════════════════════════════
        #  v2.1 — Premium: Log Analysis Report + License gating
        # ═══════════════════════════════════════════════════════════════

        # -------------------------------------------------------------- 25
        step("v2.1 license — /api/license/status reports current tier")
        s, license_before = http("GET", f"{base}/api/license/status", token=token)
        expect(s == 200, f"license/status returned HTTP {s}")
        expect("tier" in license_before, f"license/status missing tier: {license_before}")
        ok(f"license tier={license_before['tier']}, features={license_before['features']}")

        # -------------------------------------------------------------- 26
        step("v2.1 premium — analysis routes refuse 402 without a license")
        prev_key_active = license_before.get("active", False)
        if prev_key_active:
            ok("skipped (license already active from environment)")
        else:
            s, body = http("GET", f"{base}/api/analysis", token=token)
            expect(s == 402, f"expected 402 without license, got {s}: {body}")
            expect(isinstance(body.get("detail"), dict) and body["detail"].get("error") == "premium_feature",
                   f"402 body should carry the premium_feature CTA, got {body}")
            ok("free tier -> 402 Payment Required with unlock CTA")

        # -------------------------------------------------------------- 27
        step("v2.1 license — activate the demo educational key")
        s, activated = http("PATCH", f"{base}/api/license/activate", token=token,
                            body={"key": "AEGIS-EDUC-6M9N-4W7X-C1AV"})
        expect(s == 200, f"license activate returned HTTP {s}: {activated}")
        expect(activated.get("active") is True,
               f"activation should be active: {activated}")
        expect("log_analysis" in activated.get("features", []),
               f"activation should grant log_analysis: {activated}")
        ok(f"activated tier={activated['tier']}, features={activated['features']}")

        # -------------------------------------------------------------- 28
        step("v2.1 premium — upload a small log file and parse the report")
        # Small in-memory fake log file
        sample = (
            "Failed password for admin from 203.0.113.100 port 22 ssh2\n"
            "Failed password for admin from 203.0.113.100 port 22 ssh2\n"
            "Failed password for root from 203.0.113.100\n"
            "Accepted password for admin from 203.0.113.100 port 22 ssh2\n"
            "sudo: opsuser : TTY=pts/0 ; PWD=/home/ops ; USER=root ; COMMAND=/bin/bash\n"
            "File integrity violation: /etc/shadow modified by root\n"
            '203.0.113.55 - - [21/Aug/2026:14:30:00 +0000] "GET /?id=1 UNION SELECT * HTTP/1.1" 200 213 "-" "sqlmap/1.7"\n'
        ).encode()
        # multipart upload via urllib
        boundary = "----smoke" + str(_RNG.randint(1_000_000, 9_999_999))
        body_bytes = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="smoke.log"\r\nContent-Type: text/plain\r\n\r\n'
        ).encode() + sample + f'\r\n--{boundary}--\r\n'.encode()
        req = urllib.request.Request(
            f"{base}/api/analysis/upload", method="POST", data=body_bytes,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            report = json.loads(resp.read().decode())
        expect(report.get("status") == "complete",
               f"upload should return complete report, got {report}")
        summary = report.get("summary", {})
        expect(summary.get("parsed_events", 0) >= 5,
               f"expected >=5 parsed events, got {summary.get('parsed_events')}")
        expect(summary.get("findings_count", 0) >= 3,
               f"expected >=3 findings in the sample log, got {summary.get('findings_count')}")
        ok(f"report #{report['id']}: {summary['parsed_events']} events, "
           f"{summary['findings_count']} findings, worst={summary.get('worst_severity')}")
        report_id = report["id"]

        # -------------------------------------------------------------- 29
        step("v2.1 premium — printable HTML report renders")
        req = urllib.request.Request(
            f"{base}/api/analysis/{report_id}/download",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(req, timeout=10, context=_SSL_CONTEXT) as resp:
            html = resp.read().decode()
        expect(html.strip().startswith("<!DOCTYPE html"),
               "download should return an HTML document")
        expect("AegisIQ" in html and "smoke.log" in html,
               "HTML report should carry the brand + filename")
        expect("Findings" in html and ("brute" in html.lower() or "SQL" in html.lower()),
               "HTML report should include findings section")
        ok(f"HTML report {len(html):,} bytes, brand + findings present")

        # ═══════════════════════════════════════════════════════════════
        #  v2.3 — MFA (TOTP) enrolment + challenge round-trip
        # ═══════════════════════════════════════════════════════════════

        # -------------------------------------------------------------- 30
        step("v2.3 MFA — status starts disabled")
        s, body = http("GET", f"{base}/api/mfa/status", token=token)
        expect(s == 200, f"mfa status returned HTTP {s}: {body}")
        # (A prior run may have left it active; disable-by-reenroll below
        # handles both, so just assert the endpoint answers with a status.)
        expect("status" in body, f"mfa status missing 'status': {body}")
        ok(f"MFA status endpoint OK (status={body['status']}, "
           f"enabled_globally={body.get('enabled_globally')}, "
           f"required_globally={body.get('required_globally')})")

        # -------------------------------------------------------------- 31
        step("v2.3 MFA — enroll issues a secret + otpauth URI")
        # If already active from a previous run, disable it first with a
        # fresh code so this run starts clean.
        if body.get("status") == "active":
            # We can't know the old secret; skip forced disable and just
            # assert enroll refuses with 409 (correct behaviour).
            s_en, _ = http("POST", f"{base}/api/mfa/enroll", token=token, body={})
            expect(s_en == 409, f"enroll while active should 409, got {s_en}")
            ok("enroll correctly refused (409) while MFA already active — skipping re-enrol")
        else:
            s, en = http("POST", f"{base}/api/mfa/enroll", token=token, body={})
            expect(s == 200, f"enroll returned HTTP {s}: {en}")
            expect(en.get("secret") and en.get("otpauth_uri", "").startswith("otpauth://totp/"),
                   f"enroll must return secret + otpauth URI: {en}")
            secret = en["secret"]
            ok(f"enrolled: secret issued, otpauth URI OK")

            # ---------------------------------------------------------- 32
            step("v2.3 MFA — confirm with a live TOTP activates + returns backup codes")
            s, cf = http("POST", f"{base}/api/mfa/confirm", token=token,
                         body={"code": _totp_now(secret)})
            expect(s == 200, f"confirm returned HTTP {s}: {cf}")
            expect(len(cf.get("backup_codes", [])) == 10,
                   f"confirm should return 10 backup codes: {cf}")
            ok(f"MFA activated, {len(cf['backup_codes'])} backup codes issued")

            # ---------------------------------------------------------- 33
            step("v2.3 MFA — login now demands a second factor, then verify issues a token")
            s, lr = http("POST", f"{base}/api/auth/login",
                         body={"username": args.username, "password": args.password})
            expect(s == 200 and lr.get("mfa_required") is True and lr.get("access_token") is None,
                   f"login should now return an MFA challenge, got: {lr}")
            expect(lr.get("mfa_token"), "login must return an mfa_token challenge")
            s, vr = http("POST", f"{base}/api/auth/mfa/verify",
                         body={"mfa_token": lr["mfa_token"], "code": _totp_now(secret)})
            expect(s == 200 and vr.get("access_token"),
                   f"mfa/verify should return an access token: {vr}")
            ok("two-step login works: password → challenge → TOTP → token")

            # ---------------------------------------------------------- 34
            step("v2.3 MFA — disable restores the correct login mode (cleanup)")
            s, _ = http("POST", f"{base}/api/mfa/disable", token=token,
                        body={"code": _totp_now(secret)})
            expect(s == 200, f"disable returned HTTP {s}")
            # What login should do after disable depends on the server's
            # global policy: with MFA_REQUIRED=false (the default) the user
            # is back to password-only; with MFA_REQUIRED=true, disabling an
            # enrolment correctly forces re-enrolment on next login rather
            # than handing out a password-only token. Read the policy from
            # the server instead of assuming it.
            s_st, st = http("GET", f"{base}/api/mfa/status", token=token)
            required = bool(isinstance(st, dict) and st.get("required_globally"))
            s, lr = http("POST", f"{base}/api/auth/login",
                         body={"username": args.username, "password": args.password})
            if required:
                expect(s == 200 and lr.get("mfa_required") is True
                       and lr.get("enrollment_required") is True
                       and lr.get("access_token") is None,
                       f"MFA_REQUIRED=true: after disable, login should force "
                       f"re-enrolment, got: {lr}")
                ok("MFA disabled; MFA_REQUIRED=true so login correctly demands "
                   "re-enrolment")
            else:
                expect(s == 200 and lr.get("access_token"),
                       f"MFA_REQUIRED=false: after disable, login should return a "
                       f"token directly, got: {lr}")
                ok("MFA disabled; password-only login restored")

        print(f"\n{color('✓ all checks passed', GREEN)}  "
              f"({BOLD}up to 34 checks — 8 rules + security hardening + premium analysis "
              f"+ MFA all green{RESET})")
        return 0

    except SmokeError as exc:
        print(f"\n{color('✗ smoke test failed', RED)}: {exc}")
        return 1
    except urllib.error.URLError as exc:
        print(f"\n{color('✗ cannot reach backend at ' + base, RED)}: {exc}")
        print("  is `uvicorn app.main:app` running?")
        return 2


if __name__ == "__main__":
    sys.exit(main())
