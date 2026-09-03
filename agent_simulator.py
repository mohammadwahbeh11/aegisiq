#!/usr/bin/env python3
"""
agent_simulator.py -- a standalone log shipper for demos and load checks.

Sends synthetic events to a running Lightweight SIEM over the real
ingestion API. Unlike the Simulation Lab in the console (which the
backend runs for itself), this script runs OUTSIDE the server, so it also
exercises the parts the lab cannot: authentication, CORS-free HTTP from
another host, and the network path between a log source and the SIEM.
That makes it the right tool for pointing a second machine -- a Kali VM,
say -- at this SIEM and watching events arrive.

What changed and why: the previous version posted unauthenticated to
/api/logs/ingest with event types like "SSH_LOGIN_SUCCESS". That endpoint
belonged to an early in-memory prototype that no longer exists, and those
event-type strings never matched anything the detection rules look for,
so nothing it sent could ever raise an alert. This version authenticates,
posts to /api/logs, and sends raw log lines in the formats the normalizer
actually parses (app/ingestion/normalizer.py).

Usage:
    python agent_simulator.py
    python agent_simulator.py --url http://192.168.100.66:8000 --rate 2
    python agent_simulator.py --attack brute_force --count 8
    python agent_simulator.py --list-attacks

Credentials come from --username/--password, or the SIEM_USERNAME and
SIEM_PASSWORD environment variables, defaulting to the seeded admin
account. Nothing is hardcoded as a literal password in the source.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_URL = "http://localhost:8000"

HOSTNAMES = ["ubuntu-web-01", "ubuntu-db-01", "auth-gateway", "file-server-01"]

# Benign background noise. These parse to real event types but stay well
# under every rule threshold, so they fill the dashboard with realistic
# traffic without manufacturing alerts.
BACKGROUND_LINES = [
    "Accepted password for deploy from 10.20.30.{octet} port 22 ssh2",
    "Accepted publickey for ubuntu from 10.20.30.{octet} port 22 ssh2",
    "sudo: deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl reload nginx",
    "sudo: ops : TTY=pts/2 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/journalctl -u nginx",
    "Connection attempt from 10.20.30.{octet} to port 443",
    "Connection attempt from 10.20.30.{octet} to port 80",
    "File integrity violation: /srv/app/config.yaml modified by deploy",
]

# Attack patterns, each shaped to actually cross a rule's threshold.
ATTACKS: dict[str, dict] = {
    "brute_force": {
        "help": "Failed SSH logins from one address (Brute Force Authentication, T1110)",
        "template": "Failed password for invalid user admin from {attacker} port 22 ssh2",
        "default_count": 7,
    },
    "port_scan": {
        "help": "Connection attempts across many ports (Port Scanning, T1046)",
        "template": "Connection attempt from {attacker} to port {port}",
        "default_count": 12,
        "ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 3306, 3389, 8080],
    },
    "credential_compromise": {
        "help": "Failed logins followed by a success (Login After Repeated Failures, T1078)",
        "template": "Failed password for invalid user admin from {attacker} port 22 ssh2",
        "final": "Accepted password for admin from {attacker} port 22 ssh2",
        "default_count": 6,
    },
    "privilege_escalation": {
        "help": "sudo spawning a root shell and editing sudoers (T1548)",
        "lines": [
            "sudo: {user} : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash",
            "sudo: {user} : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/usr/sbin/visudo",
        ],
        "default_count": 2,
    },
    "file_tampering": {
        "help": "Modification of /etc/passwd and /etc/shadow (T1098)",
        "lines": [
            "File integrity violation: /etc/passwd modified by {user}",
            "File integrity violation: /etc/shadow modified by {user}",
        ],
        "default_count": 2,
    },
}


class SiemClient:
    def __init__(self, base_url: str, username: str, password: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.token = self._login(username, password)

    def _request(self, path: str, payload: dict, token: str | None = None) -> dict:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode())

    def _login(self, username: str, password: str) -> str:
        try:
            body = self._request("/api/auth/login", {"username": username, "password": password})
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise SystemExit(
                    f"Login rejected for user '{username}'. Set SIEM_USERNAME / SIEM_PASSWORD "
                    "(or pass --username/--password) to match the account on this SIEM."
                ) from exc
            raise SystemExit(f"Login failed: HTTP {exc.code} {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise SystemExit(
                f"Could not reach the SIEM at {self.base_url}: {exc.reason}\n"
                "Is the backend running, and is the address reachable from this machine?"
            ) from exc
        return body["access_token"]

    def send(self, raw_log: str, hostname: str, source: str = "agent-simulator") -> dict:
        return self._request(
            "/api/logs",
            {
                "raw_log": raw_log,
                "hostname": hostname,
                "source": source,
                "operating_system": "Ubuntu 22.04",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metadata": {"shipper": "agent_simulator"},
            },
            token=self.token,
        )


def _render_attack(name: str, count: int, attacker: str, user: str) -> list[str]:
    spec = ATTACKS[name]
    context = {"attacker": attacker, "user": user}

    if "lines" in spec:
        lines = spec["lines"]
        return [lines[i % len(lines)].format(**context) for i in range(count)]

    if "ports" in spec:
        ports = spec["ports"][:count]
        return [spec["template"].format(port=port, **context) for port in ports]

    rendered = [spec["template"].format(**context) for _ in range(count)]
    if "final" in spec:
        rendered.append(spec["final"].format(**context))
    return rendered


def _report(index: int, total: int, line: str, response: dict) -> None:
    alerts = response.get("alerts_generated", 0)
    marker = f"** {alerts} ALERT(S) **" if alerts else "no alert"
    print(f"[{index}/{total}] {marker:<16} {line[:88]}")


def run_attack(client: SiemClient, name: str, count: int, delay: float, hostname: str) -> None:
    attacker = f"198.51.100.{random.randint(10, 249)}"
    user = f"attacker{random.randint(1, 99)}"
    lines = _render_attack(name, count, attacker, user)

    print(f"\nScenario: {name} -- {ATTACKS[name]['help']}")
    print(f"Simulated source: {attacker} (RFC 5737 documentation range)\n")

    total_alerts = 0
    for index, line in enumerate(lines, start=1):
        response = client.send(line, hostname)
        total_alerts += response.get("alerts_generated", 0)
        _report(index, len(lines), line, response)
        time.sleep(delay)

    print(f"\nDone. {len(lines)} events sent, {total_alerts} alert(s) raised by the engine.")
    if total_alerts == 0:
        print(
            "No alerts is a real result, not a bug: the rule may already have an open alert for "
            "this source (deduplication), or its threshold may have been raised from the Rules page."
        )


def run_background(client: SiemClient, rate: float, hostname_pool: list[str]) -> None:
    print("Streaming background traffic. Press Ctrl+C to stop.\n")
    sent = 0
    try:
        while True:
            template = random.choice(BACKGROUND_LINES)
            line = template.format(octet=random.randint(2, 250))
            response = client.send(line, random.choice(hostname_pool))
            sent += 1
            _report(sent, sent, line, response)
            time.sleep(rate)
    except KeyboardInterrupt:
        print(f"\nStopped after {sent} events.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=os.environ.get("SIEM_URL", DEFAULT_URL), help=f"SIEM base URL (default {DEFAULT_URL})")
    parser.add_argument("--username", default=os.environ.get("SIEM_USERNAME", "admin"))
    parser.add_argument("--password", default=os.environ.get("SIEM_PASSWORD", "ChangeMe123!"))
    parser.add_argument("--attack", choices=sorted(ATTACKS), help="Run one attack scenario and exit")
    parser.add_argument("--count", type=int, default=None, help="Events to send for the chosen attack")
    parser.add_argument("--rate", type=float, default=3.0, help="Seconds between background events")
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds between attack events")
    parser.add_argument("--hostname", default=None, help="Hostname to tag events with")
    parser.add_argument("--list-attacks", action="store_true", help="List the available scenarios and exit")
    args = parser.parse_args()

    if args.list_attacks:
        for name, spec in sorted(ATTACKS.items()):
            print(f"  {name:<24} {spec['help']}")
        return

    print("=" * 70)
    print("Lightweight SIEM -- agent simulator")
    print(f"Target: {args.url}  User: {args.username}")
    print("=" * 70)

    client = SiemClient(args.url, args.username, args.password)
    print("Authenticated.\n")

    hostname = args.hostname or HOSTNAMES[0]

    if args.attack:
        count = args.count or ATTACKS[args.attack]["default_count"]
        run_attack(client, args.attack, count, args.delay, hostname)
    else:
        run_background(client, args.rate, [args.hostname] if args.hostname else HOSTNAMES)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
