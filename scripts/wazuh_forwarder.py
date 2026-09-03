#!/usr/bin/env python3
"""
scripts/wazuh_forwarder.py -- ship Wazuh Manager alerts into this SIEM.

Context: docs/architecture.md explains why this project runs a native
lightweight core instead of the full Wazuh + Elasticsearch + Kibana
stack, and treats Wazuh as an OPTIONAL upstream. There are two ways this
SIEM can consume a real Wazuh deployment:

  * PULL agents on demand for the Endpoints page -- built into the
    backend, see app/integrations/wazuh.py; needs only WAZUH_URL etc. in
    .env.

  * PUSH Wazuh's own alerts in as events -- this script. Run it on (or
    near) the Wazuh Manager. It tails the manager's alerts.json, maps
    each Wazuh alert to a raw log line this SIEM's normalizer understands,
    and posts it to /api/logs. From there it flows through the same
    detection + SOAR + live-broadcast pipeline as any other event.

This is deliberately a small, dependency-light tailer (standard library
only) rather than a Filebeat module: it has to run on a lab VM without
extra packages, and the mapping it performs is easy to read and adjust.

Usage (on the Wazuh Manager, or anywhere that can read alerts.json):
    export SIEM_URL=http://192.168.56.1:8000
    export SIEM_USERNAME=admin
    export SIEM_PASSWORD='ChangeMe123!'
    python3 wazuh_forwarder.py --alerts /var/ossec/logs/alerts/alerts.json
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request

DEFAULT_ALERTS = "/var/ossec/logs/alerts/alerts.json"


def login(base_url: str, username: str, password: str) -> str:
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/auth/login",
        data=json.dumps({"username": username, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode())["access_token"]


def _to_raw_log(alert: dict) -> str | None:
    """Map a Wazuh alert to a line this SIEM's normalizer parses, or the
    original full-log text when Wazuh already captured it. Returns None to
    skip alerts that carry nothing useful to forward."""
    full_log = alert.get("full_log")
    if isinstance(full_log, str) and full_log.strip():
        # Wazuh usually preserves the original syslog line -- the best
        # possible input, because it is exactly what the normalizer's
        # Linux patterns were written against.
        return full_log.strip()

    # Fall back to reconstructing a recognizable line from Wazuh's parsed
    # fields for the rule groups this SIEM has detection for.
    data = alert.get("data", {})
    src_ip = data.get("srcip")
    src_user = data.get("srcuser") or data.get("dstuser")
    groups = alert.get("rule", {}).get("groups", [])

    if "authentication_failed" in groups and src_ip:
        return f"Failed password for {src_user or 'invalid user'} from {src_ip} port 22 ssh2"
    if "authentication_success" in groups and src_ip:
        return f"Accepted password for {src_user or 'user'} from {src_ip} port 22 ssh2"
    return None


def forward(base_url: str, token: str, raw_log: str, hostname: str) -> int:
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/logs",
        data=json.dumps(
            {
                "raw_log": raw_log,
                "hostname": hostname,
                "source": "wazuh",
                "operating_system": "Linux",
            }
        ).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode()).get("alerts_generated", 0)


def tail(path: str):
    """Yield JSON alert objects appended to alerts.json, following the
    file like `tail -f`. alerts.json is one JSON object per line."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        handle.seek(0, 2)  # start at the end -- only forward NEW alerts
        buffer = ""
        while True:
            line = handle.readline()
            if not line:
                time.sleep(0.5)
                continue
            buffer += line
            try:
                alert = json.loads(buffer)
                buffer = ""
                yield alert
            except json.JSONDecodeError:
                # A multi-line alert object -- keep accumulating.
                continue


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--alerts", default=DEFAULT_ALERTS, help=f"Path to alerts.json (default {DEFAULT_ALERTS})")
    parser.add_argument("--url", default=os.environ.get("SIEM_URL", "http://localhost:8000"))
    parser.add_argument("--username", default=os.environ.get("SIEM_USERNAME", "admin"))
    parser.add_argument("--password", default=os.environ.get("SIEM_PASSWORD", "ChangeMe123!"))
    args = parser.parse_args()

    if not os.path.exists(args.alerts):
        raise SystemExit(
            f"Alerts file not found: {args.alerts}\n"
            "Run this on the Wazuh Manager, or point --alerts at a copy of alerts.json."
        )

    token = login(args.url, args.username, args.password)
    print(f"[+] Authenticated to {args.url}. Tailing {args.alerts} ...")

    forwarded = 0
    for alert in tail(args.alerts):
        raw_log = _to_raw_log(alert)
        if raw_log is None:
            continue
        hostname = alert.get("agent", {}).get("name", "wazuh-agent")
        try:
            alerts_generated = forward(args.url, token, raw_log, hostname)
        except urllib.error.HTTPError as exc:
            if exc.code == 401:  # token expired during a long run
                token = login(args.url, args.username, args.password)
                continue
            print(f"[-] Forward failed: HTTP {exc.code}")
            continue
        forwarded += 1
        marker = f"** {alerts_generated} alert(s) **" if alerts_generated else ""
        print(f"[{forwarded}] {raw_log[:80]} {marker}")


if __name__ == "__main__":
    main()
