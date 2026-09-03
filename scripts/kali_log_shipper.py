#!/usr/bin/env python3
"""
scripts/kali_log_shipper.py -- run this ON the Linux/Kali box, not on the
SIEM host.

Tails a real log file (default /var/log/auth.log) and ships each new line
to the Lightweight SIEM's ingestion API. This is what turns the project
from "a SIEM that analyses events it generated itself" into "a SIEM
watching a real machine": run this on the target, launch a real attack
against that target from Kali, and the alerts in the console come from
genuine sshd/sudo output.

It ships raw lines and lets the SIEM's normalizer parse them
(app/ingestion/normalizer.py), rather than parsing on the endpoint --
keeping the shipper trivial, and keeping one parser to reason about.

Typical lab setup
-----------------
  SIEM host (Windows, this repo)  ->  http://192.168.100.66:8000
  Target    (Ubuntu/Kali VM)      ->  runs this script against its own auth.log
  Attacker  (Kali)                ->  runs the attack at the target

On the target:
    sudo python3 kali_log_shipper.py \
        --url http://192.168.100.66:8000 \
        --file /var/log/auth.log \
        --hostname ubuntu-web-01

From the attacker box, real traffic (hydra, nmap, sudo abuse) hits the
target; its auth.log grows; this shipper forwards each new line and the
alerts appear in the SIEM console within a second or two.

Stdlib only -- no pip install on the target. Works over http or https
(https uses the system trust store; pass --insecure for a self-signed
SIEM cert).

Usage
-----
    python3 kali_log_shipper.py --url http://SIEM:8000 \
        --username admin --password ChangeMe123! \
        --file /var/log/auth.log --hostname ubuntu-web-01

    # ship the whole file first, then follow (default is follow-only,
    # i.e. only NEW lines appended after start):
    python3 kali_log_shipper.py ... --from-start

Ctrl-C to stop.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request


def _die(msg: str, code: int = 1) -> "None":
    print(f"[shipper] ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def _ctx(insecure: bool) -> "ssl.SSLContext | None":
    if not insecure:
        return None
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _post(url: str, payload: dict, token: str | None, ctx) -> tuple[int, dict]:
    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, method="POST", headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            raw = resp.read().decode() or "{}"
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, {"raw": raw}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode() or "{}"
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


def login(base: str, username: str, password: str, ctx) -> str:
    """Exchange (username, password) for a JWT. Fails loudly if the SIEM
    requires MFA for this account -- an unattended shipper can't do the
    second factor, so use a dedicated non-MFA ingestion account."""
    status, body = _post(
        f"{base}/api/auth/login",
        {"username": username, "password": password},
        None,
        ctx,
    )
    if status != 200:
        _die(f"login failed (HTTP {status}): {body}")
    if body.get("mfa_required") or "access_token" not in body:
        _die(
            "this account requires MFA; the shipper cannot complete a second "
            "factor. Create a dedicated ingestion account without MFA, or "
            "disable MFA for it."
        )
    return body["access_token"]


def follow(path: str, from_start: bool):
    """Generator yielding new lines from a growing file, handling rotation
    (truncation / inode change) the way `tail -F` does."""
    while not os.path.exists(path):
        print(f"[shipper] waiting for {path} to appear...")
        time.sleep(2)
    fh = open(path, "r", errors="replace")
    if not from_start:
        fh.seek(0, os.SEEK_END)
    inode = os.fstat(fh.fileno()).st_ino
    while True:
        line = fh.readline()
        if line:
            yield line.rstrip("\n")
            continue
        time.sleep(0.5)
        # Detect rotation: file replaced (new inode) or truncated.
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue
        if st.st_ino != inode or st.st_size < fh.tell():
            try:
                fh.close()
            except Exception:
                pass
            fh = open(path, "r", errors="replace")
            inode = os.fstat(fh.fileno()).st_ino


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("SIEM_URL", "http://localhost:8000"),
                    help="SIEM base URL (default: env SIEM_URL or http://localhost:8000)")
    ap.add_argument("--file", default="/var/log/auth.log",
                    help="log file to tail (default: /var/log/auth.log)")
    ap.add_argument("--hostname", default=os.uname().nodename if hasattr(os, "uname") else "unknown",
                    help="hostname to tag shipped events with (default: this box)")
    ap.add_argument("--username", default=os.environ.get("SIEM_USERNAME", "admin"))
    ap.add_argument("--password", default=os.environ.get("SIEM_PASSWORD", "ChangeMe123!"))
    ap.add_argument("--source", default="kali-shipper",
                    help="source tag stored on each event")
    ap.add_argument("--from-start", action="store_true",
                    help="ship the whole file first, then follow (default: only new lines)")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS verification (self-signed SIEM cert)")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    ctx = _ctx(args.insecure)
    if base.lower().startswith("https") and not args.insecure:
        print("[shipper] https: verifying SIEM cert with the system trust store "
              "(pass --insecure for a self-signed cert)")

    token = login(base, args.username, args.password, ctx)
    print(f"[shipper] authenticated to {base} as {args.username}")
    print(f"[shipper] tailing {args.file} (host={args.hostname}); Ctrl-C to stop")

    ingest = f"{base}/api/logs"
    sent = 0
    try:
        for line in follow(args.file, args.from_start):
            if not line.strip():
                continue
            payload = {
                "raw_log": line,
                "hostname": args.hostname,
                "source": args.source,
                "operating_system": "Linux",
            }
            status, body = _post(ingest, payload, token, ctx)
            if status == 401:
                # token expired -> re-auth once and retry
                token = login(base, args.username, args.password, ctx)
                status, body = _post(ingest, payload, token, ctx)
            if status not in (200, 201):
                print(f"[shipper] WARN ship failed (HTTP {status}): {body}",
                      file=sys.stderr)
                time.sleep(1)
                continue
            sent += 1
            if sent % 25 == 0:
                print(f"[shipper] shipped {sent} lines")
    except KeyboardInterrupt:
        print(f"\n[shipper] stopped. shipped {sent} lines total.")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
