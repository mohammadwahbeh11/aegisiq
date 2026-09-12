#!/usr/bin/env python3
"""
agent/kill_switch_agent.py -- AegisIQ Kill Switch endpoint agent.

Runs on each protected Linux endpoint (Debian/Ubuntu/Kali). Listens on
a private port for HMAC-signed commands from the AegisIQ backend and
executes them via iptables/usermod. Purpose: cut an attacker's
connection within one second of detection instead of waiting minutes
for a human to SSH in and type the rule.

Security model
--------------
* Every request must carry `X-AegisIQ-Signature: sha256=<hex>` computed
  as HMAC-SHA256(SHARED_SECRET, raw_body). Unsigned or wrong-signature
  requests get 401.
* Commands are constrained by an ALLOWLIST -- only `block_ip` and
  `disable_user` are executed. Anything else returns 400.
* Payload includes a `timestamp` field; commands older than
  MAX_CLOCK_SKEW_SECONDS are rejected (replay protection).
* Actions are logged to a local audit file for offline forensics.

Deployment
----------
  sudo python3 kill_switch_agent.py --port 9999 \
      --secret-file /etc/aegisiq/shared_secret

The shared secret MUST match the backend's SOAR_WEBHOOK_HMAC_SECRET env
var. Rotate it periodically.

NOT for internet exposure -- bind to the management VLAN or use an SSH
tunnel from the backend host. This agent is the trust root on the
endpoint; treat its port like SSH.

Stdlib only -- no pip install on the endpoint. Runs on Python 3.8+.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

# ── Configuration (overridable via CLI flags) ────────────────────────────
DEFAULT_PORT = 9999
MAX_BODY_BYTES = 4096                  # commands are tiny; reject bloat
MAX_CLOCK_SKEW_SECONDS = 60            # replay protection window
AUDIT_LOG_PATH = "/var/log/aegisiq-killswitch.log"

# Allowed actions. Adding a new one requires reviewing its safety first
# -- e.g. `reset_password` would need a password-rotation workflow, not
# a naked `passwd` call.
ALLOWED_ACTIONS = {"block_ip", "unblock_ip", "disable_user", "status"}

# ── Shared secret loaded at startup ──────────────────────────────────────
SHARED_SECRET: bytes = b""

# ── Logger ───────────────────────────────────────────────────────────────
log = logging.getLogger("aegisiq.killswitch")


# ── Command executors ────────────────────────────────────────────────────
def _run(cmd: list[str], check: bool = True) -> tuple[int, str, str]:
    """Wrapper around subprocess.run with logging."""
    log.info("EXEC: %s", " ".join(cmd))
    result = subprocess.run(
        cmd, capture_output=True, text=True, check=False, timeout=10
    )
    if check and result.returncode != 0:
        log.error("EXEC failed rc=%d stderr=%s", result.returncode, result.stderr)
    return result.returncode, result.stdout, result.stderr


def action_block_ip(payload: dict) -> dict:
    """Insert an iptables DROP rule at the top of INPUT for the target."""
    target = payload.get("target_ip", "").strip()
    if not target or not _looks_like_ip(target):
        return {"status": "error", "reason": "invalid target_ip"}
    # -I INPUT 1 puts it at the top so it wins against later ACCEPT rules
    rc, _, err = _run(
        ["iptables", "-I", "INPUT", "1", "-s", target, "-j", "DROP"],
        check=False,
    )
    if rc != 0:
        return {"status": "error", "reason": err.strip() or f"iptables rc={rc}"}
    return {"status": "blocked", "target": target}


def action_unblock_ip(payload: dict) -> dict:
    """Remove any DROP rule for the target from INPUT."""
    target = payload.get("target_ip", "").strip()
    if not target or not _looks_like_ip(target):
        return {"status": "error", "reason": "invalid target_ip"}
    # -D deletes; loop until no matching rule remains (in case of dupes)
    removed = 0
    while True:
        rc, _, _ = _run(
            ["iptables", "-D", "INPUT", "-s", target, "-j", "DROP"],
            check=False,
        )
        if rc != 0:
            break
        removed += 1
        if removed > 20:
            break  # safety cap
    return {"status": "unblocked", "target": target, "rules_removed": removed}


def action_disable_user(payload: dict) -> dict:
    """Lock a Unix account so it cannot log in."""
    user = payload.get("target_user", "").strip()
    if not user or not user.isidentifier():
        return {"status": "error", "reason": "invalid target_user"}
    rc, _, err = _run(["usermod", "-L", user], check=False)
    if rc != 0:
        return {"status": "error", "reason": err.strip() or f"usermod rc={rc}"}
    # Also kill live sessions of that user so an existing SSH tunnel is severed
    _run(["pkill", "-KILL", "-u", user], check=False)
    return {"status": "disabled", "target": user}


def action_status(payload: dict) -> dict:
    """Simple ping-pong to prove the agent is alive and the secret matches."""
    return {
        "status": "alive",
        "agent_version": "1.0.0",
        "python": sys.version.split()[0],
        "iptables_available": _run(["which", "iptables"], check=False)[0] == 0,
    }


ACTION_HANDLERS = {
    "block_ip":     action_block_ip,
    "unblock_ip":   action_unblock_ip,
    "disable_user": action_disable_user,
    "status":       action_status,
}


def _looks_like_ip(s: str) -> bool:
    """Very light IPv4/IPv6 sanity check -- iptables validates properly."""
    if ":" in s and all(c in "0123456789abcdefABCDEF:./" for c in s):
        return True
    parts = s.split("/")[0].split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# ── HMAC verification ────────────────────────────────────────────────────
def verify_signature(body: bytes, signature_header: str) -> bool:
    """Constant-time compare of HMAC-SHA256(SHARED_SECRET, body)."""
    if not signature_header.startswith("sha256="):
        return False
    received = signature_header[len("sha256="):].strip()
    expected = hmac.new(SHARED_SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(received, expected)


def verify_freshness(payload: dict) -> bool:
    """Reject commands older than MAX_CLOCK_SKEW_SECONDS (replay protection)."""
    try:
        sent_at = float(payload.get("timestamp", 0))
    except (TypeError, ValueError):
        return False
    return abs(time.time() - sent_at) <= MAX_CLOCK_SKEW_SECONDS


# ── HTTP handler ─────────────────────────────────────────────────────────
class KillSwitchHandler(BaseHTTPRequestHandler):
    server_version = "AegisIQ-KillSwitch/1.0"

    def _respond(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802  (stdlib naming)
        # 1. size guard
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_BODY_BYTES:
            return self._respond(413, {"error": "payload too large"})
        body = self.rfile.read(length)

        # 2. signature check
        sig = self.headers.get("X-AegisIQ-Signature", "")
        if not verify_signature(body, sig):
            log.warning("REJECT: bad signature from %s", self.client_address[0])
            return self._respond(401, {"error": "invalid signature"})

        # 3. parse payload
        try:
            payload = json.loads(body)
            if not isinstance(payload, dict):
                raise ValueError("payload not an object")
        except (json.JSONDecodeError, ValueError) as e:
            return self._respond(400, {"error": f"bad json: {e}"})

        # 4. freshness (replay protection)
        if not verify_freshness(payload):
            log.warning("REJECT: stale timestamp from %s", self.client_address[0])
            return self._respond(401, {"error": "timestamp too old or missing"})

        # 5. action allowlist
        action = payload.get("action", "")
        if action not in ALLOWED_ACTIONS:
            return self._respond(400, {"error": f"unknown action: {action}"})

        # 6. execute
        try:
            handler = ACTION_HANDLERS[action]
            result = handler(payload)
        except Exception as e:  # noqa: BLE001  -- never crash the agent
            log.exception("action %s raised", action)
            return self._respond(500, {"error": "internal", "detail": str(e)})

        # 7. audit
        log.info("ACTION %s payload=%s result=%s",
                 action,
                 {k: v for k, v in payload.items() if k != "timestamp"},
                 result)

        status_code = 200 if result.get("status") not in ("error",) else 400
        return self._respond(status_code, result)

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        # Reroute stdlib access log to our logger (with client IP)
        log.info("%s - %s", self.client_address[0], fmt % args)


# ── Entrypoint ───────────────────────────────────────────────────────────
def load_secret(path: str) -> bytes:
    if not os.path.isfile(path):
        raise SystemExit(f"secret file not found: {path}")
    with open(path, "rb") as f:
        secret = f.read().strip()
    if len(secret) < 16:
        raise SystemExit("secret must be at least 16 bytes")
    return secret


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="listen port (default 9999)")
    parser.add_argument("--bind", default="0.0.0.0",
                        help="bind address (default 0.0.0.0 -- restrict at firewall)")
    parser.add_argument("--secret-file", default="/etc/aegisiq/shared_secret",
                        help="path to file containing the shared HMAC secret")
    parser.add_argument("--audit-log", default=AUDIT_LOG_PATH,
                        help="path to local audit log")
    args = parser.parse_args()

    # Set up logging: stdout + file
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [killswitch] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(args.audit_log, mode="a"),
        ],
    )

    global SHARED_SECRET
    SHARED_SECRET = load_secret(args.secret_file)

    log.info("AegisIQ Kill Switch starting on %s:%d", args.bind, args.port)
    log.info("Shared secret loaded (%d bytes)", len(SHARED_SECRET))
    log.info("Allowed actions: %s", sorted(ALLOWED_ACTIONS))

    try:
        server = HTTPServer((args.bind, args.port), KillSwitchHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutdown requested")
        return 0
    except Exception:
        log.exception("fatal")
        return 1


if __name__ == "__main__":
    sys.exit(main())
