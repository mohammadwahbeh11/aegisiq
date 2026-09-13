#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# demo_data_render.sh — populate a deployed AegisIQ instance with realistic
# demo data so the dashboard actually shows something on the graduation demo.
#
# Usage:
#     BASE_URL="https://aegisiq-backend.onrender.com" \
#     ADMIN_USER=admin ADMIN_PASS='ChangeMe123!' \
#     bash scripts/demo_data_render.sh
#
# It logs in with the admin account, then POSTs a spread of synthetic log
# events across the built-in detection rules (brute force, port scan, priv-
# esc, malware indicator, data exfil…). All events use SAFE, well-known
# test IPs from TEST-NET / documentation ranges (RFC 5737, RFC 3849) so we
# never accidentally hit a real host, and never a real user's data.
# ---------------------------------------------------------------------------
set -euo pipefail

BASE_URL="${BASE_URL:-https://aegisiq-backend.onrender.com}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:?Set ADMIN_PASS to your admin password}"

echo "▶ Logging in to $BASE_URL as $ADMIN_USER…"
TOKEN=$(curl -fsS -X POST "$BASE_URL/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')

if [ -z "$TOKEN" ]; then
  echo "✗ Login failed. Check ADMIN_USER / ADMIN_PASS." >&2
  exit 1
fi
echo "  ✓ token acquired"

post_event() {
  # $1 = JSON payload
  curl -fsS -X POST "$BASE_URL/api/ingest/event" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "$1" >/dev/null
}

ts_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# --- 1) SSH brute force (6 failed logins from one source) -------------------
echo "▶ Simulating SSH brute force from 203.0.113.42…"
for i in $(seq 1 6); do
  post_event "$(cat <<JSON
{"event_type":"auth_failure","severity":"medium",
 "source_ip":"203.0.113.42","username":"root","hostname":"web-01",
 "timestamp":"$(ts_now)","raw_log":"sshd[$RANDOM]: Failed password for root from 203.0.113.42 port $((30000+RANDOM%20000)) ssh2"}
JSON
)"
  sleep 0.15
done

# --- 2) Port scan (many ports, one source) ---------------------------------
echo "▶ Simulating port scan from 198.51.100.7…"
for port in 21 22 23 25 53 80 110 143 443 445 3306 3389 5900 8080 8443; do
  post_event "$(cat <<JSON
{"event_type":"connection_attempt","severity":"low",
 "source_ip":"198.51.100.7","dest_port":$port,"hostname":"fw-edge",
 "timestamp":"$(ts_now)","raw_log":"iptables: DROP src=198.51.100.7 dst_port=$port proto=tcp flags=SYN"}
JSON
)"
  sleep 0.08
done

# --- 3) Privilege escalation attempt ---------------------------------------
echo "▶ Simulating sudo abuse on prod-db-01…"
post_event "$(cat <<JSON
{"event_type":"privilege_escalation","severity":"high",
 "source_ip":"10.0.0.55","username":"deploy","hostname":"prod-db-01",
 "timestamp":"$(ts_now)","raw_log":"sudo: deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash"}
JSON
)"

# --- 4) Malware indicator (known-bad hash) ---------------------------------
echo "▶ Simulating malware detection on laptop-33…"
post_event "$(cat <<JSON
{"event_type":"malware_detected","severity":"critical",
 "source_ip":"10.0.4.33","username":"j.smith","hostname":"laptop-33",
 "timestamp":"$(ts_now)","raw_log":"AV: quarantined /tmp/loader.exe sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 signature=Trojan.Generic.KDV.999"}
JSON
)"

# --- 5) Suspicious data transfer -------------------------------------------
echo "▶ Simulating data exfiltration…"
post_event "$(cat <<JSON
{"event_type":"data_transfer","severity":"high",
 "source_ip":"10.0.4.33","dest_ip":"203.0.113.99","bytes":524288000,
 "username":"j.smith","hostname":"laptop-33",
 "timestamp":"$(ts_now)","raw_log":"proxy: user=j.smith dst=203.0.113.99 method=POST size=500MB duration=48s"}
JSON
)"

# --- 6) Successful admin login (baseline, not an attack) -------------------
echo "▶ Simulating legitimate admin login…"
post_event "$(cat <<JSON
{"event_type":"auth_success","severity":"low",
 "source_ip":"10.0.0.10","username":"admin","hostname":"console",
 "timestamp":"$(ts_now)","raw_log":"login: admin from 10.0.0.10 (mfa=passed)"}
JSON
)"

echo
echo "✓ Demo data injected."
echo "  Open the dashboard — you should see events, alerts across severities,"
echo "  and SOAR containment actions on the brute-force and malware alerts."
