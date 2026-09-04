#!/usr/bin/env bash
# demo_all_rules.sh -- fire every AegisIQ detection rule against the deployed
# SIEM in one run, straight through the real ingestion API. No target VM, no
# hydra, no SSH. Each scenario sends the raw log lines the normalizer parses,
# so a rule only fires if it genuinely matched -- nothing is inserted directly.
#
# Covers all 8 rules:
#   brute_force (T1110) · login_after_failure (T1078) · port_scan (T1046) ·
#   credential_stuffing (T1110.004) · suspicious_user_agent (T1595.002) ·
#   web_attack (T1190) · privilege_escalation (T1548) · file_integrity (T1098)
#
# All sources are RFC 5737 documentation IPs, tagged source=demo-all-rules.
#
# USAGE
#   export SIEM_PASSWORD='your-render-admin-password'   # never commit / paste in history
#   ./demo_all_rules.sh
#
#   # override target / user if needed:
#   SIEM_URL=https://aegisiq-backend-md69.onrender.com SIEM_USERNAME=admin ./demo_all_rules.sh
set -euo pipefail

SIEM_URL="${SIEM_URL:-https://aegisiq-backend-md69.onrender.com}"
SIEM_USERNAME="${SIEM_USERNAME:-admin}"
# Export so the python3 helpers below can read them from os.environ.
export SIEM_URL SIEM_USERNAME SIEM_PASSWORD

if [[ -z "${SIEM_PASSWORD:-}" ]]; then
  echo "ERROR: set SIEM_PASSWORD first:  export SIEM_PASSWORD='...'" >&2
  exit 1
fi
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }
command -v curl    >/dev/null || { echo "curl required" >&2; exit 1; }

echo "[*] Waking backend..."; curl -fsS --max-time 90 "$SIEM_URL/health" >/dev/null && echo "[+] awake."

echo "[*] Authenticating..."
TOKEN="$(curl -fsS -X POST "$SIEM_URL/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$(python3 -c 'import json,os;print(json.dumps({"username":os.environ["SIEM_USERNAME"],"password":os.environ["SIEM_PASSWORD"]}))')" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')"
[[ -n "$TOKEN" ]] && echo "[+] token acquired." || { echo "auth failed" >&2; exit 1; }

# send <raw_log>  -- posts one event, prints how many alerts it raised.
send() {
  local raw="$1"
  local body alerts
  body="$(python3 -c 'import json,sys;print(json.dumps({"raw_log":sys.argv[1],"hostname":"demo-target","source":"demo-all-rules"}))' "$raw")"
  alerts="$(curl -fsS -X POST "$SIEM_URL/api/logs" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "$body" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("alerts_generated",0))' 2>/dev/null || echo 0)"
  if [[ "$alerts" -gt 0 ]]; then echo "    ** $alerts ALERT(S) **  ${raw:0:70}"; else echo "    (no alert)      ${raw:0:70}"; fi
  sleep 0.25
}
phase() { echo; echo "── $1 ─────────────────────────────────────────"; }

# Unique RFC 5737 documentation sources so dedup keys stay separate.
A_BRUTE="198.51.100.$((RANDOM%40+10))"
A_SCAN="198.51.100.$((RANDOM%40+60))"
A_STUFF="203.0.113.$((RANDOM%40+10))"
A_WEB="203.0.113.$((RANDOM%40+60))"

phase "1/8  Brute Force  (T1110)"
for i in $(seq 1 6); do send "Failed password for invalid user admin from $A_BRUTE port 22 ssh2"; done

phase "2/8  Login After Repeated Failures  (T1078)"
for i in $(seq 1 5); do send "Failed password for root from $A_SCAN port 22 ssh2"; done
send "Accepted password for root from $A_SCAN port 22 ssh2"

phase "3/8  Port Scan  (T1046)"
for p in 21 22 23 25 53 80 110 135 139 143 443 445; do send "Connection attempt from $A_SCAN to port $p"; done

phase "4/8  Credential Stuffing  (T1110.004)  -- many usernames, one source"
for u in alice bob carol dave erin frank; do send "Failed password for invalid user $u from $A_STUFF port 22 ssh2"; done

phase "5/8  Suspicious User-Agent  (T1595.002)  -- sqlmap"
send "$A_WEB - - [10/Oct/2026:14:00:00 +0000] \"GET /admin HTTP/1.1\" 200 1024 \"-\" \"sqlmap/1.7-dev\""

phase "6/8  Web Attack  (T1190)  -- SQL injection"
send "$A_WEB - - [10/Oct/2026:14:00:05 +0000] \"GET /products?id=1 UNION SELECT username,password FROM users HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\""

phase "7/8  Privilege Escalation  (T1548)  -- sudo to root shell"
send "sudo:   attacker : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash"
send "sudo:   attacker : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/usr/sbin/visudo"

phase "8/8  File Integrity  (T1098)  -- critical files tampered"
send "File integrity violation: /etc/passwd modified by attacker"
send "File integrity violation: /etc/shadow modified by attacker"

echo
echo "======================================================================"
echo "[+] Done. Open the console and review the alerts + Kill Chain view:"
echo "      https://aegisiq-frontend.onrender.com"
echo "======================================================================"
