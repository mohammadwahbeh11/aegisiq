#!/usr/bin/env bash
#
# scripts/kali_attack.sh -- drive REAL attack tooling from a Kali box
# against a target, so the Lightweight SIEM detects genuine traffic
# rather than replayed log lines.
#
# There are two honest ways to get real attacks into this SIEM, because
# the SIEM ingests LOGS, not raw packets -- it is not an IDS sniffing the
# wire. Pick the one that matches your lab:
#
#   Mode A (recommended, no agent needed): run the attack against the
#   target, then have THIS script read the target's auth log over SSH and
#   forward the matching lines to the SIEM. The events are real (hydra
#   really did fail those logins), and the SIEM parses them exactly as it
#   would from any log shipper.
#
#   Mode B (target ships its own logs): install a forwarder on the target
#   (see scripts/wazuh_forwarder.py or a filebeat->HTTP shim) and this
#   script only launches the attack; the target delivers its own logs.
#
# This script implements Mode A. It is meant for an authorized lab where
# you own both machines. Do not point it at anything you do not have
# permission to test.
#
# Usage:
#   ./kali_attack.sh --target 192.168.56.20 --siem http://192.168.56.1:8000 \
#       --siem-user admin --siem-pass 'ChangeMe123!' \
#       --ssh-user analyst --attack brute_force
#
set -euo pipefail

TARGET=""
SIEM="http://192.168.56.1:8000"
SIEM_USER="admin"
SIEM_PASS="${SIEM_PASSWORD:-ChangeMe123!}"
SSH_USER=""
ATTACK="brute_force"

usage() {
  grep '^#' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)    TARGET="$2"; shift 2;;
    --siem)      SIEM="$2"; shift 2;;
    --siem-user) SIEM_USER="$2"; shift 2;;
    --siem-pass) SIEM_PASS="$2"; shift 2;;
    --ssh-user)  SSH_USER="$2"; shift 2;;
    --attack)    ATTACK="$2"; shift 2;;
    -h|--help)   usage 0;;
    *) echo "Unknown option: $1" >&2; usage 1;;
  esac
done

[[ -z "$TARGET" ]] && { echo "ERROR: --target is required" >&2; usage 1; }

echo "[*] SIEM:   $SIEM"
echo "[*] Target: $TARGET"
echo "[*] Attack: $ATTACK"

# --- 1. Authenticate to the SIEM ------------------------------------------
echo "[*] Authenticating to the SIEM..."
TOKEN=$(curl -fsS -X POST "$SIEM/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$SIEM_USER\",\"password\":\"$SIEM_PASS\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])') || {
    echo "ERROR: could not authenticate to the SIEM at $SIEM" >&2
    exit 1
  }
echo "[+] Got an access token."

forward_line() {
  # Forwards one raw log line to the SIEM and prints whether it alerted.
  local line="$1"
  curl -fsS -X POST "$SIEM/api/logs" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "$(python3 - "$line" "$TARGET" <<'PY'
import json, sys
print(json.dumps({
    "raw_log": sys.argv[1],
    "hostname": sys.argv[2],
    "source": "kali-attack",
    "operating_system": "Linux",
}))
PY
)" >/dev/null && echo "    forwarded: ${line:0:80}"
}

# --- 2. Launch the attack --------------------------------------------------
case "$ATTACK" in
  brute_force)
    echo "[*] Running an SSH brute force with hydra (expects failures)..."
    if command -v hydra >/dev/null; then
      # A tiny wordlist of deliberately wrong passwords: the point is to
      # GENERATE failed-login events, not to actually break in.
      printf 'password\n123456\nadmin\nletmein\nroot\nqwerty\nchangeme\n' > /tmp/siem_demo_wordlist.txt
      hydra -l admin -P /tmp/siem_demo_wordlist.txt -t 4 -f \
        "ssh://$TARGET" || true
    else
      echo "    hydra not found; falling back to raw ssh attempts."
      for i in $(seq 1 7); do
        ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
          "wrong_user_$i@$TARGET" true 2>/dev/null || true
      done
    fi
    ;;
  port_scan)
    echo "[*] Running an nmap port scan..."
    command -v nmap >/dev/null || { echo "ERROR: nmap not installed" >&2; exit 1; }
    nmap -Pn -p 1-1000 "$TARGET" || true
    ;;
  *)
    echo "ERROR: unknown --attack '$ATTACK' (brute_force|port_scan)" >&2
    exit 1
    ;;
esac

# --- 3. Ship the target's fresh auth log to the SIEM -----------------------
if [[ -n "$SSH_USER" ]]; then
  echo "[*] Reading the target's auth log over SSH and forwarding matches..."
  # Pull the tail of the auth log and forward only the lines the SIEM's
  # normalizer understands. This is what turns a real attack into events
  # the detection engine actually evaluates.
  ssh -o StrictHostKeyChecking=no "$SSH_USER@$TARGET" \
    'sudo tail -n 200 /var/log/auth.log 2>/dev/null || tail -n 200 /var/log/secure' \
    | grep -E 'Failed password|Accepted password|Connection attempt|sudo:' \
    | while IFS= read -r line; do
        forward_line "$line"
      done
  echo "[+] Done. Watch the SIEM console -- alerts should be streaming in."
else
  echo "[!] No --ssh-user given, so the target's logs were not forwarded."
  echo "    The attack ran, but for the SIEM to SEE it, either re-run with"
  echo "    --ssh-user <user>, or run a log forwarder on the target."
fi
