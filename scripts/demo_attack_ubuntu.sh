#!/usr/bin/env bash
# demo_attack_ubuntu.sh -- run the full AegisIQ detection demo from an Ubuntu
# box against the PUBLIC SIEM, with no target VM and no hydra/nmap needed.
#
# Unlike scripts/kali_attack.sh (which runs a REAL hydra/nmap attack against a
# target you control and forwards that target's logs), this script drives the
# eight detection scenarios straight through the SIEM's authenticated
# ingestion API via agent_simulator.py. It is the simplest honest way to show
# the detection chain working against the deployed console:
#     event -> normalize -> detect -> alert -> MITRE -> dashboard/WSS
#
# All traffic uses RFC 5737 documentation IPs and is tagged source=simulation,
# so it is always distinguishable from real events.
#
# USAGE
#   export SIEM_PASSWORD='your-render-admin-password'   # never commit this
#   ./scripts/demo_attack_ubuntu.sh
#
#   # or point it somewhere else / change the admin user:
#   SIEM_URL=https://aegisiq-backend-md69.onrender.com \
#   SIEM_USERNAME=admin \
#   ./scripts/demo_attack_ubuntu.sh
#
# The admin password is READ FROM THE ENVIRONMENT on purpose. Do not paste it
# on the command line (it would land in your shell history) and never hardcode
# it here. On the Render free tier it is the auto-generated value under
# aegisiq-backend -> Environment -> DEFAULT_ADMIN_PASSWORD.
set -euo pipefail

SIEM_URL="${SIEM_URL:-https://aegisiq-backend-md69.onrender.com}"
SIEM_USERNAME="${SIEM_USERNAME:-admin}"

# --- preflight -------------------------------------------------------------
if [[ -z "${SIEM_PASSWORD:-}" ]]; then
  echo "ERROR: SIEM_PASSWORD is not set." >&2
  echo "  Set it first (it is the admin password from Render's Environment):" >&2
  echo "    export SIEM_PASSWORD='...'" >&2
  echo "  then re-run this script. It is read from the environment so it never" >&2
  echo "  lands in your shell history or in this file." >&2
  exit 1
fi

need() { command -v "$1" >/dev/null 2>&1; }
if ! need python3; then
  echo "python3 not found. Install it:  sudo apt update && sudo apt install -y python3" >&2
  exit 1
fi
if ! need curl; then
  echo "curl not found. Install it:  sudo apt install -y curl" >&2
  exit 1
fi

# Fetch agent_simulator.py next to this script if it is not already here.
HERE="$(cd "$(dirname "$0")" && pwd)"
SIM="$HERE/../agent_simulator.py"
if [[ ! -f "$SIM" ]]; then
  SIM="$HERE/agent_simulator.py"
  if [[ ! -f "$SIM" ]]; then
    echo "[*] agent_simulator.py not found locally; downloading it..."
    curl -fsSL -o "$SIM" \
      https://raw.githubusercontent.com/mohammadwahbeh11/aegisiq/main/agent_simulator.py
  fi
fi

echo "======================================================================"
echo " AegisIQ detection demo"
echo "   SIEM : $SIEM_URL"
echo "   user : $SIEM_USERNAME"
echo "======================================================================"
echo "[*] Waking the backend (Render free tier sleeps after ~15 min idle)..."
# One patient health call so the first real request does not eat the cold start.
curl -fsS --max-time 90 "$SIEM_URL/health" >/dev/null \
  && echo "[+] Backend is awake." \
  || { echo "ERROR: backend did not answer /health in 90s." >&2; exit 1; }

# Scenario keys agent_simulator.py actually implements (verified in source):
#   brute_force · port_scan · credential_compromise · privilege_escalation ·
#   file_tampering
# Note: the SIEM ships 8 detection RULES, but a few (login_after_failure,
# web_attack, suspicious_user_agent) fire as a side effect of these scenarios
# or need a tailored payload; this script drives the five scenarios the
# standalone shipper exposes. Run with --list-attacks to see them.
SCENARIOS=(brute_force port_scan credential_compromise privilege_escalation file_tampering)

export SIEM_PASSWORD SIEM_USERNAME
for scenario in "${SCENARIOS[@]}"; do
  echo
  echo "----------------------------------------------------------------------"
  echo "[*] Scenario: $scenario"
  echo "----------------------------------------------------------------------"
  # --delay keeps us under the auth rate limiter and paces events so you can
  # watch them land on the dashboard live.
  python3 "$SIM" \
    --url "$SIEM_URL" \
    --username "$SIEM_USERNAME" \
    --attack "$scenario" \
    --delay 0.4 || echo "[!] $scenario returned non-zero (continuing)."
  sleep 2
done

echo
echo "======================================================================"
echo "[+] Done. Open the console and watch the alerts + Kill Chain view:"
echo "      https://aegisiq-frontend.onrender.com"
echo "    Every alert here came through the real ingestion + detection path."
echo "======================================================================"
