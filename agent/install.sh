#!/usr/bin/env bash
# agent/install.sh -- install the AegisIQ Kill Switch agent as a
# systemd service on Ubuntu/Debian/Kali endpoints.
#
#   sudo bash install.sh <shared-secret-hex>
#
# The <shared-secret-hex> must match the backend's SOAR_WEBHOOK_HMAC_SECRET.
# Generate one on the backend host and paste it here:
#     openssl rand -hex 32
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "must be run as root (needs to write /etc, /var/log, and manage systemd)" >&2
  exit 1
fi

if [[ $# -lt 1 ]]; then
  echo "usage: sudo bash $0 <shared-secret-hex>" >&2
  exit 1
fi

SECRET="$1"
if [[ ${#SECRET} -lt 32 ]]; then
  echo "shared secret must be at least 32 hex chars (16 bytes)" >&2
  exit 1
fi

INSTALL_DIR=/opt/aegisiq
SECRET_FILE=/etc/aegisiq/shared_secret
SERVICE_FILE=/etc/systemd/system/aegisiq-killswitch.service
AGENT_SRC="$(dirname "$(readlink -f "$0")")/kill_switch_agent.py"

echo "==> installing agent binary to ${INSTALL_DIR}/"
mkdir -p "$INSTALL_DIR"
install -m 0755 "$AGENT_SRC" "$INSTALL_DIR/kill_switch_agent.py"

echo "==> writing shared secret to ${SECRET_FILE} (mode 0600)"
mkdir -p "$(dirname "$SECRET_FILE")"
umask 077
printf '%s' "$SECRET" > "$SECRET_FILE"
chmod 600 "$SECRET_FILE"

echo "==> writing systemd unit"
cat > "$SERVICE_FILE" <<UNIT
[Unit]
Description=AegisIQ Kill Switch endpoint agent
Documentation=file:///opt/aegisiq/README
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/aegisiq/kill_switch_agent.py \\
    --port 9999 \\
    --bind 0.0.0.0 \\
    --secret-file ${SECRET_FILE}
Restart=on-failure
RestartSec=5
# Runs as root because iptables/usermod require it. Isolate what we can:
ProtectSystem=strict
ReadWritePaths=/var/log
NoNewPrivileges=false
PrivateTmp=true
ProtectHome=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_KILL CAP_CHOWN CAP_DAC_OVERRIDE

[Install]
WantedBy=multi-user.target
UNIT

echo "==> enabling and starting service"
systemctl daemon-reload
systemctl enable aegisiq-killswitch.service
systemctl restart aegisiq-killswitch.service
sleep 1
systemctl status aegisiq-killswitch.service --no-pager || true

echo ""
echo "==> installed."
echo "    - agent:    /opt/aegisiq/kill_switch_agent.py"
echo "    - secret:   /etc/aegisiq/shared_secret (0600)"
echo "    - service:  aegisiq-killswitch.service"
echo "    - audit:    /var/log/aegisiq-killswitch.log"
echo ""
echo "==> IMPORTANT firewall step:"
echo "    Restrict port 9999 to the backend's IP only. Example:"
echo "      iptables -I INPUT -p tcp --dport 9999 -j DROP"
echo "      iptables -I INPUT -p tcp -s <BACKEND_IP> --dport 9999 -j ACCEPT"
echo ""
echo "==> smoke test (from the endpoint itself):"
echo "    SECRET=\$(cat ${SECRET_FILE})"
echo "    BODY='{\"action\":\"status\",\"timestamp\":'\$(date +%s)'}'"
echo "    SIG=sha256=\$(printf '%s' \"\$BODY\" | openssl dgst -sha256 -hmac \"\$SECRET\" | awk '{print \$2}')"
echo "    curl -sS -H \"X-AegisIQ-Signature: \$SIG\" -H 'Content-Type: application/json' \\"
echo "         -d \"\$BODY\" http://localhost:9999/"
