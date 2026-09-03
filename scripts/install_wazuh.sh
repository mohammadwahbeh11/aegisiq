#!/usr/bin/env bash
#
# scripts/install_wazuh.sh -- one-command, unattended install of the
# full Wazuh stack (Manager + Indexer + Dashboard) on a fresh Ubuntu
# 22.04 server. When it finishes it prints the API URL, the admin
# password, and the exact lines to paste into your Lightweight SIEM
# .env so the Endpoints page starts merging Wazuh agents immediately.
#
# Run this INSIDE the fresh Ubuntu VM (as root or with sudo). It talks
# only to packages.wazuh.com and standard apt mirrors.
#
# Usage:
#   sudo bash install_wazuh.sh
#
# Notes:
# - Minimum recommended VM: 2 vCPU, 4 GB RAM (Wazuh insists), 20 GB disk.
#   With less RAM the Indexer will fail to start.
# - The all-in-one Wazuh installer is idempotent-ish but reruns are noisy;
#   only run it once on a clean box. If you must re-run, wipe with the
#   uninstall flow at the bottom of this file first.
#
set -euo pipefail

MIN_RAM_KB=3500000     # ~3.4 GB, gives the JVM room to breathe
WAZUH_VERSION="4.7"    # matches packages.wazuh.com/4.7 layout
INSTALL_LOG="/var/log/wazuh-install-$(date +%Y%m%d-%H%M%S).log"

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run this with sudo (needs to install packages and open ports)." >&2
    exit 1
  fi
}

preflight() {
  echo "[*] Preflight checks"
  # Ubuntu 22.04 is Wazuh's officially supported distro for this version.
  if ! grep -qE 'VERSION_ID="(22\.04|24\.04|20\.04)"' /etc/os-release; then
    echo "  WARN: not on Ubuntu 20.04 / 22.04 / 24.04 — the installer may still work but is unsupported."
  fi

  local ram_kb
  ram_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  if (( ram_kb < MIN_RAM_KB )); then
    echo "  ERROR: only $((ram_kb/1024)) MB RAM. Wazuh's indexer needs >=4 GB total to boot reliably."
    echo "  Shut down the VM, raise memory in VirtualBox to 4096 MB, then re-run."
    exit 1
  fi
  echo "  OK: RAM = $((ram_kb/1024)) MB"

  if ! command -v curl >/dev/null; then
    apt-get update -y >/dev/null
    apt-get install -y curl gnupg apt-transport-https >/dev/null
  fi
  echo "  OK: curl + apt tools present"
}

fetch_installer() {
  echo "[*] Downloading the official Wazuh all-in-one installer"
  cd /tmp
  curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh"
  curl -sO "https://packages.wazuh.com/${WAZUH_VERSION}/config.yml" || true
  chmod +x wazuh-install.sh
  echo "  OK: /tmp/wazuh-install.sh saved"
}

run_installer() {
  echo "[*] Installing Wazuh Manager + Indexer + Dashboard (this takes 10-20 min)"
  echo "    Full log: $INSTALL_LOG"
  # -a = all-in-one (single-node), -i = ignore health checks, -o = overwrite
  # Unattended: no prompts, no y/n confirmations.
  bash /tmp/wazuh-install.sh -a -i 2>&1 | tee "$INSTALL_LOG"
}

extract_credentials() {
  echo "[*] Extracting installation credentials"
  local pwfile="/tmp/wazuh-install-files.tar"
  if [[ ! -f "$pwfile" ]]; then
    # Older versions put it in different places.
    pwfile=$(find /tmp -maxdepth 2 -name 'wazuh-install-files.tar' | head -1)
  fi
  if [[ -f "$pwfile" ]]; then
    tar -xf "$pwfile" -C /tmp
    if [[ -f /tmp/wazuh-install-files/wazuh-passwords.txt ]]; then
      cp /tmp/wazuh-install-files/wazuh-passwords.txt /root/wazuh-passwords.txt
      chmod 600 /root/wazuh-passwords.txt
      echo "  Saved: /root/wazuh-passwords.txt (root-readable only)"
    fi
  fi
}

configure_firewall() {
  echo "[*] Opening ports 55000 (API) and 443 (Dashboard) if ufw is active"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow 55000/tcp || true
    ufw allow 443/tcp   || true
    ufw allow 1514/tcp  || true  # agent enrollment
    ufw allow 1515/tcp  || true  # agent registration
    echo "  OK: ufw rules added"
  else
    echo "  ufw not active — skipping (assume no host firewall)."
  fi
}

verify_services() {
  echo "[*] Verifying Wazuh services are running"
  for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
    if systemctl is-active --quiet "$svc"; then
      echo "  OK: $svc"
    else
      echo "  WARN: $svc is NOT active — inspect: sudo journalctl -u $svc -n 50"
    fi
  done
}

verify_api() {
  echo "[*] Testing Wazuh API on port 55000"
  local api_url="https://127.0.0.1:55000"
  local admin_pw
  admin_pw=$(awk -F"'" '/admin/ && /password/ {print $2; exit}' /root/wazuh-passwords.txt 2>/dev/null || true)
  if [[ -z "$admin_pw" ]]; then
    admin_pw="admin"  # fallback (rare)
  fi

  # Try the Wazuh API's own admin, then fall back to wazuh:wazuh.
  local token
  for user in wazuh admin; do
    token=$(curl -sk -u "${user}:${admin_pw}" -X POST "$api_url/security/user/authenticate" \
      -H 'Content-Type: application/json' 2>/dev/null | grep -oP '"token"\s*:\s*"\K[^"]+' || true)
    if [[ -n "$token" ]]; then
      echo "  OK: API responded, user '$user' authenticated"
      return
    fi
  done
  echo "  WARN: API not authenticating — password may need retrieval from /root/wazuh-passwords.txt"
}

print_next_steps() {
  local ip
  ip=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
  local admin_pw
  admin_pw=$(awk -F"'" '/admin/ && /password/ {print $2; exit}' /root/wazuh-passwords.txt 2>/dev/null || echo "<see /root/wazuh-passwords.txt>")

  cat <<EOF

═══════════════════════════════════════════════════════════════════════
  WAZUH INSTALL COMPLETE
═══════════════════════════════════════════════════════════════════════

  Dashboard:   https://${ip}
               user: admin
               pass: ${admin_pw}

  API:         https://${ip}:55000
               user: wazuh   (or 'admin')
               pass: ${admin_pw}

  Log tail:    ${INSTALL_LOG}
  Passwords:   /root/wazuh-passwords.txt

  ─── Paste the following into your Lightweight SIEM's .env  ──────────

  WAZUH_URL=https://${ip}:55000
  WAZUH_USERNAME=wazuh
  WAZUH_PASSWORD=${admin_pw}
  WAZUH_VERIFY_SSL=false

  ─── Then restart the backend and open Endpoints — you should see the
  ─── Wazuh integration flip from "not_configured" to "connected".

═══════════════════════════════════════════════════════════════════════
EOF
}

main() {
  need_root
  preflight
  fetch_installer
  run_installer
  extract_credentials
  configure_firewall
  verify_services
  verify_api
  print_next_steps
}

main "$@"

# ─── Emergency uninstall (comment out unless you need it) ───────────────
# systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard
# apt-get remove --purge -y wazuh-manager wazuh-indexer wazuh-dashboard
# rm -rf /var/ossec /etc/wazuh-* /var/lib/wazuh-*
