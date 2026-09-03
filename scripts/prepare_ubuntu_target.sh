#!/usr/bin/env bash
#
# scripts/prepare_ubuntu_target.sh
#
# One-shot preparation of a fresh Ubuntu Server VM so that
# kali_full_attack.sh can hit it and every detection rule in the
# Lightweight SIEM raises its real alert.
#
# What it does (all idempotent -- safe to re-run):
#   1. Install openssh-server, enable it, allow password auth.
#   2. Grant the target user passwordless sudo (needed for the
#      privilege-escalation phase of the attack).
#   3. Open port 22 in ufw if ufw is active.
#   4. Install a few utilities the attack scenario expects (curl, ss).
#   5. Print the VM's IP + the ready-to-paste kali command.
#
# Usage:
#   sudo bash prepare_ubuntu_target.sh
#   sudo bash prepare_ubuntu_target.sh --user vboxuser   # default user
#   sudo bash prepare_ubuntu_target.sh --user analyst    # different account
#
# The script does NOT install Wazuh -- that is a separate concern
# handled by scripts/install_wazuh.sh. Wazuh is optional; the attack
# scenario works fine without it.

set -euo pipefail

# ─── args ─────────────────────────────────────────────────────────────
TARGET_USER="vboxuser"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) TARGET_USER="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

GREEN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[0;33m'; BLU='\033[0;34m'; NC='\033[0m'
log()  { printf "${BLU}[*]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
warn() { printf "${YEL}[!]${NC} %s\n" "$*"; }
die()  { printf "${RED}[ERR]${NC} %s\n" "$*" >&2; exit 1; }

# ─── preflight ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  die "run with sudo:  sudo bash prepare_ubuntu_target.sh"
fi

if ! id -u "$TARGET_USER" >/dev/null 2>&1; then
  die "user '$TARGET_USER' does not exist on this system. Create it first, or pass --user <existing-user>."
fi

log "Target user: $TARGET_USER"

# ─── 1. openssh-server ────────────────────────────────────────────────
log "Installing OpenSSH server (if missing)"
if ! dpkg -s openssh-server >/dev/null 2>&1; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server
fi
ok "openssh-server installed"

log "Enabling and starting ssh"
systemctl enable ssh   >/dev/null 2>&1
systemctl start ssh    >/dev/null 2>&1 || systemctl start sshd
if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
  ok "ssh service is running"
else
  die "ssh service failed to start -- run: sudo systemctl status ssh"
fi

# ─── 2. password authentication ───────────────────────────────────────
log "Enabling PasswordAuthentication (both /etc/ssh/sshd_config and any drop-in)"
sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
# Newer Ubuntu ships an override that disables it in sshd_config.d — fix that too.
for f in /etc/ssh/sshd_config.d/*.conf; do
  [[ -e "$f" ]] || continue
  sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication yes/' "$f"
done
if grep -REq '^\s*PasswordAuthentication\s+no' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null; then
  warn "There is still a PasswordAuthentication no somewhere -- inspect the files above manually."
else
  ok "PasswordAuthentication is set to yes everywhere"
fi
systemctl reload ssh 2>/dev/null || systemctl restart ssh
ok "ssh reloaded"

# ─── 3. passwordless sudo for the target user ─────────────────────────
log "Granting passwordless sudo to $TARGET_USER (needed for privilege-escalation phase)"
SUDOFILE="/etc/sudoers.d/${TARGET_USER}"
echo "${TARGET_USER} ALL=(ALL) NOPASSWD:ALL" > "$SUDOFILE"
chmod 440 "$SUDOFILE"
if visudo -cf "$SUDOFILE" >/dev/null; then
  ok "sudoers file valid: $SUDOFILE"
else
  rm -f "$SUDOFILE"
  die "sudoers syntax invalid -- change reverted."
fi

# ─── 4. firewall ──────────────────────────────────────────────────────
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  log "ufw is active -- opening port 22"
  ufw allow 22/tcp >/dev/null
  ok "ufw rule added for ssh"
else
  ok "ufw not active -- nothing to do at the firewall"
fi

# ─── 5. utilities used by the attack script ───────────────────────────
log "Installing curl, ss (for connectivity checks)"
DEBIAN_FRONTEND=noninteractive apt-get install -y curl iproute2 >/dev/null
ok "utilities installed"

# ─── 6. sanity check ──────────────────────────────────────────────────
log "Quick self-test"

# ssh port listening
if ss -tln | awk '{print $4}' | grep -qE '(:22)$'; then
  ok "ssh is listening on :22"
else
  warn "ssh does not appear to be listening on :22 -- check 'sudo ss -tln | grep 22'"
fi

# passwordless sudo works
if runuser -u "$TARGET_USER" -- sudo -n true 2>/dev/null; then
  ok "passwordless sudo works for $TARGET_USER"
else
  warn "passwordless sudo NOT working for $TARGET_USER -- check /etc/sudoers.d/$TARGET_USER"
fi

# auth.log writable and present
if [[ -r /var/log/auth.log ]] || sudo -n cat /var/log/auth.log >/dev/null 2>&1; then
  ok "/var/log/auth.log is readable"
else
  warn "/var/log/auth.log missing -- some rules ship logs to /var/log/secure instead"
fi

# ─── 7. summary + ready-to-paste kali command ─────────────────────────
IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)

cat <<EOF

═══════════════════════════════════════════════════════════════════════
  UBUNTU TARGET READY
═══════════════════════════════════════════════════════════════════════

  Hostname : $(hostname)
  User     : ${TARGET_USER}
  IP       : ${IP}

  From KALI, run the full attack drill with:
  ───────────────────────────────────────────────────────────────────
  /tmp/kali_full_attack.sh \\
      --target     ${IP} \\
      --siem       http://<WINDOWS-HOST-IP>:8000 \\
      --siem-user  admin \\
      --siem-pass  'ChangeMe123!' \\
      --valid-user ${TARGET_USER} \\
      --valid-pass '<${TARGET_USER}s-actual-password>'
  ───────────────────────────────────────────────────────────────────

  On the SIEM console you should see, in order:
    1. HIGH · T1046 · Port Scanning        (Reconnaissance)
    2. HIGH · T1110 · Brute Force          (Actions on Objectives)
    3. CRITICAL · T1078 · Login After Fail (Exploitation)
    4. CRITICAL · T1548 · Priv. Escalation (Actions on Objectives)
    5. CRITICAL · T1098 · File Integrity   (Installation)

  Optional next step: install Wazuh on this VM with
      sudo bash /tmp/install_wazuh.sh

═══════════════════════════════════════════════════════════════════════
EOF
