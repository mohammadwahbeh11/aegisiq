# AegisIQ — Kill Switch (Endpoint Response Agent)

> "Kill Switch" = a signed one-click command from the SIEM to a protected
> endpoint that severs an attacker's connection or account **within one
> second** of detection — instead of waiting minutes for a human analyst
> to SSH in and type `iptables` rules by hand.

**Agent:** `agent/kill_switch_agent_v2.py` (v2.7 — Linux/Windows/macOS)
**Installer:** `agent/install.sh`
**Backend (v3.3):**
`backend/app/soar/executor.py` — decides, signs and queues orders
`backend/app/api/routes/response.py` — the endpoints the agent polls
`backend/app/models/endpoint_agent.py` — the registry and the order ledger

> **v3.3 note.** Until v3.3 this document described a backend that did not
> exist: the agent polled `/api/soar/agent/orders` and posted to
> `/api/soar/agent/result`, and neither route was implemented, so the kill
> switch could never fire. Both exist now, the console drives them, and
> the chain is covered end to end by
> `backend/tests/test_kill_switch_v33.py`.

---

## How it actually works now

The agent **polls**; the SIEM never connects into the estate. A protected
host therefore needs no inbound port, no public address and no firewall
exception, and the SIEM holds no credential to the estate — only a shared
HMAC secret per endpoint, encrypted at rest.

```
alert (HIGH/CRITICAL)
  → app/soar/engine.py           decides the containment (playbook)
  → app/soar/executor.py         guard rails, then a signed order
  → GET  /api/soar/agent/orders  the agent collects it (response signed)
  → iptables / netsh / pf        the agent applies it, and auto-expires it
  → POST /api/soar/agent/result  the agent reports back (request signed)
  → console                      status EXECUTED, with the agent's output
```

**Enrol an endpoint** in the console: *Automated response → Enrol
endpoint*. The shared secret is displayed once and stored encrypted;
there is no API that reads it back. Then run the agent on that host with
`AEGIS_ENDPOINT_ID`, `AEGIS_SHARED_SECRET` and `AEGIS_SIEM_URL`.

**Guard rails that always apply** (`executor._refuse_reason`): never a
loopback, link-local, multicast or reserved address; never the console's
own origin; never `root`/`administrator`/`admin`/`system` or anything in
`SOAR_PROTECTED_ACCOUNTS`; never a target that will not parse. A refused
action is recorded with its reason and shown in the console — the SIEM
says what it would not do, and why.

**Everything is reversible and time-boxed.** An order not collected
within `SOAR_ORDER_TTL_SECONDS` expires unapplied; the agent auto-expires
its own blocks after `MAX_BLOCK_MINUTES`; and *Undo* in the console
queues the inverse action (`unblock_ip` / `enable_user`).

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│  SIEM Backend  (aegisiq-backend)                                       │
│                                                                        │
│  Alert becomes CRITICAL  →  Analyst clicks "🔴 Block IP" in UI         │
│                             (or SOAR auto-fires on CRITICAL)           │
│         │                                                              │
│         ▼                                                              │
│  Build payload:                                                        │
│    { action: "block_ip", target_ip: "203.0.113.42",                    │
│      alert_id: 123, timestamp: 1737644400 }                            │
│         │                                                              │
│         ▼                                                              │
│  Sign:  X-AegisIQ-Signature: sha256=<HMAC(SECRET, body)>               │
│         │                                                              │
│         ▼                                                              │
│  POST http://<endpoint>:9999/  (management VLAN only!)                 │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Endpoint  (Ubuntu / Debian / Kali — /opt/aegisiq/)                    │
│                                                                        │
│  kill_switch_agent.py (systemd unit, running as root)                  │
│                                                                        │
│  1. Verify HMAC signature (constant-time compare) → 401 if bad         │
│  2. Verify timestamp freshness ±60 s → 401 if stale (replay guard)     │
│  3. Check action in ALLOWLIST → 400 if unknown                         │
│  4. Execute:                                                           │
│       block_ip     →  iptables -I INPUT 1 -s <ip> -j DROP              │
│       unblock_ip   →  iptables -D INPUT -s <ip> -j DROP  (all matches) │
│       disable_user →  usermod -L <user> + pkill -KILL -u <user>        │
│       status       →  (ping/pong for health check)                     │
│  5. Write to /var/log/aegisiq-killswitch.log (audit)                   │
│  6. Return JSON with result                                            │
│                                                                        │
│  Effect on attacker: SSH tunnel drops instantly. Next packets ignored. │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Installation on an endpoint

**On the SIEM backend host (once), generate a shared secret:**

```bash
openssl rand -hex 32
# copy the output — you'll paste it on the endpoint AND set it as the
# backend's SOAR_WEBHOOK_HMAC_SECRET env var.
```

**On each endpoint you want to protect:**

```bash
# 1. Copy the agent + installer to the endpoint (SSH, scp, ansible, …).
scp -r agent/ user@endpoint:/tmp/aegisiq-agent

# 2. Install as root:
ssh user@endpoint
cd /tmp/aegisiq-agent
sudo bash install.sh <shared-secret-hex>

# 3. Verify:
sudo systemctl status aegisiq-killswitch.service
sudo journalctl -u aegisiq-killswitch.service -n 20
```

**Restrict the port to the backend only** (crucial — port 9999 is a
remote code execution surface, protect it like SSH):

```bash
sudo iptables -I INPUT -p tcp --dport 9999 -j DROP
sudo iptables -I INPUT -p tcp -s <BACKEND_IP> --dport 9999 -j ACCEPT
# Persist with `iptables-persistent` or nftables equivalents.
```

---

## Smoke test (from the endpoint itself)

```bash
SECRET=$(sudo cat /etc/aegisiq/shared_secret)
BODY='{"action":"status","timestamp":'$(date +%s)'}'
SIG=sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')

curl -sS \
  -H "X-AegisIQ-Signature: $SIG" \
  -H "Content-Type: application/json" \
  -d "$BODY" \
  http://localhost:9999/
```

Expected response:
```json
{"status":"alive","agent_version":"1.0.0","python":"3.10.12","iptables_available":true}
```

---

## Backend integration

The backend already contains the signing side in
`backend/app/soar/webhook.py`. To wire the Kill Switch, set on the backend:

```bash
export SOAR_ENABLED=true
export SOAR_EXECUTE=true
export SOAR_WEBHOOK_URL=http://<endpoint>:9999/
export SOAR_WEBHOOK_HMAC_SECRET=<same-hex-string-you-used-in-install.sh>
```

Restart the backend. Now HIGH/CRITICAL alerts fire a signed webhook to
the endpoint, which executes the containment action.

**Multiple endpoints:** run one webhook target per endpoint or point at
a lightweight fan-out proxy that forwards to the correct endpoint based
on the alert's `source_ip` → `agent_id` mapping.

---

## Threat model (why it's safe)

| Threat | Mitigation |
|---|---|
| Attacker crafts a fake block request | HMAC-SHA256 signature → cannot forge without secret |
| Attacker replays a captured block request | Timestamp freshness (±60s window) rejects stale ones |
| Attacker probes port 9999 from the internet | Firewall rule allows only the backend IP |
| Attacker compromises the SIEM host | They **do** get the secret — then Kill Switch is theirs. Mitigate: run SIEM under strict CIS hardening + SOC 2 controls |
| False-positive rule causes wide auto-block | Default: SOAR is `record_only` — auto-execute requires explicit env flag + human review for MEDIUM/LOW |
| Command injection via `target_ip` | Not shell-executed — passed as an argv element to `iptables`; `_looks_like_ip()` validates format |
| Buffer / DoS attempt | 4096-byte body cap, 10s subprocess timeout |
| Log tampering after breach | Audit log lives on the endpoint — ship it out via journald + syslog to the SIEM itself |

---

## Actions supported

| Action | Command executed | Reversible? |
|---|---|---|
| `block_ip` | `iptables -I INPUT 1 -s <ip> -j DROP` | yes, via `unblock_ip` |
| `unblock_ip` | `iptables -D INPUT -s <ip> -j DROP` (all matches) | n/a |
| `disable_user` | `usermod -L <user>` + `pkill -KILL -u <user>` | yes, `usermod -U <user>` (not exposed — do it manually to keep the API narrow) |
| `status` | ping/pong — verifies agent is alive and secret matches | n/a |

Adding a new action requires editing `ACTION_HANDLERS` and `ALLOWED_ACTIONS`
in `kill_switch_agent.py`. Keep the list minimal — every action is
remote code execution.

---

## Operational notes

- **Runs as root** (needs `CAP_NET_ADMIN` for iptables, `CAP_KILL` for pkill).
  The systemd unit uses `ProtectSystem=strict`, `PrivateTmp`, `ProtectHome`
  and a narrow `CapabilityBoundingSet` to reduce blast radius.
- **Not for internet exposure.** Bind to the management VLAN, an SSH
  tunnel, or a WireGuard mesh from the backend.
- **Rotate the shared secret** at least quarterly. Regenerate on the
  backend, run `install.sh` with the new value on every endpoint, restart
  the service (`systemctl restart aegisiq-killswitch`), restart the backend.
- **Audit log** at `/var/log/aegisiq-killswitch.log` is your forensic
  trail. Ship it to the SIEM via the log shipper for correlation.

---

*See also: `DEFENSE_LAYERS.md` (where Kill Switch fits — Layer 7 SOAR),
`SECURITY.md` (auth, encryption), `HOW_IT_WORKS.md` (architecture).*
