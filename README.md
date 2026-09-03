# AegisIQ — Intelligent Shield SIEM & SOAR

**Version 2.0** — a resource-efficient Security Information and Event Management platform with automated response, built as an honest alternative to the Wazuh + Elasticsearch + Kibana stack for < 2 GB RAM environments.

نظام **AegisIQ** — درع ذكي: SIEM & SOAR خفيف الوزن مبني بـ FastAPI + React، يعمل ضمن أقل من 500 MB من الذاكرة الفعلية، مع 8 قواعد كشف حقيقية مرتبطة بـ MITRE ATT&CK وسلسلة القتل السيبراني (Cyber Kill Chain)، وطبقة SOAR مسؤولة، وتصلّب أمني متكامل.

> **What's new in v2.0** (2026-08-25):
> - Rebrand to **AegisIQ**
> - 3 new detection rules: **Web Application Attack** (T1190), **Credential Stuffing** (T1110.004), **Suspicious User-Agent** (T1595.002) — now 8 rules total
> - Rate-limited auth, security-headers middleware, password policy, append-only audit log
> - Light / Dark / System theme, keyboard shortcuts, session idle timeout
> - Full CSP + CORS lock-down
> - See [`CHANGELOG.md`](CHANGELOG.md) and [`docs/SECURITY.md`](docs/SECURITY.md) for the complete v2.0 posture.

---

## What's inside · محتوى المشروع

| Layer            | Technology                                       | Notes                                                                                                        |
| ---------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Backend          | Python 3.11 · FastAPI · SQLAlchemy 2 · SQLite    | JWT auth, RBAC (administrator / security_analyst), 5 real detection rules, SOAR (record-only), WebSocket bus |
| Frontend         | React 18 · TypeScript · Vite · hand-written CSS  | 8 pages, live feed, no CDN dependencies — runs on an air-gapped lab                                          |
| Detection engine | Native, rule-per-module dispatcher               | brute_force, port_scan, login_after_failure, file_integrity, privilege_escalation                            |
| Frameworks       | MITRE ATT&CK IDs + Lockheed Martin Kill Chain    | Every rule and every alert carries both mappings (objective O6)                                              |
| Optional         | Wazuh Manager integration (agents API)           | If `WAZUH_URL` is set the console merges Wazuh agents with local ones; otherwise reports "not_configured"    |

---

## Repository layout

```
lightweight-siem/
├── backend/
│   ├── app/
│   │   ├── api/routes/          # auth, logs, alerts, rules, agents, soar, simulation, stream (WebSocket), integrations, health, dashboard
│   │   ├── auth/                # bcrypt hashing, JWT, RBAC dependency
│   │   ├── core/init_db.py      # tables, default admin, seeded rules, idempotent migrations
│   │   ├── detection/           # engine + one module per rule
│   │   │   └── rules/           # brute_force · port_scan · login_after_failure · file_integrity · privilege_escalation
│   │   ├── ingestion/           # LogIngestRequest, normalizer (Linux + Windows Event IDs + generic JSON), service
│   │   ├── integrations/wazuh.py# optional Wazuh Manager connector (never fabricates data)
│   │   ├── models/              # SQLAlchemy models: User, Agent, Log, DetectionRule, Alert, Incident, SoarAction
│   │   ├── realtime/hub.py      # in-memory WebSocket hub with replay buffer + threadsafe publish
│   │   ├── schemas/             # Pydantic wire shapes
│   │   ├── soar/engine.py       # containment playbooks — DECIDES + RECORDS, never executes
│   │   ├── config.py            # BaseSettings, .env-driven
│   │   ├── database.py          # engine + SessionLocal
│   │   └── main.py              # FastAPI app + lifespan (binds the WebSocket loop)
│   ├── tests/                   # pytest — auth, RBAC, health, normalization, log ingestion, every detection rule
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── api/client.ts        # single axios instance + WebSocket URL helper + shared TS types
│   │   ├── context/             # AuthContext (JWT + role) · LiveContext (one WS for the whole console, backoff)
│   │   ├── components/          # Layout, ToastRail, ui bits, inline-SVG charts
│   │   └── pages/               # Dashboard · Alerts · AlertDetail · Logs · Rules · Endpoints · Response · Simulation · Login
│   ├── Dockerfile               # multi-stage: node build → nginx serve
│   ├── nginx.conf               # SPA fallback + long-cache static assets
│   └── vite.config.ts
├── scripts/
│   ├── smoke_test.py            # end-to-end verification against a running backend (exit 0 = green)
│   ├── kali_attack.sh           # drive real attack tooling from a Kali VM
│   ├── kali_log_shipper.py      # ship /var/log/auth.log lines to the SIEM
│   └── wazuh_forwarder.py       # optional: forward Wazuh alerts into the SIEM's ingestion API
├── agent_simulator.py           # standalone log generator (benign + attack patterns)
├── docs/
│   └── architecture.md          # design decisions, especially why NOT Wazuh+ELK
├── data/                        # SQLite file lives here (gitignored)
├── docker-compose.yml           # one-command whole-stack (backend + built frontend)
├── .env.example                 # every setting the backend reads
└── README.md                    # this file
```

---

## Detection rules (project document, Table 1)

| # | Rule name                        | Rule type              | Trigger                                                    | Severity | MITRE  | Kill Chain phase       |
| - | -------------------------------- | ---------------------- | ---------------------------------------------------------- | -------- | ------ | ---------------------- |
| 1 | Brute Force Authentication       | `brute_force`          | ≥ 5 failed logins from same IP within 120 s                | HIGH     | T1110  | Actions on Objectives  |
| 2 | Port Scanning                    | `port_scan`            | ≥ 10 **distinct** dst ports from same IP within 60 s       | HIGH     | T1046  | Reconnaissance         |
| 3 | Login After Repeated Failures    | `login_after_failure`  | Successful login after ≥ 5 failures from same IP in 300 s  | CRITICAL | T1078  | Exploitation           |
| 4 | Critical File Integrity Change   | `file_integrity`       | Any modification of `/etc/passwd`, `/etc/shadow`, …        | CRITICAL | T1098  | Installation           |
| 5 | Privilege Escalation             | `privilege_escalation` | Suspicious `sudo` (shell / passwd / visudo / …) or 4672    | CRITICAL | T1548  | Actions on Objectives  |

Thresholds are stored in the `detection_rules` table and read at evaluation time — editing a rule from the console changes real behavior on the next event, with no restart.

---

## Install — one command from Docker Hub · تنصيب بأمر واحد

The published images run anywhere Docker runs, with no source checkout:

```bash
# create a folder for the persistent database, then pull + run:
mkdir siem && cd siem
curl -O https://raw.githubusercontent.com/<your-github>/lightweight-siem/main/docker-compose.public.yml
docker compose -f docker-compose.public.yml up
```

- **Console** → <http://localhost:5173>  · login **admin** / **ChangeMe123!**
- **Backend API** → <http://localhost:8000>  · docs at <http://localhost:8000/docs>

That's it — no Python, no Node.js, no Wazuh dependency.

Images on Docker Hub:

- `<your-hub-username>/lightweight-siem-backend`
- `<your-hub-username>/lightweight-siem-frontend`

To wipe the demo database and start clean:
`docker compose -f docker-compose.public.yml down && rm -f data/siem.db && docker compose -f docker-compose.public.yml up`

---

## Alternative — build from source · تشغيل من المصدر

Use this instead of the published images when you want to modify the
code or run the full test suite locally:

```bash
# from the repo root on Windows / macOS / Linux with Docker Desktop
docker compose up --build
```

Same URLs and defaults as above; this build reads the code and
Dockerfiles in this repo directly.

---

## Developer flow — no Docker · تشغيل بدون Docker

### 1) Backend — Windows (PowerShell)

```powershell
cd backend
py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 1) Backend — Linux / macOS

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

On first start the backend creates `data/siem.db`, seeds the default **admin / ChangeMe123!** account, and seeds the 5 detection rules. Change the password from the console — or from `.env` before the first boot.

### 2) Frontend

```bash
cd frontend
npm install
npm run dev            # http://localhost:5173
```

`frontend/.env` (or `frontend/.env.local`) points the console at the API:

```
VITE_API_URL=http://localhost:8000
# Use the LAN IP if you open the console from a Kali/Ubuntu VM
# VITE_API_URL=http://192.168.56.1:8000
```

### 3) Verify end-to-end

With the backend running:

```bash
python scripts/smoke_test.py
```

This exercises **16 checks** through the real HTTP API — health, JWT login, wrong-password 401, unauth 401, invalid IP 422, benign log ingestion, brute-force detection (6 failed logins → alert), port-scan detection (12 distinct ports → alert), file-integrity + privilege-escalation parsing, alerts endpoint, MITRE + Kill Chain populated on every alert, SOAR containment record, dashboard stats, MITRE coverage, and false-positive guard (4 failed logins stays silent).

Exit code `0` means the SIEM is green.

### Deploy online (free, one click)

Push to GitHub → connect Render → done. Both backend and console live at
`*.onrender.com` with HTTPS in ~15 minutes, no credit card. Full walk-through:
**`docs/DEPLOY_RENDER.md`**. Blueprint is committed as `render.yaml` at the
repo root.

### Secure HTTPS / TLS (optional)

Run the API and live alert stream over an encrypted connection with a
self-signed certificate (localhost) in one command:

```bash
# Linux / macOS
./scripts/generate_certs.sh
./scripts/run_https.sh                 # -> https://localhost:8443
```
```powershell
# Windows
powershell -ExecutionPolicy Bypass -File scripts\generate_certs.ps1
powershell -ExecutionPolicy Bypass -File scripts\run_https.ps1   # -> https://localhost:8443
```

Then set `VITE_API_URL=https://localhost:8443` in `frontend/.env` (the
WebSocket stream upgrades to `wss://` automatically). Verify:

```bash
python scripts/smoke_test.py --url https://localhost:8443
```

Docker: `docker compose -f docker-compose.yml -f docker-compose.https.yml up --build`.
Full guide (trust, mixed-content, production reverse-proxy): **docs/HTTPS.md**.

### 4) Run the pytest suite (optional)

```bash
cd backend
pytest -q
```

The suite runs against a temp-file SQLite (see `tests/conftest.py`) so it never touches the demo database.

---

## Live demo · سيناريو العرض التقديمي

Once the console is open (`admin` / `ChangeMe123!`) go to **Simulation lab** and click:

1. **Network port scan** → HIGH alert (T1046), Kill Chain _Reconnaissance_, SOAR block_ip recorded.
2. **Credential compromise** → HIGH brute-force alert **then** CRITICAL "Login After Repeated Failures" (T1078, Kill Chain _Exploitation_) — the difference between "someone is knocking" and "someone got in".
3. **Privilege escalation via sudo** → routine `systemctl status` is ignored, `/bin/bash` and `visudo` fire a CRITICAL alert (T1548).
4. **Critical file tampering** → separate CRITICAL alerts for `/etc/passwd` and `/etc/shadow` (T1098).
5. **Full attack chain** → Reconnaissance → Credential Access → Privilege Escalation → Persistence, in one click. Every detection rule fires; the dashboard's Kill Chain view fills in as the intrusion progresses.

Every event streams through the real ingestion pipeline (normalize → persist → detect → SOAR → WebSocket) — nothing is inserted into the alerts table directly, so if a rule doesn't fire on the traffic, no alert appears. All simulated traffic uses documentation IPs (`198.51.100.0/24`) and is tagged `source="simulation"` so it can always be distinguished from real events afterwards.

---

## Real attack testing from a Kali VM · اختبار حقيقي من Kali

```bash
# from the Kali VM, against a target you control:
./scripts/kali_attack.sh \
    --target 192.168.56.20 \
    --siem   http://192.168.56.1:8000 \
    --siem-user admin \
    --siem-pass 'ChangeMe123!' \
    --ssh-user analyst \
    --attack brute_force
```

The script runs a real `hydra` brute-force against the target, then reads the target's `/var/log/auth.log` over SSH and forwards the matching lines to the SIEM. The events are genuine; the SIEM parses them exactly as it would from any log shipper.

Or just fire the standalone shipper:

```bash
# from anywhere with Python 3 + network access to the backend:
python agent_simulator.py --url http://192.168.56.1:8000 \
    --attack brute_force --count 8
```

---

## Optional: pull agents from an existing Wazuh Manager

Set these in `.env` before boot:

```
WAZUH_URL=https://192.168.56.30:55000
WAZUH_USERNAME=wazuh
WAZUH_PASSWORD=your-password
WAZUH_VERIFY_SSL=false   # lab self-signed cert
```

The **Endpoints** page then merges local + Wazuh agents. If the manager is unreachable the console says **"unreachable"** with the actual error — it never fabricates an agent list.

---

## Security posture · الوضع الأمني

- Passwords are **bcrypt** hashed (never stored in plaintext).
- Auth is **JWT (HS256)**, 60 min lifetime, `SECRET_KEY` from `.env` (rotate for anything non-local).
- **RBAC** — administrator vs security_analyst matches the project's Use Case Diagram; enforced with `require_role()`.
- Every ingestion field is **Pydantic-validated** at the API boundary: IPs are `ipaddress`-parsed, ports bounded 0–65535, severities restricted to the enum, timestamps parsed as ISO-8601.
- Search endpoints use SQLAlchemy parameterized queries — **no string-concatenated SQL**, no injection surface.
- **CORS** is an explicit allow-list from `.env`.
- The login endpoint **does not leak whether a username exists** — same 401 for wrong password and unknown user.
- **WebSocket auth** uses a token query parameter (browser API cannot set headers on the handshake). The known trade-off — query strings appear in server access logs — is documented in `app/api/routes/stream.py` with a production recommendation (terminate TLS + prefer httpOnly cookie / single-use ticket).
- **SOAR is scope-honest**: this build **records** containment decisions, it does not execute them. `SOAR_EXECUTE=true` only marks actions as intended-for-execution (status PENDING) so an executor can be plugged in later — the shipped codebase has **no code path** that runs a firewall command or disables an account.
- Wazuh integration **never fabricates data**: an unset URL returns `not_configured`, a bad credential returns `unauthorized`, an unreachable manager returns `unreachable` with the actual error.
- No CDN dependencies in the frontend — everything ships in the Vite bundle, so the console renders on an isolated lab network.

---

## Verification · قائمة التحقق قبل العرض

Before your defense, run this checklist:

- [ ] `docker compose up --build` — backend and frontend come up clean, no errors in the logs.
- [ ] Open <http://localhost:5173>, log in with `admin / ChangeMe123!`.
- [ ] Dashboard renders — every KPI is a real number (or "n/a" honestly), no placeholder text.
- [ ] `python scripts/smoke_test.py` — 16/16 green.
- [ ] `cd backend && pytest -q` — the suite is green.
- [ ] Simulation → **Full attack chain**. Watch alerts appear live in the toast rail and in the Kill Chain view.
- [ ] Alerts → open one — see the triggering log, the related evidence, the MITRE + Kill Chain badges, and the status-history audit trail.
- [ ] Rules → open Brute Force Authentication, drop threshold from 5 to 3, save. Trigger 3 failures. Alert fires — proving rules are **data, not code**.
- [ ] Response → the SOAR history shows recorded containment actions. `execution_mode = record_only` is visible.
- [ ] Change `admin`'s password from the console. Re-login. New password works.

If any item fails, capture the log and open an issue in the project repository — do not ship a demo with a red check.

---

## License

Graduation project — 2026. All rights reserved. See `docs/architecture.md` for the "why not Wazuh + ELK" rationale.
