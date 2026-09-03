# AegisIQ — How It Works, From Zero

> **What this document is.** A single, complete explanation of AegisIQ:
> every feature, how the tool works end-to-end starting from nothing,
> **why** it was built the way it was, the database and language stack,
> and a step-by-step trace of exactly how a security alert is raised.
> Written so that a graduation panel — or a new SOC analyst — can read it
> once and understand the whole system.
>
> Version 2.3 · Companion docs: `SECURITY.md` (threat model + crypto),
> `COMPLIANCE.md` (standards mapping), `COMPARISON.md` (vs. the market),
> `ARCHITECTURE.md`, `API_REFERENCE.md`.

---

## 0 · What AegisIQ is, in one paragraph

AegisIQ ("Intelligent Shield") is a **lightweight SIEM + SOAR** — a
Security Information and Event Management platform with a Security
Orchestration, Automation and Response layer. It ingests log events
from Linux, Windows, network devices and web servers; **normalizes**
them into one canonical shape; runs **8 detection rules** (plus 140+
offline threat signatures) that map every finding to **MITRE ATT&CK**
and the **Cyber Kill Chain**; raises **alerts** an analyst triages in a
live web console; **records an automated response** for each
high-severity alert; and, as a premium feature, analyzes an uploaded
historical log file into a detailed, downloadable vulnerability report.
It runs on a laptop, boots in seconds, and every part of it is small
enough to read.

---

## 1 · The technology stack, and why each piece

| Layer | Technology | Why this choice |
|---|---|---|
| **Backend language** | **Python 3.11** | The lingua franca of security tooling; the detection logic reads like the rules it implements. Fast enough for this scale, and every SOC engineer can extend it. |
| **API framework** | **FastAPI** | Async, typed, auto-generates OpenAPI docs at `/docs`. Pydantic validation at the boundary means malformed input is rejected with a precise `422` before it reaches business logic. |
| **ORM** | **SQLAlchemy 2** | Database-agnostic. The app never writes SQLite-specific SQL, so moving from the dev database to production is a one-line `DATABASE_URL` change. |
| **Database (dev)** | **SQLite** | Zero-configuration, single file, ships in the Python stdlib. Perfect for a lab, a classroom, or a single-tenant appliance. |
| **Database (prod)** | **PostgreSQL** | Same code, same ORM. Swap `DATABASE_URL` to `postgresql+psycopg://…` for concurrency, larger retention, and TDE encryption. |
| **Auth** | **JWT (HS256, RFC 7519)** + **bcrypt** | Stateless tokens so any worker can serve any request; bcrypt (cost 12) for password hashing — deliberately slow to resist offline cracking. |
| **2FA** | **TOTP (RFC 6238)**, stdlib | Interoperates with every authenticator app; validated against the RFC test vectors. No third-party dependency. |
| **Encryption at rest** | **AES-256-GCM** (`cryptography`) | Authenticated encryption for MFA secrets; scrypt key derivation. |
| **Real-time** | **WebSocket + polling fallback** | The console updates the instant an event lands; if the socket can't hold, it silently falls back to polling so the analyst is never blind. |
| **Frontend** | **React 18 + TypeScript + Vite** | Typed UI, fast HMR in dev, a single static bundle in prod. |
| **Packaging** | **Docker + docker-compose** | `docker compose up` → full stack in under 10 seconds. |

**The overarching design principle: minimal dependencies.** A
"lightweight" SIEM that pulls in fifty packages isn't lightweight. TOTP
is 40 lines of stdlib instead of a library; there's no Alembic (a small,
documented column-migration helper stands in); the detection engine is
plain Python. Every dependency in `requirements.txt` earns its place.

---

## 2 · The data model — the five tables that matter

Everything AegisIQ does revolves around a small, honest schema
(`app/models/`):

- **`logs`** — every normalized event. Columns for the fields rules
  actually query (`event_type`, `source_ip`, `destination_port`,
  `username`, `severity`, `timestamp`) plus `raw_log` (the original
  line, kept verbatim for forensics) and `normalized_data` (a JSON blob
  for everything else). *Why keep raw_log?* Forensics must never come up
  empty-handed — the analyst can always see exactly what arrived.

- **`detection_rules`** — the rules as **data, not code**: `threshold`,
  `time_window_seconds`, `severity`, `enabled`, and a `parameters` JSON
  for rule-specific settings (watched paths, attack patterns). *Why?* So
  a SOC analyst tunes a rule from the Rules page — or via one API call —
  with **no restart and no code edit**. The engine reads these values on
  every single evaluation.

- **`alerts`** — a rule firing produces an alert: `severity`, `mitre_id`,
  `kill_chain_phase`, `description`, `status` (new → investigating →
  resolved / false_positive), `dedup_key`, and `log_id` back to the
  triggering evidence. Status changes are recorded in
  `alert_status_history` (who, when, from what, to what) — the audit
  trail of the SOC's own decisions.

- **`soar_actions`** — the recorded automated response per alert.

- **`users`** + **`user_mfa`** + **`audit_log`** — identity, second
  factor, and an append-only record of every mutating action.

*Why one canonical log shape instead of storing each source's native
format?* Because a detection rule should be written once and work
whether the event came from `sshd`, a Windows Event Log, or an nginx
access line. Normalization is what makes eight rules cover many sources.

---

## 3 · The pipeline — ingest → normalize → store → detect → respond

This is the spine of the whole system (`app/ingestion/service.py`):

```
   POST /api/logs                (a log shipper, agent, or the Kali drill)
        │
        ▼
   1. AUTHENTICATE   get_current_user  → 401 if no/invalid JWT
        │
        ▼
   2. VALIDATE       LogIngestRequest (Pydantic) → 422 on bad input
        │
        ▼
   3. NORMALIZE      normalize()  → one canonical NormalizedEvent
        │            (parses sshd/PAM, Windows Event IDs, nginx, syslog…)
        ▼
   4. STORE          INSERT into logs   (SQLAlchemy)
        │
        ▼
   5. BROADCAST      hub.publish(EVENT_LOG)  → live console feed
        │
        ▼
   6. DETECT         detection_engine.evaluate(log)  → runs all 8 rules
        │
        ▼
   7. For each rule that fired:
        ├── create an Alert row
        ├── hub.publish(EVENT_ALERT)   → alert pops on the console live
        └── soar_engine.respond()      → record a containment action
        │
        ▼
   8. RESPOND        HTTP 201 with {alerts_generated, alert_ids}
```

**Why this order matters.** The log is stored *before* detection, so
even if a rule crashes the evidence is already saved. Broadcast happens
before SOAR, so the analyst sees the alert instantly and the (slower)
response layer can't delay the UI. Every broadcast and the SOAR call are
wrapped defensively: a failure in the response layer must never turn a
successfully-detected attack into an HTTP 500 that makes the shipper
retry.

---

## 4 · How an alert is raised — step by step

Take the textbook case: **an SSH brute-force attack.**

1. **Events arrive.** A log shipper POSTs lines like
   `Failed password for admin from 203.0.113.7 port 22 ssh2` to
   `/api/logs`, one per failed attempt.

2. **Normalization** (`app/ingestion/normalizer.py`). A regex recognises
   the sshd pattern and produces a `NormalizedEvent`:
   `event_type="authentication_failure"`, `source_ip="203.0.113.7"`,
   `username="admin"`, `severity="medium"`. If the line were a Windows
   Event ID 4625 instead, a different branch would produce the *same*
   `authentication_failure` type — that's the point of normalization.

3. **Storage.** The event is inserted into `logs` with its UTC
   timestamp.

4. **Detection dispatch** (`app/detection/engine.py`). The engine loads
   the enabled rules and hands the new log to each one's `evaluate()`.

5. **The brute_force rule runs** (`app/detection/rules/brute_force.py`).
   It reads its own `threshold` (say 5) and `time_window_seconds` (say
   300) **from the database row**, then asks the database:

   ```sql
   SELECT COUNT(id) FROM logs
   WHERE event_type = 'authentication_failure'
     AND source_ip  = '203.0.113.7'
     AND timestamp >= (this_event_time − 300s)
     AND timestamp <= this_event_time
   ```

   *Why a database query rather than an in-memory counter?* So detection
   is correct even immediately after a restart — there is no in-memory
   state to lose. The window is a **rolling** window ending at the
   triggering event, inclusive at both ends.

6. **Threshold check.** If the count is below 5, `evaluate()` returns
   `None` — nothing happens, the event is just a stored log. On the 5th
   failure within the window, the count reaches the threshold.

7. **Deduplication** (`app/detection/alerting.py::has_active_alert`).
   Before creating an alert, the engine checks whether an alert for this
   same rule + `dedup_key` (here the source IP) is already open, or was
   created inside the current window. If so, it suppresses the new one —
   so attempts #6, #7, #8 don't each spawn a fresh alert. *Why?* An
   analyst wants **one incident** per attacker, not a hundred rows.

8. **Alert creation.** Otherwise `create_alert()` writes an `alerts`
   row: `severity` from the rule (HIGH), `mitre_id="T1110"`,
   `kill_chain_phase`, a human description
   ("Brute-force … 5 failed attempts within 300 seconds"), `status="new"`,
   and `log_id` pointing at the triggering event.

9. **Broadcast.** `hub.publish(EVENT_ALERT, …)` pushes the serialized
   alert down every open WebSocket. On the analyst's Alerts page the new
   row **slides in and pulses** — no refresh, because the console is
   listening on the live stream.

10. **SOAR.** `soar_engine.respond_to_alert()` records a containment
    action (e.g. "block source IP 203.0.113.7") in `soar_actions`. By
    default it is **record-only** (`SOAR_EXECUTE=false`) — the schema and
    decision are captured so a real executor can be plugged in later
    without changing anything, but the project never runs a real
    firewall command on its own.

11. **Investigation.** The analyst clicks the alert. The detail view
    pulls the triggering log **and** the surrounding evidence — the other
    failures from the same source in the rule's window — so the verdict
    can be confirmed or dismissed without writing a query by hand. They
    set the status to Resolved or False positive; that decision is
    written to `alert_status_history` with their name and the time.

That is the entire life of an alert, from a log line to a triaged
incident, and every step corresponds to a small, readable file.

---

## 5 · The 8 detection rules

Each is a single Python module under `app/detection/rules/`, data-driven
and MITRE-tagged.

| Rule | What it detects | MITRE | Kill Chain | Severity |
|---|---|---|---|---|
| `brute_force` | N failed logins from one IP | T1110 | Actions on Objectives | HIGH |
| `port_scan` | N distinct ports from one IP | T1046 | Reconnaissance | MEDIUM |
| `login_after_failure` | success right after ≥N failures | T1078 | Exploitation | CRITICAL |
| `privilege_escalation` | suspicious `sudo`/Event 4672 | T1548 | Actions on Objectives | CRITICAL |
| `file_integrity` | change to a watched critical file | T1098 | Installation | CRITICAL |
| `web_attack` | SQLi/XSS/traversal/RCE/Log4Shell in a request | T1190 | Exploitation | HIGH |
| `credential_stuffing` | failures across N distinct usernames from one IP | T1110.004 | Credential Access | CRITICAL |
| `suspicious_user_agent` | attacker-tool UA (sqlmap, nikto…) | T1595.002 | Reconnaissance | MEDIUM |

*Why these eight?* They cover the full Kill Chain from reconnaissance
(port_scan, suspicious_user_agent) through credential access
(brute_force, credential_stuffing) to exploitation
(login_after_failure, web_attack) and actions-on-objectives
(privilege_escalation, file_integrity) — a coherent story an analyst can
follow, not a random grab-bag.

---

## 6 · The premium feature — offline Log Analysis Report

Live detection watches a stream. But a SOC also needs to answer *"here
is a log file from an incident last week — what happened?"* That is the
**Log Analysis Report** (`app/analysis/`), gated behind an HMAC-signed
license.

1. **Upload** a `.log`, `.txt`, `.json`, `.jsonl` or `.csv` file (up to
   50 MB / 100 000 lines).
2. **Format detection** figures out plain text vs JSON-lines vs CSV. The
   CSV reader recognises `raw_log`, `message`, `content`, `description`
   and more, and falls back to concatenating a whole row so structured
   exports (Windows Event CSV, Zeek, Sysmon) still parse.
3. **The same normalizer** parses every line — no rule drift between the
   live path and the offline path.
4. **Three detection layers run in memory** (no DB writes — analyzing a
   customer's logs must not pollute operational data):
   - the 8 detection rules, replayed against the in-memory events;
   - **Windows anomaly heuristics** — dangerous HRESULT bulk (e.g.
     `CBS_E_MANIFEST_INVALID_ITEM`), Security Event IDs (1102 audit-log
     cleared, 1116/1117 Defender, 4672 special-privileges, 7045 service
     install), CBS servicing-store integrity damage, and a bulk
     failure-rate signal;
   - **140+ threat signatures** across web attacks, known CVEs
     (Log4Shell, ProxyShell, Spring4Shell, PrintNightmare, Zerologon…),
     reverse shells, PowerShell abuse, LOLBAS, credential dumping
     (Mimikatz, Kerberoasting, DCSync), ransomware
     (vssadmin/wbadmin/bcdedit), exfiltration, persistence, lateral
     movement, defense evasion, crypto-miners, web-shells, container
     escapes, and Linux SSH auth attacks.
5. **Enrichment.** Every finding carries MITRE technique + blurb, Kill
   Chain phase, CWE/OWASP mapping where relevant, a first/last-seen
   window, and up to 5 **verbatim sample events** from the file.
6. **The report** — shown inline immediately *and* downloadable as a
   self-contained HTML file (print-to-PDF ready) — includes a verdict
   banner, KPI row, an SVG activity timeline coloured by severity, the
   findings table with sample events, an IOC block (IPs, users, ports,
   URLs, user-agents), and numbered remediation steps per finding.

*Why a separate offline engine instead of replaying through the live
DB?* Isolation. A forensic analysis of someone else's logs must never
create operational alerts, pollute the metrics, or trip the live SOAR.

---

## 7 · Security controls (and why each exists)

- **Password policy** (NIST SP 800-63B): ≥12 chars, 3-of-4 character
  classes, blocklist of known-leaked passwords, no forced rotation
  (rotation *reduces* security by pushing users to predictable
  patterns — 800-63B says so). `app/security/password_policy.py`.
- **JWT** (RFC 7519, HS256) with a 60-minute ceiling; the frontend also
  enforces an idle logout.
- **Two-factor authentication** (RFC 6238 TOTP) with backup codes — see
  §4 of `SECURITY.md`.
- **Encryption at rest** (AES-256-GCM) for MFA secrets; SQLCipher/TDE
  recommended for the whole log store — see `SECURITY.md`.
- **Rate limiting** (token bucket) on `/api/auth/login` and
  `/api/auth/mfa/verify` so codes and passwords can't be brute-forced.
- **Security headers** (CSP, HSTS, X-Frame-Options, X-Content-Type-
  Options) stamped on every response by middleware.
- **RBAC**: administrator vs security_analyst, enforced by a dependency.
- **Append-only audit log** of every mutating action — logins, rule
  edits, alert triage, deletions, MFA changes, license activation.
- **Honest refusal semantics**: `401` auth, `403` role, `422` input,
  `429` rate-limit, `402` premium-locked — never conflated, so a client
  always knows exactly what went wrong.

Full standards mapping (NIST, OWASP ASVS, CIS, ISO 27001, SOC 2, GDPR,
PCI-DSS, HIPAA) is in `COMPLIANCE.md`.

---

## 8 · From zero to a running console — the exact steps

```bash
# 1. Backend
cd backend
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
#    (optional but recommended in production)
export DATA_ENCRYPTION_KEY=$(openssl rand -hex 32)     # turns on AES-256-GCM at rest
uvicorn app.main:app --reload --app-dir .              # http://localhost:8000  (/docs for the API)

# 2. Frontend
cd ../frontend
npm install
npm run dev                                            # http://localhost:5173

# 3. Sign in
#    user: admin   password: ChangeMe123!   (change it immediately)

# 4. Prove every rule fires end-to-end
python ../scripts/smoke_test.py                        # up to 34 green checks

# 5. Or the whole stack in one command
docker compose up -d                                   # console live in < 10 s
```

On first boot `init_db()` creates the schema, seeds the admin user and
the 8 rules, and runs the small idempotent column-migrations. Set
`MFA_REQUIRED=true` once the first admin has enrolled a second factor.

**Tuning a rule live (no restart):**
```bash
# make brute_force fire on 3 attempts instead of 5
curl -X PATCH http://localhost:8000/api/rules/<id> \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"threshold":3}'
```
The `scripts/kali_full_attack.sh` drill has a ready `TUNE_RULES=1` demo
of exactly this.

---

## 9 · Is it ready for a SOC?

**Yes, within its declared scope**, and the honest boundary is stated so
the claim stays credible.

**Ready now** — a small team, a lab, a classroom, a small MSSP running
one appliance per tenant, or any environment up to a few thousand
events/second (PostgreSQL profile) gets: real-time detection with
MITRE + Kill Chain on every alert, triage with a full audit trail,
record-only SOAR, offline forensic analysis, password policy + MFA +
encryption of secrets, rate limiting, security headers, and a standards
mapping an auditor can follow. `python scripts/smoke_test.py` proves the
whole chain green in one command, and the Kali→Ubuntu drill proves it
against real attacker tools.

**Before a large-enterprise production deployment**, do the standard
hardening that is deployment-specific, not code: put the DB on an
encrypted store (SQLCipher/TDE), terminate TLS at a proxy, set strong
`SECRET_KEY` / `DATA_ENCRYPTION_KEY`, turn on `MFA_REQUIRED`, and — for
petabyte-scale ingest, UEBA, or a large connector library — recognise
that those are explicitly **out of scope** (see `COMPARISON.md`, which
names where the enterprise SIEMs beat AegisIQ and where AegisIQ wins on
merit: auditability, MITRE-first design, offline-first, cost, and the
fact that you can read the whole thing).

The `WORLD_READINESS.md` checklist links every "world-class SIEM"
requirement to the file that proves it — and lists, plainly, the seven
things this project deliberately does **not** claim.
