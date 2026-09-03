# Changelog

All notable changes to this project are documented here. Format is
loosely based on [Keep a Changelog](https://keepachangelog.com); dates
are the day the change landed on `main`.

## [2.4.2] — One-click Render.com deployment — 2026-09-03

Adds the free-tier public deploy path so the project can be online in ~15
minutes without any paid hosting or a credit card.

### Added

- **`render.yaml`** at the repo root — Blueprint provisioning both services
  (Docker backend + static-site frontend), auto-generating `SECRET_KEY`,
  `DATA_ENCRYPTION_KEY` and `DEFAULT_ADMIN_PASSWORD`, and wiring CORS +
  `VITE_API_URL` between them.
- **`docs/DEPLOY_RENDER.md`** — three-step deploy walk-through with the
  free-tier caveats spelled out (cold start, ephemeral disk, cutover to
  Postgres for durability, adding a custom domain).

### Changed

- **`backend/Dockerfile`** — `RUN mkdir -p /app/data` so a bare `docker
  run` (no bind mount) still has a writable SQLite directory. Boot command
  still baked in for docker-compose; Render overrides with the dynamic
  `$PORT` uvicorn command from the Blueprint.

## [2.4.1] — Secure HTTPS / TLS transport — 2026-09-03

Adds encrypted **data-in-transit** to complement the AES-256-GCM at-rest
encryption: the API and the live alert WebSocket can now run over TLS.

### Added — TLS transport

- **`scripts/generate_certs.sh` / `.ps1`** — one-command self-signed cert
  with `localhost` / `127.0.0.1` SANs (825-day validity) for local HTTPS.
- **`scripts/run_https.sh` / `.ps1`** — start the backend over TLS on
  `:8443` (auto-generates a cert on first run; prefers the project venv).
- **`docker-compose.https.yml`** — TLS overlay that mounts `./certs` and
  restarts uvicorn with `--ssl-keyfile/--ssl-certfile`.
- **`docs/HTTPS.md`** — local, docker and production (reverse-proxy) TLS
  guidance, cert-trust notes, and the mixed-content rule.

### Changed

- **`scripts/smoke_test.py`** — accepts `https://` URLs; auto-skips
  certificate verification for the self-signed local cert (with a printed
  notice) and adds `--verify-tls` to enforce a trusted chain. All requests
  and the raw-header check now flow through a shared TLS context.
- **`config.py`** — default `CORS_ORIGINS` now also lists the `https://`
  console origins, so a TLS frontend works out of the box.
- **`.gitignore`** — ignores `certs/` and key/cert material so a private
  key is never committed.

### Fixed — live dashboard under attack load

- **Dashboard stayed blank / "Could not load dashboard data" during a
  live attack.** Three causes, all fixed:
  - The dashboard refreshed all five aggregate endpoints on *every* alert;
    a burst stampeded the single-worker backend. Alert-driven refreshes are
    now **coalesced** (leading + trailing edge, one per 2.5 s) with an
    overlap guard, so a flood of alerts costs one refresh, not hundreds.
  - `Promise.all` made one slow/failed query blank the whole panel. The
    loader now uses **`Promise.allSettled`**, applies every result that
    succeeded, keeps the last-good value for any that failed, and only shows
    the error banner if it has *never* loaded — a transient mid-attack
    failure is absorbed silently and retried.
  - The DB connection pool was the default (5+10); concurrent reads during
    ingestion could exhaust it. Enlarged to **pool_size=20, max_overflow=40,
    pool_pre_ping, pool_timeout=10** (safe under WAL, which allows many
    concurrent readers alongside the single writer).
- **`scripts/smoke_test.py`** now backs off and retries on the auth
  rate-limiter's `429` (honouring the server's Retry-After hint) instead of
  failing — a full run legitimately exceeds 10 auth calls/min.
- Repaired two corrupted files found during verification: a stray leading
  byte in `smoke_test.py` (caused a `SyntaxError`) and a truncated
  `scripts/kali_log_shipper.py` (rebuilt as a complete stdlib-only shipper).

### Notes

- The self-signed cert is for local/lab use; production should terminate
  TLS at a reverse proxy with a CA-issued cert (see `docs/HTTPS.md §5`).
- No application code path changed: `streamUrl()` already upgraded
  `https` → `wss`, so the alert stream rides the same TLS switch.

## [2.4.0] — Pluggable event store (OpenSearch / ClickHouse) — 2026-09-03

Addresses the SOC-readiness gap "SQLite won't handle real EPS" by putting
the high-volume event stream behind a swappable interface, while the
relational data (users, rules, alerts, audit) stays transactional.

### Added — `LogStore` abstraction + three backends

- **`app/storage/`** — a `LogStore` interface (`base.py`) capturing every
  operation the app performs on events: `index` (write), the six
  detection query primitives the rules run, and `search`/`get`/
  `related_logs`/`distinct_event_types`/`delete`/`bulk_delete`.
- **SQLAlchemyLogStore** (default) — behavior-preserving; every query is
  the one that used to be inline in the rules, moved behind the interface
  unchanged. Events stay in `DATABASE_URL` (SQLite/Postgres).
- **OpenSearchLogStore** — bool filters + cardinality aggregations
  (`opensearch-py`). **ClickHouseLogStore** — MergeTree ordered for the
  rule queries (`clickhouse-connect`). Both lazy-import their driver.
- **Factory** `get_log_store(db)` selects by `LOG_STORE`
  (`sqlalchemy` | `opensearch` | `clickhouse`).

### Changed — detection + ingestion route through the interface

- The five stateful rules (`brute_force`, `port_scan`,
  `login_after_failure`, `credential_stuffing`, `file_integrity`,
  `privilege_escalation`) now ask the `LogStore` for their historical
  counts instead of a hardcoded SQL query — so **detection scales onto
  whichever backend holds the events**. Behavior is identical under the
  default backend.
- Ingestion writes every event via `store.index()`. In external-store
  mode the event is indexed there and `Alert.log_id` is left NULL
  (evidence referenced by source/dedup); no FK violation.

### Infra + docs

- `docker-compose.yml` gains **`opensearch`** and **`clickhouse`**
  profiles (and the earlier `postgres` profile).
- **`docs/STORAGE.md`** — the architecture, the three backends, the
  honest wired-vs-follow-on status (console read routes still read the
  relational DB directly; correct for the default backend), the
  Alert↔event linkage in external mode, and the cutover checklist.

### Honest scope

The scale-critical path (event write + all detection reads) is routed
through the interface. The log-console read routes / dashboard still read
the relational `Log` model directly — correct and unchanged for the
default `sqlalchemy` backend, and the documented next step for full
external-mode console reads. The external adapters are written to each
engine's query contract; exercising them needs the service (compose
profiles provided). No breaking changes; default behavior is identical.

## [2.3.0] — MFA, encryption, richer analysis — 2026-09-01

Security-hardening release plus a much stronger offline analysis engine.

### Added — multi-factor authentication (TOTP, RFC 6238)

- Two-step login: password → 5-minute `mfa_pending` challenge token →
  TOTP (or backup) code → access token. Challenge tokens are rejected
  as session tokens everywhere else.
- Pure-stdlib TOTP (`app/security/totp.py`), **validated against the
  official RFC 6238 Appendix-B test vectors** (`tests/test_totp_crypto.py`)
  — proven interoperable with Google Authenticator, Authy, 1Password,
  Microsoft Authenticator. No third-party OTP dependency by design.
- Enrolment / confirm / disable endpoints (`/api/mfa/*`), 10 one-time
  backup codes (shown once, stored only as salted hashes and consumed on
  use), and a **Security → Two-factor** page in the console.
- Config: `MFA_ENABLED`, `MFA_REQUIRED`, `MFA_ISSUER`, `MFA_TOTP_WINDOW`.
  Every enrol/confirm/disable/challenge is audited.

### Added — data-at-rest encryption (AES-256-GCM)

- `app/security/crypto.py`: authenticated AES-256-GCM with per-value
  96-bit nonces; key derived from `DATA_ENCRYPTION_KEY` via scrypt
  (N=2¹⁵). Versioned `v1:` wire format; legacy plaintext rows read
  transparently; tamper is rejected.
- MFA secrets and backup-code hashes are always encrypted at rest via a
  transparent `EncryptedString` SQLAlchemy column type.
- Log payloads stay searchable in the clear by design; full-store
  confidentiality is documented as SQLCipher (SQLite) / TDE (PostgreSQL)
  — the same "encrypt the store, not the field" choice Splunk/Elastic
  make. See `docs/SECURITY.md § Encryption`.
- Boot logs the encryption posture; unset key → clearly-labelled
  plaintext dev mode so a lab still runs.

### Added — analysis engine: Windows + 140 threat signatures

- Windows anomaly heuristics (no DB rule needed): dangerous HRESULT bulk
  (e.g. `CBS_E_MANIFEST_INVALID_ITEM`), Security Event IDs (1102, 1116/
  1117, 4672, 4720, 7045…), CBS servicing-store integrity damage, and a
  bulk failure-rate signal.
- 140+ threat signatures across web attacks, known CVEs (Log4Shell,
  ProxyShell, Spring4Shell, PrintNightmare, Zerologon, MOVEit, Citrix
  Bleed…), reverse shells, PowerShell abuse, LOLBAS, credential dumping,
  ransomware, exfiltration, persistence, lateral movement, defense
  evasion, crypto-miners, web-shells, container escapes, and Linux SSH
  auth attacks — each MITRE + Kill Chain tagged, with bulk-escalation.
- CSV parser now recognises Windows/structured exports (`Content`,
  `Description`, `Details`, `Info`, `Text` columns) and falls back to
  whole-row concatenation.
- **Download bugfix**: the printable report opened blank because
  `window.open` dropped the JWT; the console now fetches it authenticated
  as a blob. Report enriched with IOCs, an SVG timeline, per-finding
  sample events, CWE/OWASP mapping and numbered remediation.

### Added — live rule-tuning demo in the Kali drill

- `scripts/kali_full_attack.sh` gained a `TUNE_RULES=1` block that PATCHes
  a rule's threshold at runtime (and restores it), demonstrating that
  rules are data, tuned with no restart and no code edit.

### Added — SOC-readiness: Sigma, DB concurrency, SOAR webhook, guardrails

Addressing a gap analysis of what blocks real SOC use (see the new
`docs/GAP_ANALYSIS.md` for the honest done/mitigated/roadmap breakdown):

- **Sigma rule support** (`app/detection/sigma.py`) — detections as
  config, not code. Drop a `.yml` into `sigma_rules/` and it's live on
  the next analysis. Supports field modifiers (contains/startswith/
  endswith/re/all), keyword lists, and conditions (and/or/not, parens,
  `1 of x*` / `all of them`); `level`→severity and `attack.tXXXX`→MITRE.
  Aggregation rules are skipped, not mis-evaluated. Three example rules
  ship; wired into the offline analysis engine.
- **Windows Event Log parsing** — a real parser extracts Event ID, the
  *target* account, Logon Type and source address from Security Event
  exports, so events stop showing as 100% "unparsed". Context-aware:
  SYSTEM/service/machine-account 4672/4624 are informational, not HIGH.
- **Web-signature context gate** — SSRF/SQLi/XSS/CVE signatures fire only
  on web-context events, fixing the false positive where "localhost" in
  a Windows logon was flagged as SSRF.
- **Correlation layer** — links failed→successful logons per account so a
  real pattern drives the finding, with an honest note that it may be a
  user who forgot their password.
- **SQLite concurrency** — WAL + busy_timeout so the dev DB survives
  bursts instead of raising `database is locked`; **PostgreSQL profile**
  added to `docker-compose.yml`.
- **SOAR outbound webhook** (`app/soar/webhook.py`) — recorded actions
  POST (HMAC-signed, non-blocking) to Shuffle/Cortex/n8n so real
  playbooks can run externally.
- **Production startup guardrails** — `ENV=production` refuses to boot
  with demo SECRET_KEY, demo admin password, missing DATA_ENCRYPTION_KEY,
  or wildcard CORS.
- **Repo hygiene** — hardened `.gitignore` (pycache, SQLite artifacts,
  `*.stale_*`, uploads, venvs, editor dirs).

### Verification

`python scripts/smoke_test.py` runs up to **34 checks** — the 8 rules,
security hardening, premium analysis, and the full MFA
enrol→confirm→challenge→disable round-trip. TOTP, AES-256-GCM, the
Windows parser, and the Sigma engine each have dedicated unit tests
(`tests/test_totp_crypto.py`, `test_windows_parsing.py`, `test_sigma.py`).

### Upgrade notes

No breaking changes. The `user_mfa` table is created automatically on
first boot (no migration needed). `pip install -r requirements.txt`
picks up `cryptography` (already a transitive dep, now direct). Set
`DATA_ENCRYPTION_KEY` in production; the login response is now
union-shaped but keeps `access_token` for the no-MFA path, so existing
clients keep working.

---

## [2.2.0] — Standards, tier picker, CSV export — 2026-08-27

Documentation-heavy release that closes the "is this defensible in
front of a graduation panel?" gap, plus two small feature additions
(CSV export and a proper tier picker) that a real SOC would expect.

### Added — standards mapping documentation

- **`docs/COMPLIANCE.md`** — 400+ line side-by-side mapping of every
  security control in the codebase against nine external standards:
  NIST SP 800-63B (password policy), OWASP ASVS 4.0 Level 2, OWASP
  Top 10 (2021), CIS Controls v8, GDPR Articles 5/15/17/25/30/32/33/34,
  ISO/IEC 27001:2022 Annex A, SOC 2 Trust Services Criteria,
  PCI-DSS v4.0 requirements 8/10, HIPAA § 164.312. Includes a full
  cryptographic inventory table and an explicit list of what AegisIQ
  does **not** claim (FIPS 140-3, Common Criteria, solo-HIPAA).
- **`docs/COMPARISON.md`** — Honest side-by-side comparison of
  AegisIQ 2.2 vs. Splunk Enterprise Security, Elastic Security,
  Wazuh, Microsoft Sentinel, Datadog Cloud SIEM, and Google
  Chronicle. Covers RAM footprint, pricing, rule count, MITRE
  mapping, SOAR, deployment complexity, and best-fit situations. The
  document names where AegisIQ wins on merit and where the
  enterprise SIEMs beat it — no marketing.
- **`docs/WORLD_READINESS.md`** — One-page verification checklist
  linking every "world-class SIEM" requirement to the file that
  proves it, plus a candid section titled "what this project
  deliberately does not claim."

### Added — CSV export for alerts and logs

Every SOC's ticketing pipeline eventually asks for CSV. Both
`GET /api/alerts` and `GET /api/logs` now accept
`?format=csv`, returning a streaming `text/csv` response with a
UTF-8 BOM (so accented usernames and Arabic hostnames open
correctly in Excel without a text-import dance). The column
contracts are fixed and documented in-file
(`_ALERT_CSV_COLUMNS`, `_LOG_CSV_COLUMNS`) so a downstream cron
can rely on positional parsing.

The Alerts and Log search pages both grew a **⇩ Export CSV**
button in the page header. It honours the current filter set and
caps at 1000 rows so a distracted export cannot exceed what the
operator saw on screen. Filename is dated
(`aegisiq_alerts_20260827T140900Z.csv`) so archives don't collide.

### Added — Premium tier picker in the paywall panel

The locked Analysis page now shows three tier cards
(Trial · Educational · Business) with a **Copy key** button and a
**Use this tier** button that fills the license input below.
Educational carries a gradient RECOMMENDED ribbon because that's
the key the graduation panel will use.
The old "paste key here" flow still works — the tier picker just
makes it a two-click activation.

### Documentation refresh

The README's "quality signals" section now points at the four
standards documents. The Premium page's hint text now references
`docs/COMPLIANCE.md` for the standards mapping, so anyone landing
on the paywall can see the full alignment story in one click.

### Upgrade notes

No breaking changes. No database migration. `docker compose up`
picks up the new routes; a frontend rebuild
(`npm run build` inside `frontend/`) is required for the CSV
buttons and tier picker to appear in the production bundle.
Verify with `python scripts/smoke_test.py` — the CSV export
routes reuse the existing auth and filter contract so the v2.1
suite still passes without changes.

---

## [2.0.0] — AegisIQ — 2026-08-25

Major release. Rebranded from **Lightweight SIEM** to **AegisIQ**
("intelligent shield") and hardened across every layer.

### Rebrand

- Product name: **AegisIQ** (from "Lightweight SIEM").
- Tagline: **Intelligent Shield · SIEM & SOAR**.
- Version bumped to **2.0.0** (from 1.0.0). Reported by `GET /health`.
- Frontend title, sidebar brand, login card, and page metadata all
  updated. Legacy localStorage keys (`siem_user`, `siem_access_token`)
  are auto-migrated to `aegisiq_*` on first load — no logout on upgrade.

### Added — three new detection rules

Rule count went from 5 → 8. All 8 rules ship enabled with the same
data-driven contract (threshold + window read from the database at
evaluation time, editable from the Rules page with no restart).

| Rule | Type | MITRE | Kill Chain | Severity |
|---|---|---|---|---|
| Web Application Attack | `web_attack` | T1190 | Exploitation | HIGH |
| Credential Stuffing | `credential_stuffing` | T1110.004 | Credential Access | CRITICAL |
| Suspicious User-Agent | `suspicious_user_agent` | T1595.002 | Reconnaissance | MEDIUM |

**Web Application Attack** matches SQL injection, XSS, path traversal,
OS command injection, SSTI, and Log4Shell patterns on any HTTP request
event. Fires on a single match; dedup by `source_ip + pattern_name` so
a scanner cycling through 100 SQLi payloads shows as one incident, but
a different attack shape from the same source opens a fresh alert.
Patterns list is stored in `rule.parameters["patterns"]` and editable
from the Rules page. Signature list is documented in the rule's module
docstring.

**Credential Stuffing** counts distinct usernames from the same source
IP within the window — deliberately different from `brute_force`,
which counts attempts against a single username. A positive detection
indicates the attacker holds a leaked credential dump; the severity is
CRITICAL because "attacker has an external data source about your
users" is a more urgent condition than "attacker is guessing".

**Suspicious User-Agent** matches sqlmap, nikto, nmap NSE, metasploit,
wpscan, dirbuster, gobuster, hydra, ffuf, burp, acunetix, nuclei,
masscan, and zaproxy in the User-Agent header. Severity is MEDIUM by
design — sophisticated attackers spoof the UA, so this rule catches
the noise floor rather than the threats that matter most. Its value is
identifying and filtering out background scanning so real attacks stand
out on the dashboard.

### Added — security hardening

- **Rate limiting** on `/api/auth/login`: in-process token bucket per
  source IP (default 10 requests/minute, burst 5). Prevents
  credential-stuffing against the API itself — a class of attack the
  `login_after_failure` detection rule cannot see because 401s are
  refused before ingestion runs. See `app/security/rate_limit.py`.

- **Security-headers middleware** applied to every HTTP response:
  X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy,
  Permissions-Policy (camera/mic/geo/USB/serial/payment denied), CSP,
  HSTS (over TLS only), and Cache-Control no-store on `/api/auth/*`.
  See `app/security/headers.py`.

- **Password policy** enforced on password change (NOT on login — an
  operator tightening the policy tomorrow must not lock every existing
  user out overnight). Rules: ≥ 12 chars, ≥ 3 of {lowercase, uppercase,
  digit, symbol}, not on the well-known-leak list, cannot equal or
  contain the username. See `app/security/password_policy.py`. The
  policy is exposed at `GET /api/auth/policy` so the frontend can show
  the exact requirements next to the password input.

- **Password change endpoint**: `PATCH /api/auth/password`. Requires
  the current password (prevents a hijacked session from locking the
  real user out with a new password). Every change is audited.

- **Append-only audit log** for every mutating action: login (success
  and failure), password change, rule edit, alert triage, alert
  deletion, log deletion, retention purge, agent registration,
  simulation run. Row schema: timestamp, username, action, target,
  outcome, source_ip, JSON details. See `app/security/audit.py`.
  Analysts see their own rows; administrators see everyone's.

- **Content Security Policy** meta tag in `frontend/index.html`:
  `default-src 'self'; script-src 'self'; object-src 'none'; ...`.
  Belt-and-braces with the backend header-middleware CSP.

- **Client-side idle timeout** with cross-tab activity broadcast. On
  15 minutes of no keyboard/mouse/touch activity, the console auto
  logs out and redirects to `/login`. Countdown appears in the top
  status bar when < 2 minutes remain. See `frontend/src/security.ts`.

- **JWT pre-expiry logout**: the client parses the JWT `exp` claim and
  schedules a logout 30 seconds before it, so a request firing exactly
  at expiry never surfaces as a raw 401 the user has to reason about.

- **Failure-mode audit**: every login failure records a row with
  `outcome=failure` and `details.reason=invalid_credentials`. Combined
  with the audit search UI, this makes offline forensic review of a
  suspected compromise straightforward.

### Added — frontend UX polish

- **Light / Dark / System theme** with persistence. Follows OS
  preference by default; the sidebar has a one-click theme cycler.
  Every color routes through `--var` tokens so the swap is a single
  root-attribute change with no flash on first paint.

- **Keyboard shortcuts** (leader-key grammar borrowed from
  GitHub / Linear):

  | Shortcut | Action |
  |---|---|
  | `g d`  | Go to Dashboard |
  | `g a`  | Go to Alerts |
  | `g l`  | Go to Log search |
  | `g r`  | Go to Rules |
  | `g e`  | Go to Endpoints |
  | `g p`  | Go to Response |
  | `g t`  | Go to Retention |
  | `g s`  | Go to Simulation |
  | `g u`  | Go to Audit |
  | `/`    | Focus the search input on the current page |
  | `?`    | Show the shortcut list |
  | `Esc`  | Close the open modal |

  Shortcuts are refused while any input is focused, so no collision
  with normal typing.

- **Audit page** in the console, reachable at `/audit` or via `g u`.
  Filters by action, outcome, and (admin only) username.

### Changed

- `/health` response now includes `product`, `tagline`, `version`, and
  a `security` block reporting the live status of rate limiting,
  headers, audit, and password policy — makes the hardening visible to
  any external monitoring poller.

- Detection engine registry (`app/detection/engine.py::_RULE_HANDLERS`)
  extended with the three new rule types. `implemented_rule_types()`
  now returns all 8.

- `init_db._seed_rules` seeds the three new rules on any fresh
  database and honors the existing `_backfill_rule_parameters` behavior
  when upgrading an existing v1.x install — the new rules appear with
  their default parameters on first startup after upgrade.

- Ingestion normalizer now recognizes the nginx / Apache "combined"
  HTTP access-log format and emits `event_type=web_request` events
  the new web_attack rule can evaluate.

### Fixed

- Login endpoint no longer emits a Cache-Control header from the
  application code — the `SecureHeadersMiddleware` sets it (`no-store`)
  centrally so a caching proxy cannot hand a stale token to a
  different user.

- Frontend user object key renamed to avoid v1/v2 collision if the
  same browser has ever opened both versions.

### Security posture summary

See `docs/SECURITY.md` for the full v2.0 hardening breakdown. Highlights:

- Passwords: bcrypt (unchanged), plus the new server-side policy on
  change and the client-side surfacing of the policy on the change
  form.
- Session: JWT (unchanged), plus the new rate limiter on the issuing
  endpoint and the new client-side idle + pre-expiry logout.
- Transport: security headers on every response, CSP in the HTML,
  HSTS over TLS.
- Audit: append-only log for every mutating action, exposed to the
  console for role-scoped review.
- Refusal semantics: `401` for auth failures with no username
  enumeration, `403` for role denial, `422` for input-validation
  refusal — the three are never conflated.

### Upgrade notes

1. **Stop the backend and frontend.**
2. **Pull the new files.** No database migration is required; the
   existing `_ensure_columns` idempotent migration in `init_db` covers
   the new `audit_log` table (created via `create_all`) and the
   `parameters` JSON column that already exists on `detection_rules`.
3. **Restart the backend.** On first startup, three new rules seed
   into the `detection_rules` table with their default parameters.
   The `audit_log` table is created; the seeded admin's first login
   after upgrade is the first audited event.
4. **Restart the frontend.** Vite's HMR will pick up the file changes
   in dev; a production build (`npm run build`) is required for the
   published bundle.
5. **Verify.** Run `python scripts/smoke_test.py` — the v2.0 suite has
   24 checks (was 19), covering the 3 new rules and the security
   headers + rate-limit + audit endpoints. Every check should be green.

No breaking changes to existing API endpoints. Existing scripts,
Docker images, and integrations continue to work as-is.

---

## [1.0.0] — 2026-08-23

Initial release. Five detection rules (brute_force, port_scan,
login_after_failure, file_integrity, privilege_escalation), MITRE +
Kill Chain mapping, SOAR record-only, JWT + RBAC, retention API, live
WebSocket + polling console. See the initial README for details.
