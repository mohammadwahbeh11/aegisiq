# AegisIQ — Security Audit v3.2

> A code-level audit of the AegisIQ backend and console, and the fixes
> that closed each finding. Written to be checked, not believed: every
> claim names the file it lives in and, where a control is behavioural,
> the test that proves it (`backend/tests/test_security_controls_v32.py`).
>
> Scope: authentication and session management, authorisation, the
> detection-rule path, file upload, outbound calls, logging and audit,
> and the console's own client-side posture. Target frameworks: **NIST SP
> 800-53 Rev. 5**, **DoD STIG (application security)**, **OWASP ASVS
> v4.0.3 Level 2**, **CIS Benchmarks** (file and container hygiene), with
> the existing ISO 27001 / SOC 2 mapping in `docs/COMPLIANCE.md`.
>
> Date: 2026-09-14. Audited commit: `a3e30fc` (v3.1).

---

## Summary

| # | Finding | Severity | Control | State |
|---|---|---|---|---|
| 1 | MFA bypass on the live event stream: `/ws/stream` accepted the pre-second-factor challenge token | **High** | IA-2(1), ASVS V2.8 | **Fixed** |
| 2 | No account lockout — the only brute-force control was a per-IP rate limit | **High** | AC-7, STIG APSC-DV-000110 | **Fixed** |
| 3 | `X-Forwarded-For` trusted unconditionally: rate-limit evasion + forged audit source addresses | **High** | SI-10, AU-3, SC-5 | **Fixed** |
| 4 | Unbounded upload read into memory on `/api/analysis/upload` | **Medium** | SC-5, ASVS V12.1 | **Fixed** |
| 5 | A password change did not terminate sessions already issued | **Medium** | AC-12, IA-5(1) | **Fixed** |
| 6 | `eval()` in the Sigma condition evaluator, on rule content fetched from the internet | **Medium** | SI-10, CWE-95 | **Fixed** |
| 7 | No account-disable path; a valid token outlived any account state change | **Medium** | AC-2 | **Fixed** |
| 8 | Internal exception text returned to the caller on analysis failure | **Low** | ASVS V7.4.1 | **Fixed** |
| 9 | `SOAR_WEBHOOK_URL` accepted any URL scheme, `file://` included | **Low** | SI-10, CWE-918 | **Fixed** |
| 10 | Console fetched Google Fonts — blocked by its own CSP, and an outbound call from an air-gapped SOC | **Low** | SC-7, privacy | **Fixed** |
| 11 | Server would not start from a fresh clone (`data/` absent); database file world-readable | **Low** | AC-6, CIS | **Fixed** |
| 12 | Light theme rendered dark panels under dark text — the console was unusable at default OS settings | — | usability (WCAG 2.2 AA) | **Fixed** |
| 13 | `rules_api.router` registered 15 times; duplicated operations in the OpenAPI contract | — | hygiene | **Fixed** |
| 14 | `data/` was not gitignored: the SIEM database (password hashes, MFA secrets, audit trail) was one `git add -A` from being published | **Medium** | AU-9, IA-5, CM-3 | **Fixed** |

Nothing in this list was a supply-chain finding: the dependency set in
`backend/requirements.txt` and `frontend/package.json` is small, pinned
where it matters, and free of known-vulnerable versions at audit time.

---

## 1 · MFA bypass on the live event stream — High

**What was wrong.** `app/api/routes/stream.py::_authenticate` accepted any
token whose signature and expiry checked out. The two-step login issues a
**challenge token** after the password step and before the TOTP step
(`create_mfa_challenge_token`); the REST dependency rejected it
(`mfa_pending`), the WebSocket did not.

**Why it matters.** An attacker holding only a stolen password could open
`/ws/stream?token=<challenge>` and receive every alert the SOC sees, live
— including the alerts raised by their own activity. MFA was enforced on
the paperwork and bypassed on the feed that matters operationally.

**Fix.** The socket now applies the same rules as the REST dependency:
challenge tokens, disabled accounts, locked accounts and superseded token
versions are all refused (close code 1008).

**Evidence.** `test_mfa_challenge_token_cannot_open_the_event_stream`,
`test_valid_access_token_does_open_the_event_stream`,
`test_stream_rejects_a_token_from_before_a_password_change`.

## 2 · No account lockout — High

**What was wrong.** The only brute-force control was
`app/security/rate_limit.py`, a token bucket keyed by source address.

**Why it matters.** A per-IP limiter stops one host hammering the login
form. It does nothing against the attack this SIEM's own detection rules
are written to catch: credential stuffing spread across many addresses,
one attempt each. Every bucket stays full; the limiter never fires. AC-7
and the application STIG both require a per-account threshold.

**Fix.** `app/security/lockout.py` — after `LOCKOUT_THRESHOLD` (5)
consecutive password failures an account is locked for `LOCKOUT_MINUTES`
(15), and the lock is enforced at login, on every authenticated request,
and on the WebSocket. The lock is temporary and self-clearing by design:
a permanent lock would turn a guessed username into a denial of service
against the real analyst — mid-incident, that is the attacker's win
condition (NIST SP 800-63B endorses a throttle of this shape). A locked
account returns the byte-identical 401 of a wrong password, so the
response cannot be used to enumerate accounts; the distinction is written
to the audit trail, where the defender can see it and the attacker
cannot.

**Evidence.** `test_account_locks_after_threshold_consecutive_failures`,
`test_successful_login_clears_the_failure_counter`,
`test_lockout_is_audited`.

## 3 · `X-Forwarded-For` trusted unconditionally — High

**What was wrong.** Three separate copies of the same helper read the
left-most `X-Forwarded-For` value and used it as the client address — for
the rate limiter's bucket key and for the audit trail's `source_ip`.

**Why it matters.** The header is client-supplied. Against an instance
that is not behind a rewriting proxy, an attacker rotates it per request:
the login rate limit disappears entirely, and every audit row about the
intrusion names an address of the attacker's choosing. A SIEM whose own
audit log can be authored by the attacker is worse than one with no audit
log, because it is believed.

**Fix.** One implementation, `app/security/net.py`, used by the limiter,
the auth routes, the MFA routes and the analysis routes. The header is
honoured only when `TRUST_PROXY_HEADERS=true` (the operator asserting
there is a proxy in front), and the value is parsed as an IP address
before it can reach a log line.

**Evidence.** `test_forwarded_for_header_is_ignored_unless_a_proxy_is_declared`,
`test_forwarded_header_must_be_a_valid_ip_when_trusted`.

## 4 · Unbounded upload — Medium

`POST /api/analysis/upload` called `await file.read()`, which materialises
the entire body in memory before any check runs. One authenticated
analyst — or one stolen token — could post a multi-gigabyte file and take
down the box that is supposed to be watching for the attack. The body is
now read in 1 MiB chunks against a `MAX_UPLOAD_MB` ceiling (default 25)
and abandoned with 413 the moment it is exceeded; the refusal is audited.
Evidence: `test_oversized_upload_is_refused_with_413`.

## 5 · Password change did not end existing sessions — Medium

The old response said so out loud: *"Existing sessions remain valid until
their JWT expires."* That makes the standard response to a suspected
compromise — change the password — not actually evict the intruder for up
to the token's remaining lifetime.

Every token now carries a `ver` claim holding the user's `token_version`,
which is compared on each request. A password change increments the
column, so tokens minted before it stop validating immediately. The same
mechanism gives an administrator a forced-sign-out primitive.
Evidence: `test_password_change_revokes_tokens_issued_earlier`.

The console side of this matters too: `frontend/src/api/client.ts` now
has a response interceptor that turns any unexpected 401 into "your
session ended — sign in again", instead of leaving a dead console filling
with error banners.

## 6 · `eval()` in the detection path — Medium

`app/detection/sigma.py` sanitised a Sigma condition string and then
handed it to `eval(..., {"__builtins__": {}}, {})`.

The input is rule content, and rule content is exactly what this project
invites from outside: `sigma_rules/*.yml`, plus a tarball pulled from the
public SigmaHQ repository by `/api/rules/sync`. The sanitiser looked
sound, and "the regex covers it" only has to be wrong once. A detection
engine that can be talked into executing its own rule content is a worse
hole than the attacks it looks for, and no assessor passes an `eval()` on
externally-sourced data whatever the guard in front of it.

It is replaced by a recursive-descent parser over a fixed token set
(`True`/`False`/`and`/`or`/`not`/parentheses) that can only ever return a
boolean. Unparseable conditions fail closed, as before.
Evidence: `test_sigma_condition_parser_never_executes_rule_content`, and
`test_no_eval_or_exec_remains_in_the_backend`, a grep-level assertion that
neither `eval(` nor `exec(` appears anywhere under `backend/app/`.

## 7 · No account state — Medium

The `users` table had no notion of an account being disabled, so the only
way to stop a user was to delete the row — which orphans their audit
history. `is_active` (AC-2) is now enforced at login, on every
authenticated request and on the socket; a disabled account with a valid
token gets 403.
Evidence: `test_disabled_account_cannot_log_in`,
`test_disabled_account_cannot_use_an_existing_token`.

## 8–13 · Lower-severity findings

**8 · Exception text in the response.** The analysis endpoint returned
`f"Analysis failed: {exc}"`, which can carry file paths and library
internals. The caller now gets a stable reference; the detail stays in
the server log and on the report row (ASVS V7.4.1).

**9 · Webhook URL scheme.** `urllib` opens `file://` as happily as
`https://`. A mistyped or tampered `SOAR_WEBHOOK_URL` would have made the
SIEM read local files on every containment action. Only `http`/`https`
are dispatched now, and plain HTTP in production logs a warning.

**10 · Remote fonts.** `frontend/index.html` carried three Google Fonts
tags directly under a comment promising no CDN dependencies. The
console's own CSP (`style-src 'self'`) refused the stylesheet, so the
fonts never loaded — and the request itself is the problem in the
air-gapped SOC this project sells itself on. Removed; the font stack
falls back to the platform UI faces. To pin exact faces, self-host the
`.woff2` files under `public/fonts/`.

**14 · The database was committable.** `.gitignore` covered backups,
`node_modules/` and `.env`, but not `data/` or `*.db`. The SQLite file
holds bcrypt password hashes, encrypted MFA secrets and the append-only
audit trail; on a public repository one routine `git add -A` publishes
all three, and the audit trail's value depends on it not being
re-writable by anyone who pulls. Added `data/`, `*.db`, `*.db-{shm,wal}`
and `*.sqlite*`, plus the build artefacts (`*.tsbuildinfo`, the generated
`vite.config.js`) that were also being tracked. Verify with
`git ls-files | grep -E '\.db|tsbuildinfo'` — it must print nothing.

**11 · Fresh-clone bootstrap and file permissions.** `data/` is
gitignored, so a clone could not start: SQLite failed with "unable to
open database file" before the app could explain itself. The directory is
now created (0700) at import, and the database file is chmod 0600 on
first connect — it holds credentials, MFA material and the audit trail
(AC-6; CIS file-permission guidance).

**12 · The light theme.** `aegisiq_worldclass.css` and
`aegisiq_radix.css` hardcoded near-black translucent surfaces
(`rgba(11,14,23,0.70) !important`) that ignored `data-theme`, so a
light-mode console rendered dark panels under dark text — unreadable for
anyone whose OS is set to light, which is most laptops out of the box.
Every translucent surface now routes through `--surface-*` tokens with
light and dark values, and the `!important` hotfix block that pinned the
page ground and the active nav item to dark-only values is now
theme-aware. Verified by screenshot in both themes.

**13 · Duplicate router registration.** `app.include_router(rules_api.router)`
appeared fifteen times in `app/main.py`. FastAPI matches the first, so
behaviour was unaffected — but every one of those operations appeared
fifteen times in the generated OpenAPI document, which is the artefact an
assessor reads. One registration each, in one loop.

---

## Control mapping

| Control | Requirement | Where it lives |
|---|---|---|
| **AC-2** | Account management — disable without deleting | `models/user.py::is_active`, `auth/dependencies.py` |
| **AC-6** | Least privilege on stored data | `database.py` (0700 dir, 0600 db file) |
| **AC-7** | Unsuccessful logon attempts | `security/lockout.py`, `api/routes/auth.py` |
| **AC-12** | Session termination | `token_version` claim; `auth/security.py`, `auth/dependencies.py` |
| **AU-3** | Content of audit records — trustworthy source IP | `security/net.py`, `security/audit.py` |
| **AU-9** | Protection of audit information | append-only table; db file 0600; `data/` gitignored |
| **IA-2(1)** | MFA for privileged accounts — on every channel | `api/routes/stream.py`, `api/routes/auth.py` |
| **IA-5** | Authenticator management — issuer/audience, pinned algorithm | `auth/security.py` |
| **SC-5** | Denial-of-service protection | `MAX_UPLOAD_MB` streaming cap; rate limiters |
| **SC-8/SC-13** | Transport + at-rest cryptography | `docs/HTTPS.md`, `security/crypto.py` |
| **SI-10** | Information input validation | Sigma parser; webhook scheme check; IP parsing |
| **ASVS V2.2/V2.8** | Authentication + one-time verifier controls | lockout, MFA on all channels |
| **ASVS V3.5** | Token verification | `decode_access_token` (pinned alg, iss, aud) |
| **ASVS V7.4** | Error handling without leakage | analysis 500 path |
| **ASVS V12.1** | File upload size limits | analysis upload |

## Re-running the audit

```bash
cd backend
python -m pytest -q                       # 170 tests, including the 15 above
python -m pytest tests/test_security_controls_v32.py -q
cd .. && python scripts/smoke_test.py     # 34 end-to-end checks against a running server
grep -rnE "(^|[^A-Za-z_.])(eval|exec)\(" backend/app   # must print nothing
```

## What this audit does **not** claim

* No penetration test was performed against a deployed instance; this is
  a code and configuration audit.
* Tokens live in `localStorage` on the console, which is XSS-exposed by
  construction. The mitigations are the strict CSP, the absence of any
  CDN script, and short token lifetimes. An httpOnly-cookie session with
  CSRF protection remains the stronger design and is the right next step
  before a production deployment.
* The rate limiter is in-process. A multi-worker deployment needs a
  shared store (Redis) for it to mean anything; the lockout counter,
  being in the database, is already correct across workers.
* `MFA_REQUIRED` is off by default so the first administrator can enrol.
  For an accredited deployment it must be on, and `docs/DEPLOYMENT.md`
  says so.
