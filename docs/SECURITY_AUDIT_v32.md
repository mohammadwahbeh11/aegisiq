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
| **SC-5** | Denial-of-service protection | `MAX_UPLOAD_MB` streaming cap; rate limiters (Redis-backed when `REDIS_URL` is set) |
| **SC-8/SC-13** | Transport + at-rest cryptography | `docs/HTTPS.md`, `security/crypto.py` |
| **SC-23** | Session authenticity — httpOnly cookie + CSRF | `security/session_cookie.py`, `auth/dependencies.py` |
| **ASVS V3.4** | Cookie-based session management | `security/session_cookie.py` |
| **ASVS V4.2.2** | CSRF protection on state-changing requests | `session_cookie.enforce_csrf` |
| **SI-10** | Information input validation | Sigma parser; webhook scheme check; IP parsing |
| **ASVS V2.2/V2.8** | Authentication + one-time verifier controls | lockout, MFA on all channels |
| **ASVS V3.5** | Token verification | `decode_access_token` (pinned alg, iss, aud) |
| **ASVS V7.4** | Error handling without leakage | analysis 500 path |
| **ASVS V12.1** | File upload size limits | analysis upload |

## Re-running the audit

```bash
cd backend
python -m pytest -q                                  # full suite
python -m pytest tests/test_security_controls_v32.py -q   # findings 1-14
python -m pytest tests/test_session_hardening_v32.py -q   # findings 15-18
cd .. && python scripts/smoke_test.py     # 34 end-to-end checks against a running server
grep -rnE "(^|[^A-Za-z_.])(eval|exec)\(" backend/app      # must print nothing
grep -rn "localStorage" frontend/src/context/AuthContext.tsx  # user profile only, never the token
curl -s http://localhost:8000/health | jq .security       # the live posture
```

---

## Second pass — the four things the first pass had only named

The list below used to be this document's "not claimed" section: known
structural weaknesses, honestly stated and left standing. Leaving a
finding documented is not the same as fixing it, so each one was closed.

### 15 · The session no longer lives in `localStorage` — Medium

`localStorage` is readable by any script on the page, so one XSS
anywhere in the console — a dependency, a rendered log line, a future
careless `dangerouslySetInnerHTML` — yields a working analyst token the
attacker can replay from their own machine. Short token lifetimes and a
strict CSP reduce that window; they do not close it.

`app/security/session_cookie.py` issues the session as an **httpOnly**
cookie, which script cannot read at all, alongside a readable CSRF
cookie. Every state-changing cookie-authenticated request must echo that
value in `X-AegisIQ-CSRF` (the standard double-submit pattern): the
browser will attach the session cookie to a request a malicious page
triggers, but that page cannot read the CSRF cookie to set the header.
The console writes nothing to `localStorage` when the cookie is in play,
and requests carrying an `Authorization` header are exempt from the CSRF
check — a header is not something a cross-site page can set, and
demanding it there would break the agent, the log shippers and the smoke
test for no gain. `AUTH_COOKIE_ENABLED=false` restores pure bearer mode.

Two things fell out of this. The WebSocket no longer needs `?token=` for
browser clients — the cookie authenticates the handshake — which retires
the "the JWT ends up in every proxy access log" trade-off this document
listed under Transport. And `POST /api/auth/logout` now exists: there
was no logout endpoint at all, so signing out dropped the client's copy
of the token and left it valid for the rest of its lifetime. It clears
the cookie and bumps `token_version`, revoking every token for that
account (AC-12).

**Evidence.** `test_login_sets_an_httponly_session_cookie`,
`test_cookie_write_without_csrf_header_is_refused`,
`test_cookie_write_with_csrf_header_is_allowed`,
`test_bearer_write_needs_no_csrf_header`,
`test_logout_revokes_tokens_issued_before_it`.

### 16 · `MFA_REQUIRED` was unusable, so it was never switched on — Medium

The flag existed and the documentation said to enable it for an
accredited deployment. Doing so locked the administrator out of their own
console: an un-enrolled user receives only an `mfa_pending` challenge
token, and every endpoint rejected it — `/api/mfa/enroll` included. The
one action the user needed was the one action the policy forbade, and
the login screen said so, advising them to go to a settings page they
could not reach. A control that cannot be turned on is not a control.

`get_enrolling_user` accepts the challenge token for enrolment **only**
(it still opens no alert, log or dashboard), the login screen now walks a
first-run user through setup — setup key, code, backup codes — and
`/api/mfa/confirm` returns a real access token, because both factors were
just proven and sending the user back to the password box proves
nothing. `MFA_REQUIRED=true` is now a supported configuration rather
than a trap.

**Evidence.** `test_challenge_token_can_enrol_mfa_but_nothing_else`,
`test_enrolment_confirmation_returns_a_usable_access_token`.

### 17 · The rate limiter is now correct with more than one worker — Low

In-process buckets mean each worker counts separately, so two workers
permit twice the configured rate while `/health` still reports the
single-worker number — a control that passes on paper and fails in
production. With `REDIS_URL` set the buckets move to Redis behind one
atomic Lua script (read, refill, consume, store), so workers cannot
interleave a read-modify-write. Without it, behaviour is exactly as
before. Either way `/health` now reports
`security.rate_limit_store`, so which one is live is observable rather
than assumed. Redis failures fail **open**, like the in-process limiter:
a limiter that takes the login page down when its cache blips is a worse
outage than the abuse it prevents.

### 18 · Deployment configuration that was wrong in practice — Medium

`render.yaml` set `ENV=production` and generated real secrets, but left
`TRUST_PROXY_HEADERS` at its safe default. Render terminates TLS at its
edge, so *every* request arrived carrying the proxy's address: the
per-IP login limiter put the entire internet in one bucket (ten sign-ins
a minute for everyone, then 429), and every audit row recorded the proxy
instead of the analyst. The flag is now set for that deployment — safe
there precisely because a proxy in front overwrites the header, and
still false by default for a directly-exposed instance where a client
could forge it.

The console and API also sit on different `*.onrender.com` hosts, which
makes the session cookie cross-site: `SameSite=None` is required for the
browser to send it, and a `SameSite=None` cookie without `Secure` is
discarded outright — a login that appears to succeed and then does
nothing. Both are set, and the production guardrail now refuses to boot
on that combination rather than letting it fail silently in the field.
`/health` reports the whole posture (environment, encryption, lockout,
MFA, session transport, proxy trust, upload ceiling) so a deploy can be
verified from outside instead of by reading the environment tab.

**Evidence.** `test_health_reports_the_rate_limit_store_and_posture`,
`test_production_guardrail_rejects_an_unsecured_cookie_policy`.

---

## What this audit still does **not** claim

* No penetration test was performed against a deployed instance; this is
  a code and configuration audit.
* Bearer tokens remain accepted (agents and log shippers need them), so a
  deployment that leaves `AUTH_COOKIE_ENABLED=false` keeps the
  `localStorage` exposure described in finding 15. The default is on.
* The cookie session is a JWT, not a server-side session record: logout
  and password change revoke it through `token_version`, but there is no
  per-session list an administrator can browse and kill individually.
  That needs a sessions table, which is the right next step if per-device
  sign-out becomes a requirement.
* `MFA_REQUIRED` still defaults to false so a fresh install can be
  explored; it is now safe to enable, and an accredited deployment must.
