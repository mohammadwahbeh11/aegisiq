# AegisIQ — Security Posture (v2.3)

This document is the reference for every security control AegisIQ
ships. It exists so a security review can confirm what is claimed
matches what is running — with a file path for every claim.

## Authentication

| Control | Implementation | Reference |
|---|---|---|
| Password hashing | bcrypt (`passlib[bcrypt]`), cost 12 | `app/auth/security.py` |
| Password never stored | Plaintext exists only during the login request | `app/auth/security.py` |
| Password policy on set | ≥ 12 chars, ≥ 3 of 4 categories, not on leak list, not equal/contain username | `app/security/password_policy.py` |
| Password change requires current | Prevents a hijacked session locking the user out | `app/api/routes/auth.py::change_password` |
| Session tokens | JWT (HS256), 60 min default | `app/auth/security.py::create_access_token` |
| No username enumeration | Same 401 for wrong password and unknown user | `app/api/routes/auth.py::login` |
| Login rate limit | Token bucket, 10 req/min per source IP, burst 5 | `app/security/rate_limit.py` |
| Idle timeout (client) | 15 min, cross-tab, warning at < 2 min | `frontend/src/security.ts` |
| Pre-expiry logout (client) | 30 s before JWT exp | `frontend/src/security.ts` |
| RBAC | administrator vs security_analyst | `app/auth/dependencies.py::require_role` |

## Transport

| Control | Implementation | Reference |
|---|---|---|
| HSTS (TLS only) | max-age 2 years, includeSubDomains, preload | `app/security/headers.py` |
| X-Frame-Options: DENY | Clickjacking protection | `app/security/headers.py` |
| X-Content-Type-Options: nosniff | MIME sniff refusal | `app/security/headers.py` |
| Referrer-Policy | strict-origin-when-cross-origin | `app/security/headers.py` |
| Permissions-Policy | Deny camera/mic/geo/USB/serial/payment | `app/security/headers.py` |
| Cross-Origin-Opener-Policy | same-origin | `app/security/headers.py` |
| Content-Security-Policy (API) | `default-src 'none'; frame-ancestors 'none'; base-uri 'none';` | `app/security/headers.py` |
| Content-Security-Policy (console) | `default-src 'self'; script-src 'self'; ...` (in HTML) | `frontend/index.html` |
| Cache-Control on auth | `no-store` on `/api/auth/*` | `app/security/headers.py` |
| CORS | Explicit allow-list, no wildcard | `app/main.py::add_middleware(CORSMiddleware)` |

## Input validation

| Control | Implementation | Reference |
|---|---|---|
| IP address parsing | `ipaddress.ip_address` | `app/ingestion/schemas.py::_validate_ip_format` |
| Port range | 0-65535 (Pydantic ge/le) | `app/ingestion/schemas.py` |
| Severity enum | Restricted to LOW/MEDIUM/HIGH/CRITICAL | `app/models/log.py::Severity` |
| Timestamp | ISO-8601 (Pydantic datetime) | `app/ingestion/schemas.py` |
| Raw log size | Capped at 10,000 chars | `app/ingestion/schemas.py` |
| Empty payload refusal | 422 when neither raw_log, event_type, nor event_id present | `app/ingestion/schemas.py::_require_something_to_normalize` |
| SQL parameterization | 100% via SQLAlchemy, no string-concat | Every `app/api/routes/*.py` |
| Rule threshold bounds | 1-100,000; window 1-86,400 | `app/schemas/rule.py::RuleUpdate` |
| Retention safety | Empty purge → 400; unresolved alerts + HIGH+ preserved by default | `app/api/routes/retention.py::purge` |

## SOAR

| Control | Implementation | Reference |
|---|---|---|
| Scope | Record-only by default; PENDING when SOAR_EXECUTE=true | `app/soar/engine.py` |
| No executor code path | Nothing in this codebase runs a firewall / account command | The absence of code |
| Playbook per rule type | Documented mapping in the engine | `app/soar/engine.py::_PLAYBOOKS` |
| Minimum severity for containment | HIGH; below that, NOTIFY_ANALYST only | `app/soar/engine.py::_MIN_SEVERITY_FOR_CONTAINMENT` |

## Audit trail

| Control | Implementation | Reference |
|---|---|---|
| Append-only log | Never updated or deleted from application code | `app/security/audit.py::AuditEntry` |
| Recorded actions | login success/failure, password change, rule edit, alert triage, alert/log delete, retention purge, agent register, simulation run | `app/security/audit.py::ACT_*` |
| Row schema | timestamp, username, action, target, outcome, source_ip, JSON details | `app/security/audit.py` |
| RBAC on read | Analyst sees own rows only; admin sees all | `app/api/routes/audit.py` |
| Retention exclusion | The purge endpoint does NOT touch the audit table | `app/api/routes/retention.py` |
| Fail-open on write | Audit failure never fails the caller's operation | `app/security/audit.py::record` |

## Data protection

| Control | Implementation | Reference |
|---|---|---|
| SECRET_KEY from .env | Never committed; default flagged as insecure | `app/config.py::Settings.SECRET_KEY` |
| Wazuh credentials from .env | Same as SECRET_KEY | `app/config.py::WAZUH_PASSWORD` |
| No sensitive fields in logs | Application logging never includes JWT or password fields | Code review |
| SQLite file permissions | Inherit from the process umask | OS-level |
| **MFA secrets encrypted at rest** | AES-256-GCM per-value, key via scrypt | `app/security/crypto.py`, `app/models/mfa.py` |
| **Backup codes hashed** | Only salted SHA-256 stored; plaintext shown once | `app/security/mfa_service.py` |

## Encryption (v2.3)

**Algorithm.** AES-256-GCM (NIST SP 800-38D authenticated encryption).
Every encrypted value carries its own random 96-bit nonce; GCM's tag
means a tampered ciphertext fails to decrypt rather than returning
garbage. Implemented in `app/security/crypto.py`.

**Key management.** The operator sets `DATA_ENCRYPTION_KEY` in the
environment. It is stretched to a 32-byte AES key with **scrypt**
(N=2¹⁵, r=8, p=1 — memory-hard, OWASP interactive parameters). The salt
is application-scoped and fixed so derivation is deterministic across
restarts (a DB written by one process must decrypt in the next).
Rotating the env value re-keys new writes; a migration re-encrypts old
rows. Left unset, the app boots in a clearly-logged **plaintext dev
mode** so a lab still runs without a key.

**What is encrypted.** TOTP/MFA secrets and backup-code hashes — small,
never-searched, high-value secrets — via a transparent SQLAlchemy
`EncryptedString` column type. These are the fields whose leakage would
let an attacker bypass the second factor, so they are always encrypted
when a key is set.

**What is NOT field-encrypted, and why.** The log `raw_log` column and
`normalized_data` are deliberately stored in the clear, because the
console's substring **search** (SQL `LIKE`) and the detection rules
(`json_extract` over `normalized_data`) must read them — field-level
encryption would break both. This is the same design choice Splunk and
Elastic make: **encrypt the store, not the field, so search keeps
working.** For confidentiality of the whole log store at rest, encrypt
the storage layer:

- **SQLite:** build against **SQLCipher** and point `DATABASE_URL` at
  the encrypted database file, or place the DB on a **LUKS**/FileVault/
  BitLocker volume.
- **PostgreSQL:** enable **TDE** (Transparent Data Encryption) or run on
  an encrypted volume; set `DATABASE_URL=postgresql+psycopg://…`.

Because the app never uses SQLite-specific SQL (see `app/database.py`),
swapping to an encrypted store is a `DATABASE_URL` change, not a code
change.

## Multi-factor authentication (v2.3)

**Standard.** TOTP per **RFC 6238** (HMAC-SHA1, 6 digits, 30-second
period) — the defaults every authenticator app (Google Authenticator,
Authy, 1Password, Microsoft Authenticator) assumes. Implemented on the
Python standard library in `app/security/totp.py` and **validated
against the official RFC 6238 Appendix-B test vectors** in
`tests/test_totp_crypto.py`, so interoperability is proven, not assumed.

**Login flow.** Two steps: `POST /api/auth/login` verifies the password
and, when a second factor is required, returns a 5-minute
`mfa_pending` challenge token instead of an access token; `POST
/api/auth/mfa/verify` exchanges that token + a code for the real JWT.
The challenge token is rejected everywhere else (`get_current_user`
refuses any token carrying `mfa_pending`), so it cannot be used as a
session token.

**Recovery.** Ten single-use backup codes are issued at enrolment,
shown once, and stored only as salted hashes; each is consumed on use.
`MFA_REQUIRED=true` makes enrolment mandatory for every account.

**Config.** `MFA_ENABLED` (feature on/off), `MFA_REQUIRED` (force
enrolment), `MFA_ISSUER` (label in the app), `MFA_TOTP_WINDOW` (drift
tolerance in 30 s steps). Every enrol/confirm/disable/challenge is
written to the audit log.

## Refusal semantics

| HTTP status | Meaning | Never used for |
|---|---|---|
| 401 | Missing / invalid / expired token; wrong credentials | Role denial |
| 403 | Authenticated but role not permitted | Bad credentials |
| 422 | Pydantic input-validation failure | Missing auth |
| 429 | Rate-limit exceeded | Any non-auth path (only `/api/auth/login`) |
| 400 | Documented safety guard (e.g. empty retention purge) | Generic input error |

The three are never conflated — a client can tell exactly what class
of problem occurred from the status code alone.

## Known trade-offs (stated on purpose)

- **WebSocket auth via query token.** The browser's WebSocket API cannot
  set headers on the handshake; the alternatives are cookies or a
  query-string token. This project uses the latter, with the trade-off
  documented in `app/api/routes/stream.py`. A production deployment
  should terminate TLS at a proxy and prefer an httpOnly cookie or a
  short-lived single-use ticket issued specifically for the socket.

- **In-process rate limiter.** Suits the single-uvicorn-worker
  deployment the project targets. A multi-worker setup would need a
  shared store (Redis). Documented at
  `app/security/rate_limit.py::RateLimiter`.

- **Idle timeout is client-side.** The JWT lifetime is the enforceable
  server ceiling. The client-side idle timer is a UX improvement, not
  the security boundary. Documented in `frontend/src/security.ts`.

- **Password policy on change, not on login.** Tightening the policy
  should not lock existing users out until they change their password.
  Documented in `app/security/password_policy.py`.

- **SOAR is scope-honest.** Documented in every place a user could see
  or configure it — the module docstring, the /health report, the
  console badge, the .env comments.

## Verifying the posture

```bash
python scripts/smoke_test.py
```

The v2.0 smoke test includes 24 checks. Every claim in this document
is exercised by at least one check; a green run is the current
best-effort evidence that the posture matches reality.
