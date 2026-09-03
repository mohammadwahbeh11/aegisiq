# AegisIQ — Compliance & Standards Reference

Every security control AegisIQ ships is aligned with a recognised
international standard. This document maps each control to its
underlying reference so an auditor, a customer's security review, or
a compliance framework can trace every claim in `docs/SECURITY.md`
back to a published specification.

## Password Policy — NIST SP 800-63B

Our password policy (`app/security/password_policy.py`) implements the
NIST Digital Identity Guidelines, section 5.1.1:

| Requirement | AegisIQ | NIST SP 800-63B section |
|---|---|---|
| Minimum length | **12 chars** | § 5.1.1.2 ("SHALL require at least 8") — we exceed |
| Character composition | 3 of {lowercase, uppercase, digit, symbol} | § 5.1.1.2 (composition rules allowed, not required) |
| Blocked common passwords | Local list + username collision | § 5.1.1.2 ("SHALL check against a list of known-compromised") |
| Forced rotation | **DISABLED** (never expire) | § 5.1.1.2 ("SHALL NOT require periodic change") ✓ |
| Password hints | **DISABLED** | § 5.1.1.2 ("SHALL NOT permit … hints") ✓ |
| Knowledge-based auth | **DISABLED** | § 5.1.1.2 ("SHALL NOT prompt subscribers for … KBA") ✓ |
| Password strength meter | Requirements shown to user | § 5.1.1.2 ("SHOULD offer guidance") ✓ |
| Rate-limit failed attempts | **10/min, burst 5** | § 5.2.2 (throttling required) ✓ |

**Note on the "forced rotation" ban.** NIST explicitly removed periodic
password rotation from SP 800-63B in the 2017 revision because it
leads to `<company>-Winter2025!` style patterns that reduce entropy.
AegisIQ follows this guidance strictly.

## Password Hashing — bcrypt

- Algorithm: **bcrypt** (Provos & Mazières, USENIX ATC 1999)
- Cost factor: **12** (2^12 = 4096 rounds)
- PHC (Password Hashing Competition) finalist
- Implementation: `passlib[bcrypt]` (Python)

**Why not Argon2id?** Argon2id (2015 PHC winner) is stronger against
GPU attacks but not universally available in shipped Python distros.
bcrypt is the industry baseline; a migration to Argon2id is
one-line-change ready (`passlib` supports both) but out of the current
scope.

## Session Tokens — JWT RFC 7519

- Standard: **RFC 7519** (JSON Web Token)
- Algorithm: **HS256** (HMAC-SHA256, RFC 7518 § 3.2)
- Lifetime: 60 minutes (configurable in `.env`)
- Signing key: `SECRET_KEY` from `.env`, ≥ 384 bits recommended
- No refresh token (short-lived design; re-auth on expiry)

## Message Authentication — FIPS 198-1

- License key signing: **HMAC-SHA256**
  - Standard: FIPS 198-1 (HMAC)
  - Hash: SHA-256, FIPS 180-4
  - Verification: constant-time (`hmac.compare_digest`) to prevent
    timing attacks
- JWT signing: same HMAC-SHA256 primitive (per RFC 7518 § 3.2)

## Transport Security

### HTTPS / TLS 1.3
- **TLS 1.3** — RFC 8446 (production deployment)
- **HSTS** — RFC 6797 (`Strict-Transport-Security`)
- Emitted only over TLS to prevent HSTS-poisoning on plain HTTP
- max-age = 63072000 (2 years), includeSubDomains, preload-eligible

### Security Headers — OWASP recommendations

| Header | RFC / Standard | AegisIQ value |
|---|---|---|
| `X-Frame-Options` | Draft; superseded by CSP `frame-ancestors` | `DENY` |
| `X-Content-Type-Options` | HTML Living Standard | `nosniff` |
| `Referrer-Policy` | W3C Referrer Policy | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | W3C Permissions Policy | Deny camera/mic/geo/USB/serial/payment |
| `Content-Security-Policy` | W3C CSP Level 3 | `default-src 'none'` (API); `default-src 'self'` (console) |
| `Cross-Origin-Opener-Policy` | W3C HTML | `same-origin` |
| `Cross-Origin-Resource-Policy` | Fetch Standard | `same-site` |
| `Cache-Control` | RFC 9111 | `no-store` on `/api/auth/*` |

## Application Security — OWASP ASVS 4.0.3

AegisIQ implements ASVS Level 2 controls (adequate for most applications
handling sensitive data):

| ASVS Control | AegisIQ implementation |
|---|---|
| **V2.1** Password Security | See NIST SP 800-63B mapping above |
| **V2.2** General Auth | Bearer tokens, no session cookies |
| **V2.4** Credential Storage | bcrypt cost 12, no plaintext anywhere |
| **V2.10** Service Auth | JWT signed with `SECRET_KEY` from KMS/env |
| **V3.1** Session Management | JWT expiration, client-side idle timeout, no refresh token |
| **V3.3** Session Termination | `PATCH /api/auth/password` — sessions remain until natural expiry |
| **V4.1** Access Control | RBAC via `require_role()` dependency |
| **V4.2** Operation Level Access | Per-endpoint role checks; admin-only endpoints refuse 403 |
| **V5.1** Input Validation | Pydantic on every field; IP via `ipaddress`, port range, ISO-8601 timestamps |
| **V5.2** Sanitization | SQLAlchemy parameterized queries — no string concat |
| **V5.3** Output Encoding | React auto-escapes; API returns JSON only |
| **V7.1** Log Content | Never log passwords, tokens, JWTs — audit-log documented |
| **V7.4** Log Protection | Append-only audit log; retention purge does NOT touch it |
| **V8.1** Data Protection | `.env` secrets, `.gitignore` excludes secrets |
| **V13.1** Generic Web Services | REST + JSON; OpenAPI at `/docs`, ReDoc at `/redoc` |
| **V14.4** HTTP Security | See "Security Headers" table above |
| **V14.5** HTTP Request Validation | Body size limits, method allow-list |

## OWASP Top 10 (2021)

| Risk | Mitigated by |
|---|---|
| **A01: Broken Access Control** | RBAC dep + explicit role checks + 403 refusal |
| **A02: Cryptographic Failures** | bcrypt, HMAC-SHA256, HTTPS/HSTS documented; no plaintext storage |
| **A03: Injection** | SQLAlchemy ORM; no string SQL; regex parsing bounded |
| **A04: Insecure Design** | Threat-modelled (SOAR record-only, no exec path) |
| **A05: Security Misconfiguration** | Security headers middleware, explicit CORS list, no debug in prod |
| **A06: Vulnerable & Outdated Components** | Pinned `requirements.txt`; `npm audit` in CI |
| **A07: Identification & Auth Failures** | JWT + password policy + rate limit + no username enumeration |
| **A08: Software & Data Integrity Failures** | HMAC-signed license keys; audit-log append-only |
| **A09: Security Logging & Monitoring Failures** | Full audit trail; every mutating action recorded |
| **A10: SSRF** | No user-controlled URL fetching (Wazuh URL is admin-configured) |

## CIS Controls v8 (Implementation Group 2)

AegisIQ IS a SIEM, so it implements the **detection and response**
side of CIS Controls, not the endpoint-protection side. The 5 shipped
rules + 3 v2.0 rules cover:

| CIS Control | AegisIQ rule |
|---|---|
| **8.5** Collect detailed audit logs | Audit-log table (v2.0) |
| **8.11** Conduct audit log reviews | Analyst-facing Audit page + filters |
| **12.6** Use secure network mgmt | Port-scan rule (T1046) |
| **13.1** Centralize security event alerting | Every rule → single alerts queue |
| **13.3** Deploy network-based IDS | Not shipped — SIEM ingests logs, not packets |
| **13.6** Collect network traffic logs | Ingestion pipeline accepts nginx / firewall logs |
| **16.11** Leverage vetted modules | Only pinned dependencies (see `requirements.txt`) |
| **17.3** Establish and maintain incident response process | Alert → Investigate → Resolve → Audit |

## GDPR — Personal-Data Handling

AegisIQ processes security event data. Where that data contains
personal identifiers (usernames, source IP addresses, hostnames of
personal devices), GDPR applies. AegisIQ supports the required
lifecycle controls:

| GDPR Article | AegisIQ mechanism |
|---|---|
| **Art. 5(1)(e)** Storage limitation | Retention API (`/api/retention/purge`) with dry-run + preview |
| **Art. 15** Right of access | Audit page shows every event tied to a user |
| **Art. 17** Right to erasure | Admin can delete an individual's log entries + alerts |
| **Art. 25** Data protection by design | Encryption at rest via disk-level FDE; secrets in `.env` |
| **Art. 30** Records of processing | Audit log records every mutating action + who did it |
| **Art. 32** Security of processing | See "Security Posture" doc; bcrypt, TLS, RBAC |
| **Art. 33/34** Breach notification | Alerts + audit trail = evidence chain for notifications |

## ISO/IEC 27001:2022 — Annex A Alignment

The 93 controls in Annex A of ISO 27001:2022 span organisational,
people, physical, and technological. AegisIQ addresses the
**technological** and applicable **organisational** controls:

| Annex A Control | AegisIQ |
|---|---|
| **A.5.16** Identity management | User + role model |
| **A.5.17** Authentication information | bcrypt + policy |
| **A.5.18** Access rights | RBAC dependency |
| **A.5.24** Info security incident mgmt | Alert queue + triage workflow |
| **A.5.25** Assessment & decision on infosec events | Detection engine + SOAR playbooks |
| **A.5.28** Collection of evidence | Append-only audit log |
| **A.6.3** Info security awareness | This doc + `docs/SECURITY.md` + `docs/PREMIUM.md` |
| **A.8.15** Logging | Structured log ingestion + normalization |
| **A.8.16** Monitoring activities | Live console + rule-based detection |
| **A.8.17** Clock synchronisation | Timestamps in UTC ISO-8601; NTP is deployment-level |
| **A.8.24** Use of cryptography | bcrypt + JWT HS256 + HMAC-SHA256 |
| **A.8.28** Secure coding | Pinned deps, no `eval`, Pydantic validation |

## SOC 2 Type II — Trust Services Criteria

AegisIQ supports SOC 2 audits by providing the mechanisms that
demonstrate each Trust Service Criterion:

| TSC | AegisIQ evidence |
|---|---|
| **CC1** Control Environment | Documented policies (`docs/SECURITY.md`, this file) |
| **CC2** Communication & Information | `/health` + audit log + Wazuh integration honest status |
| **CC3** Risk Assessment | Detection rule library — configurable per risk model |
| **CC4** Monitoring | Live console + WebSocket + poll fallback |
| **CC5** Control Activities | RBAC + rate limiting + input validation |
| **CC6.1** Logical Access | JWT + bcrypt + password policy |
| **CC6.2** Authentication | See "Session Tokens" |
| **CC6.3** Access Removal | Delete user endpoint + audit trail |
| **CC6.6** External Access | CORS allow-list; no wildcard |
| **CC6.7** Restriction of Sensitive Info | Never log passwords/tokens |
| **CC6.8** Malicious Software | Detection engine covers common attack patterns |
| **CC7.1** Vulnerability Detection | Detection rules + IOC-friendly ingestion |
| **CC7.2** System Component Monitoring | `/health` returns live subsystem state |
| **CC7.3** Security Event Analysis | Alert investigation view with related evidence |
| **CC7.4** Security Incident Response | SOAR playbooks (record) + alert workflow |
| **CC8.1** Change Management | Audit log records every rule + alert status change |

## PCI-DSS v4.0 — Where Applicable

If a deployment ingests logs from a Cardholder Data Environment (CDE),
these PCI-DSS v4.0 requirements are directly supported:

- **Req. 8.3.1**: MFA — supported via reverse proxy (out of scope for
  the AegisIQ backend itself, but not blocked)
- **Req. 8.3.6**: Password length ≥ 12 — ✓ (see NIST mapping above)
- **Req. 8.3.7**: Password history — ✗ (out of scope; NIST recommends
  against forced rotation)
- **Req. 10.2**: Audit logs of every access + admin action — ✓
- **Req. 10.5.2**: Log integrity — ✓ (append-only, no delete API)
- **Req. 10.5.4**: Log tampering detection — supported via file
  integrity rule on the audit log volume

## HIPAA — Health-Data Deployment

If deployed to monitor a HIPAA-covered environment:

- **§ 164.312(a)(1)** Access control — RBAC ✓
- **§ 164.312(a)(2)(iv)** Encryption/decryption — bcrypt + TLS ✓
- **§ 164.312(b)** Audit controls — audit log ✓
- **§ 164.312(c)** Integrity — HMAC-signed keys + append-only audit ✓
- **§ 164.312(d)** Person/entity authentication — JWT + password policy ✓
- **§ 164.312(e)** Transmission security — HSTS + TLS 1.3 ✓

## Cryptographic Inventory

| Purpose | Algorithm | Key Size | Standard |
|---|---|---|---|
| Password hashing | bcrypt | 60-byte output, cost 12 | Provos & Mazières 1999 |
| Session tokens | JWT HS256 | ≥ 384-bit HMAC key | RFC 7519 + RFC 7518 |
| License signatures | HMAC-SHA256 | 384-bit shared secret | FIPS 198-1 + FIPS 180-4 |
| Constant-time compare | `hmac.compare_digest` | n/a | FIPS 202-guided |
| Transport (production) | TLS 1.3 | ≥ 256-bit AEAD | RFC 8446 |
| Random tokens (SECRET_KEY) | `secrets.token_urlsafe(48)` | 288-bit entropy | NIST SP 800-90A |

**Not shipped, but ready to plug in:**
- Argon2id for password hashing (`passlib` supports it)
- RS256 / EdDSA for JWT (asymmetric option in `python-jose`)
- Data-at-rest encryption via disk-level FDE (LUKS on Linux, BitLocker
  on Windows) — deployment concern, not application code

## Supply-Chain Security

- Backend: pinned versions in `requirements.txt`
- Frontend: `package-lock.json` committed, `npm ci` (not `install`) in
  the build stage of the Docker image
- No CDN dependencies — every asset is bundled locally
- Base images: `python:3.11-slim` (official) and `node:20-alpine`
  (official) — signed by Docker Hub

## What AegisIQ Does NOT Claim

Honesty is the design principle. AegisIQ does NOT claim:

- **FIPS 140-3 certification** — the underlying `hashlib` + `hmac`
  modules are not FIPS-mode by default. A deployment on RHEL 9 with
  the system OpenSSL in FIPS mode inherits FIPS-approved primitives,
  but AegisIQ itself is not FIPS-certified.
- **Common Criteria (ISO 15408)** evaluation — not undergone.
- **PCI-DSS certification of the SIEM itself** — the SIEM can be part
  of a PCI-DSS-certified environment, but the AegisIQ codebase has
  not been PCI-audited.
- **HIPAA compliance in isolation** — a covered entity's whole
  environment must be HIPAA-compliant, not just its SIEM.

These claims require **third-party attestation**, which is a
deployment/business decision, not a code change.

## Summary — What This Doc is For

- **Auditors** can trace every AegisIQ control to a published standard.
- **Customers** can answer their infosec questionnaires ("what
  password policy do you use?" → "NIST SP 800-63B") without
  guessing.
- **Developers** modifying the codebase know which requirements each
  security control was designed to meet, so a "helpful" refactor
  doesn't accidentally remove compliance.
