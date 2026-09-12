# AegisIQ — Defense-in-Depth Architecture

> Every request to AegisIQ passes through 8 sequential defense layers.
> A failure at any layer stops the request before it reaches the next.
> This document explains each layer, its purpose, its file, and how it
> defends against specific attack classes.

---

## Request Flow — The 8 Layers

```
Client Request
     │
     ▼
[1] TLS 1.3          ← encrypts wire
     │
     ▼
[2] CORS Middleware  ← rejects unknown origins
     │
     ▼
[3] Rate Limiter     ← token bucket, 10/min/IP  ← STOPS BRUTE FORCE HERE
     │
     ▼
[4] JWT + MFA        ← identity verification (3 factors)
     │
     ▼
[5] Input Validation ← Pydantic v2 schemas
     │
     ▼
[6] Detection Engine ← 8 rules, MITRE-mapped
     │
     ▼
[7] SOAR Response    ← auto block_ip / disable_user
     │
     ▼
[8] Audit Log        ← immutable compliance trail
```

---

## Layer 1 — TLS (Transport Security)

- **Purpose:** Encrypt data-in-transit (prevent eavesdropping, MITM)
- **Standard:** TLS 1.3 (Cloudflare Tunnel / Render / uvicorn `--ssl-*`)
- **Files:** `scripts/generate_certs.sh`, `scripts/run_https.sh`, `docs/HTTPS.md`
- **Defends against:** packet sniffing, session hijacking, credential theft

## Layer 2 — CORS (Cross-Origin Resource Sharing)

- **Purpose:** Prevent malicious sites from calling the API on the user's behalf
- **File:** `backend/app/main.py` — FastAPI `CORSMiddleware`
- **Config:** `CORS_ORIGINS` env var — comma-separated allowlist
- **Guardrail:** `validate_production_security()` refuses to boot with `CORS_ORIGINS=*` in production

## Layer 3 — Rate Limiter (Token Bucket) — THE BRUTE-FORCE BREAKER

**File:** `backend/app/security/rate_limit.py`

### Algorithm
- Each source IP has a bucket of `burst=5` tokens
- Refills at `10/min = 1 token every 6 seconds`
- Each login consumes 1 token
- Empty → HTTP 429 with `Retry-After` header

### Scenario
| Time | Bucket | Request | Result |
|---|---|---|---|
| t=0.0s | 5 → 4 | login #1 | 200 OK |
| t=0.5s | 0 | login #6 | **429 "Try again in 6s"** |
| t=6.0s | 0 → 1 | (refill) | — |

### Impact
1000 attempts/second → throttled to **10/minute** → attack that would
take 1 hour on unprotected system takes **6 years** here.

### Applied via dependency injection
- `POST /api/auth/login` — `Depends(enforce_auth)`
- `POST /api/auth/mfa/verify`, `POST /api/auth/change-password`

### Fail-open design
If limiter itself crashes → request proceeds. A limiter that DoS's the
login page it protects is worse than one letting extra requests past.

## Layer 4 — Authentication (JWT + Bcrypt + MFA)

### 4a. JWT
- RFC 7519, HS256, TTL 60min, signed with `SECRET_KEY`

### 4b. Bcrypt
- Cost 12 (~250ms per hash), passlib + bcrypt

### 4c. MFA (TOTP RFC 6238)
- Pure stdlib in `backend/app/security/totp.py`
- HMAC-SHA1(secret, floor(now/30)) → 6 digits, ±30s window
- Backup codes: 10 single-use, salted-hash stored
- Secrets: AES-256-GCM encrypted in `user_mfa` table

## Layer 5 — Input Validation (Pydantic v2)

- **File:** `backend/app/ingestion/schemas.py`
- Rejects with HTTP 422 before business logic
- Validates: IPv4/IPv6, port 0-65535, string length caps, types

## Layer 6 — Detection Engine (8 rules)

| Rule | Threshold | MITRE | Severity |
|---|---|---|---|
| `brute_force` | 6 fails / 10min / IP | T1110 | HIGH |
| `port_scan` | 12 ports / 5min / IP | T1046 | HIGH |
| `login_after_failure` | success after 5 fails | T1078 | **CRITICAL** |
| `credential_stuffing` | 5+ distinct users / IP | T1110.004 | **CRITICAL** |
| `file_integrity` | /etc/{shadow,passwd,sudoers} | T1098 | **CRITICAL** |
| `privilege_escalation` | sudo /bin/bash | T1548 | **CRITICAL** |
| `web_attack` | SQLi/XSS/LFI | T1190 | HIGH |
| `suspicious_user_agent` | sqlmap, nikto | T1595.002 | MEDIUM |

**Standards:** CVSS v3.1 severity, NIST SP 800-61, Sigma YAML rules

## Layer 7 — SOAR (Automated Response)

- **File:** `backend/app/soar/engine.py`
- **Default:** `record_only` — logs intended action, doesn't execute
- **Execute mode:** `SOAR_EXECUTE=true` + `SOAR_WEBHOOK_URL` — fires
  HMAC-SHA256 signed webhook to Shuffle / Cortex XSOAR / n8n
- **Actions:** `block_ip`, `disable_user`, `isolate_endpoint`
- **Kill Switch:** `agent/kill_switch_agent.py` executes `iptables DROP` on receipt

## Layer 8 — Audit Log (Compliance Trail)

- **File:** `backend/app/security/audit.py`
- **Table:** `audit_log` (separate from `alerts`)
- **Logs:** every login (success/failure), MFA events, password changes,
  rule modifications, alert status changes
- **Compliance:** ISO 27001 A.12.4, SOC 2 CC7.2, GDPR Art. 30, NIST SP 800-53 AU-2/3/12

---

## Transparent Extra Protections

### Security Headers Middleware
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `CSP: default-src 'self'`,
`Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: geolocation=()...`

### Data-at-Rest Encryption
- `backend/app/security/crypto.py`
- AES-256-GCM (NIST SP 800-38D), scrypt KDF (N=2^15, maxmem=64MB)
- Envelope: `v1:<nonce>:<ciphertext+tag>` (versioned for rotation)
- Mandatory for MFA secrets

### Production Guardrails
`backend/app/config.py::validate_production_security()` — refuses to boot in
`ENV=production` if `SECRET_KEY` is default/<32 chars, admin password is demo,
`DATA_ENCRYPTION_KEY` is empty, or `CORS_ORIGINS` contains `*`.

---

## Attack → Layer Mapping

| Attack | Layer that stops it | How |
|---|---|---|
| Password brute force from 1 IP | **3** (Rate Limiter) | Throttles to 10/min |
| Brute force via 1000 proxies | **6** (credential_stuffing) | Cross-user pattern detection |
| Password stuffing (leaked db) | **6** (credential_stuffing) | Same rule |
| Post-compromise login | **6** (login_after_failure) | CRITICAL + SOAR blocks IP |
| SQL injection in log field | **5** (Pydantic) | 422 rejected |
| XSS via console | CSP header | Browser blocks inline scripts |
| Session hijacking | **1** (TLS 1.3) | Wire encrypted |
| MFA bypass attempts | **3** (Rate Limiter on /mfa/verify) | Same 10/min limit |
| Stolen JWT reuse | **4a** (60min TTL) | Token expires |
| DB file theft (physical) | AES-256-GCM | MFA secrets encrypted |
| CSRF | **2** (CORS) | Origin rejected |
| Default-secrets deploy | Prod Guardrails | Refuses to boot |

---

## The Defense-in-Depth Principle

No single layer is perfect. Each layer will occasionally fail — a bug, a
misconfiguration, a novel attack. The value: **an attacker must defeat every
layer; defenders only need any one layer to hold.**

- Layer 3 alone reduces attack surface **6000×**
- Layer 4 (MFA) alone makes stolen passwords insufficient
- Layer 6 alone catches what layers 3-5 missed
- Layer 7 alone contains what layer 6 detected
- Layer 8 alone gives forensic evidence

**Combined: probability of a successful full-chain attack drops orders of magnitude below any single layer's failure rate.**

---

*See also: `SECURITY.md`, `HOW_IT_WORKS.md`, `STORAGE.md`, `HTTPS.md`.*
