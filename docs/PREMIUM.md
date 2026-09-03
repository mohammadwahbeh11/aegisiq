# AegisIQ — Premium Tier (v2.1+)

AegisIQ ships free-forever with all 8 detection rules, MITRE mapping,
SOAR record-only, retention, audit, and every UX feature. The
**Log Analysis Report** is an OPTIONAL PAID FEATURE for teams that
need offline batch review of historical log files.

## What Log Analysis Report gives you

You upload a log file (plaintext, JSON-lines, or CSV). AegisIQ parses
every line through the same normalizer + 8 detection rules that power
the live console — but **without polluting the live SIEM's own event
store** — and produces:

- Executive summary: bytes processed, parse rate, worst severity
- Event-type breakdown with proportional bars
- Findings table: every rule match with MITRE tag + Kill Chain phase
- Top source addresses & top users
- Concrete, prioritised remediation recommendations per finding
- **Printable HTML report** — one-click open, browser's *Save as PDF*
  handles the rest

Limits: 50 MB / 100,000 events per file. Reports run synchronously in
~1-2 seconds for a typical 5 MB file on a single-vCPU VM.

## Tiers

| Tier | Log Analysis | PDF export | API batch | Priority support |
|---|---|---|---|---|
| **Free** | — | — | — | — |
| **Trial** (30 days) | ✓ | — | — | — |
| **Educational** | ✓ | — | — | — |
| **Business** | ✓ | ✓ | — | — |
| **Enterprise** | ✓ | ✓ | ✓ | ✓ |

## Demo license keys (graduation defense)

Use one of these to unlock the feature for the panel — no purchase
needed, no data leaves your machine, no server-side check:

```
AEGIS-DEMO-3G4H-8K2L-P0RT   → trial tier
AEGIS-EDUC-6M9N-4W7X-C1AV   → educational tier  ← recommended for the panel
```

The Educational key never expires and unlocks the `log_analysis`
feature. The keys are **hardcoded into the codebase** (see
`backend/app/security/license.py::DEMO_KEYS`) — they're safe to
publish because there's no license server; verification is a local
HMAC check.

## How the customer activates a license

### From the console (recommended)

1. Sign in as administrator.
2. Open **Log analysis** in the sidebar (it will show a PREMIUM lock).
3. Paste the license key into the *Activate* field.
4. Click **Activate**.

The page reloads with the unlocked view.

### From the .env file (persistent across restarts)

```
PREMIUM_LICENSE_KEY=AEGIS-EDUC-6M9N-4W7X-C1AV
```

Restart the backend. The `/health` endpoint's `license` block reports
`active: true, tier: educational`.

### From the API

```bash
curl -X PATCH http://localhost:8000/api/license/activate \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"key":"AEGIS-EDUC-6M9N-4W7X-C1AV"}'
```

## How the paywall works internally

Every route under `/api/analysis/*` starts with:

```python
require_feature("log_analysis", settings.PREMIUM_LICENSE_KEY)
```

Which returns HTTP **402 Payment Required** when the license is
missing / expired / doesn't grant the feature. The response body
includes the exact CTA the console renders:

```json
{
  "error": "premium_feature",
  "feature": "log_analysis",
  "message": "'log_analysis' is a premium feature. Activate a license from Settings → License, or try a demo key.",
  "current_tier": "free",
  "current_features": [],
  "how_to_activate": {
    "endpoint": "PATCH /api/license/activate",
    "body": {"key": "AEGIS-EDUC-6M9N-4W7X-C1AV"},
    "docs": "docs/PREMIUM.md"
  }
}
```

No sensitive functionality behind the gate — the free tier remains a
complete SIEM. This is a *value-add* paywall, not a *cripple* paywall.

## How the license mechanism works

For the demo, verification is a local HMAC-SHA256 check with the
tier + expiry encoded in base32 and a truncated signature — see
`backend/app/security/license.py::verify`. A real deployment would
replace `verify()` with a call to a licensing server (Keygen, Paddle,
LemonSqueezy) — the rest of the codebase never changes.

The demo keys `AEGIS-DEMO-*` and `AEGIS-EDUC-*` are constant-time
matched against a whitelist, so an attacker can't brute-force a key
by measuring response time.

## Pricing (indicative)

For the graduation defense, treat these as illustrative:

| Tier | Price (indicative) |
|---|---|
| Trial | Free 30 days |
| Educational | Free with .edu email |
| Business | $199 / month per instance |
| Enterprise | Contact sales |

## Data protection

- Uploaded logs are processed **in memory only** — no `Log` row is
  inserted into the live SIEM's `logs` table.
- The generated report is stored in a separate `analysis_reports`
  table with the uploader's username, byte size, and JSON summary.
- The original uploaded file is **not** persisted — only the summary
  survives, so a re-download regenerates the HTML from the summary
  rather than re-reading the file.
- Admin-only delete removes the report row.
- Retention purge (`POST /api/retention/purge`) does **not** touch
  the analysis-reports table — analysis history is out of scope for
  the operational-data lifecycle.

## Verifying the feature works

```bash
# Activate the demo key
curl -X PATCH http://localhost:8000/api/license/activate \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"key":"AEGIS-EDUC-6M9N-4W7X-C1AV"}'

# Upload a sample log file
curl -X POST http://localhost:8000/api/analysis/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/var/log/auth.log"

# List reports
curl http://localhost:8000/api/analysis -H "Authorization: Bearer $TOKEN"

# Download printable HTML
curl http://localhost:8000/api/analysis/1/download -H "Authorization: Bearer $TOKEN" -o report.html
```
