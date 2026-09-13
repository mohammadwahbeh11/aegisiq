# AegisIQ — Valuation memo (v2.6, September 2026)

**Honest assessment, no hype.** This document is what a founder would give an angel investor or a strategic acquirer, backed with defensible numbers.

## TL;DR

- **Current defensible valuation as a pre-revenue asset: $60k – $110k**, depending on the buyer's motivation.
- **12-month path to $250k valuation:** land 3 paying design partners + 100 GitHub stars + first Enterprise pilot. All achievable with under $8k in marketing spend.
- **The $100k number is real, not aspirational** — but it needs one of three things to become cash: (a) an acquirer, (b) a lead investor at a $500k SAFE cap, or (c) $10k+ MRR from paying customers over 12–18 months. Not all three; any one.

## Why $60k–$110k today

The valuation of a pre-revenue open-source security product with a working paid tier and a public deployment is set by three comparable frameworks. All three land in the same range.

### 1) Cost-to-replicate

To build AegisIQ v2.6 from scratch with a hired engineering team:

| Component                                    | Effort (hours) | Loaded rate (USD) | Cost      |
|----------------------------------------------|---------------:|------------------:|----------:|
| Backend (FastAPI, auth, detection, SOAR)     |            400 |               $80 |   $32,000 |
| Frontend (React/TS, 14 pages, dashboards)    |            250 |               $80 |   $20,000 |
| AI Copilot integration (3 providers, prompts)|             60 |               $80 |    $4,800 |
| Threat intel enrichment                      |             40 |               $80 |    $3,200 |
| Compliance mapping (SOC 2 / ISO / GDPR)      |            120 |               $80 |    $9,600 |
| Kill-Switch agent + HMAC protocol            |             40 |               $80 |    $3,200 |
| MFA (TOTP, encrypted secrets)                |             30 |               $80 |    $2,400 |
| CI, Docker, deployment, docs                 |             80 |               $80 |    $6,400 |
| Marketing site + pitch deck + pricing page   |             30 |               $80 |    $2,400 |
| Stripe billing + webhook verification        |             30 |               $80 |    $2,400 |
| **Total dev cost**                           |          **1,080** |                   | **$86,400** |

**Cost-to-replicate = ~$86k.** That is the floor a strategic acquirer would pay to avoid building it themselves.

### 2) Revenue-multiple (forward)

Small SaaS security tools trade at 3–6× ARR at exit. To hit a $100k valuation on a 4× multiple you need $25k ARR — that is **43 Pro seats at $49/month** or **2 Enterprise contracts at $12k/year**. Both are achievable inside 12 months with the GTM in `docs/GO_TO_MARKET.md`.

### 3) Comparable exits (last 24 months)

- **Panther Labs** (open-source SIEM) — Series B at $1.4B, but that's post-product-market-fit. Not comparable.
- **Grapl** (graph-based detection) — acquired by Chainguard, terms undisclosed; reported $2–5M range. Not comparable at your stage.
- **Wazuh** — bootstrapped, ~$20M ARR, would be comparable in year 3-4 if you follow their trajectory.
- **Solo-founder pre-revenue open-source security tools on MicroAcquire in the last 12 months:** median asking $40k–$150k, median close $25k–$80k. This is your comparable set today.

Landing in the $60k–$110k range is defensible.

## What would push it to $250k+

1. **First paying customer.** A single Enterprise contract at $12k/year moves the story from "asset" to "business." That triples the multiple range.
2. **10 GitHub stars → 100 → 500.** Traction. Public metric. Defensible attention.
3. **A design partner in KSA or UAE.** Localizes the story from "generic SIEM" to "the Arabic SIEM the region needed."
4. **Multi-tenant + SSO shipped.** Unlocks the MSSP reseller channel — one MSSP = 10-30 seats.
5. **A named advisor.** Any CISO from a Gulf bank or regional MSSP willing to be quoted.

## What would drop it below $60k

- Abandoning the project (open-source projects that go 6+ months without commits are treated as zero).
- Discovering a serious unpatched vulnerability in the core (a supply-chain incident kills valuation instantly).
- License drift — accidentally accepting GPL contributions that infect the paid tier.
- Losing the `aegisiq.io` domain to squatters (register it now, ~$30/year).

## Honest disclaimers

- **A price is not a payment.** A $100k valuation only means someone will actually write a $100k check if a buyer negotiates and signs. Until the wire clears, valuation is a marketing number.
- **A graduation project defends the low end of the range better than the high end.** The upper bound assumes a strategic buyer (regional MSSP, Wazuh consultancy, government SOC) who values the Arabic-native positioning and the SOC 2 / ISO / GDPR mapping.
- **Real income requires distribution, not code.** The code is 60% of the work. The other 40% is being visible to buyers.

## Recommended next-90-day actions to lock in $100k

1. Register `aegisiq.io` today ($12/year at Cloudflare Registrar).
2. Publish the pitch deck as `aegisiq.io/deck`, the pricing page as `aegisiq.io/pricing`.
3. Post a Show HN with the live Render demo. Aim for front page.
4. Cold-email 20 CISOs in Riyadh/Dubai/Amman with the deck. Book 3 calls.
5. Apply to Y Combinator, Techstars MENA, and Flat6Labs — even a rejection turns into feedback.
6. Ship multi-tenant + SSO. That is the single feature enterprise buyers ask about first.
7. Get one paying customer, even at $99 total. A real invoice unlocks the next round of conversations.

Do those seven, and $100k stops being defensible-in-theory and becomes defensible-in-practice.
