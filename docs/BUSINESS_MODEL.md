# AegisIQ — Business Model & Go-to-Market

> Honest business plan. No hockey-stick projections, no vanity metrics.
> A path from graduation project → first paying customer → sustainable
> revenue that funds the team.

---

## The problem AegisIQ solves

**Small and medium businesses (10-500 employees) have zero good SIEM
options.** Splunk costs $150+/GB/day. Wazuh needs a full-time engineer
to run. Microsoft Sentinel assumes an Azure-first stack. Result: 92%
of SMBs run **no SIEM at all** (Verizon DBIR 2024 — SMB segment).

Meanwhile:
- **43% of cyberattacks target SMBs** (Verizon)
- Average breach cost for an SMB is **$120k-$1.24M** (IBM Cost of a Breach 2024)
- Median SMB cannot recover — **60% close within 6 months of a breach**

The market gap: an SIEM cheap enough for a $50/month budget, simple
enough for a solo IT admin to deploy, powerful enough to catch real
attacks, and **compliant enough to help pass SOC 2** (which most SMB
enterprise customers now demand).

## Target market — 3 concentric circles

### Ring 1 (year 1): Arabic-speaking SMBs in the GCC & Levant
- **Size:** ~450,000 SMBs in Jordan, Saudi Arabia, UAE, Egypt, Kuwait
- **Why here:** zero direct competition — Splunk, Sentinel, and Wazuh
  are English-only. Cultural fit + regional support = defensible moat.
- **Pain:** rising ransomware, national CERT regulations (SDAIA in KSA,
  NCA in UAE) increasingly demand SIEM evidence for licensed sectors.
- **Willingness to pay:** $50-500/month for a 5-25 employee firm.
- **First 10 customers:** direct outreach — my professional network,
  Jordan Cybersecurity Association, LinkedIn.

### Ring 2 (year 2): SMBs globally (English-speaking)
- **Size:** ~4.5M businesses with 10-250 employees in EU + US
- **Why later:** SEO + content marketing take 12+ months to compound.
- **Distribution:** Product Hunt launch, HN Show HN, security newsletter
  sponsorships, integrations page on GitHub.

### Ring 3 (year 3+): MSPs (Managed Service Providers)
- **Size:** ~40k security MSPs globally
- **Why lucrative:** one MSP customer = 10-50 SMB tenants.
- **Model:** multi-tenant fork ($299/tenant/month at wholesale).

## Pricing tiers (real, not aspirational)

| Tier | Price | Target | Value delivered |
|---|---|---|---|
| **Community** | Free forever | Hobbyists, small startups, students | Full features, self-host, MIT license |
| **Pro** | $49/analyst/month | 5-50 employee firms with 1-3 SOC analysts | Managed cloud, SLA, priority support, AI included |
| **Enterprise** | Custom (start $2000/mo) | 50+ employee firms or regulated industries | On-prem, SSO, dedicated engineer, air-gapped Ollama |

### Unit economics (Pro tier)

- **Revenue per customer:** $49 × 2 analysts (median) = **$98/month = $1,176/year**
- **Cost per customer (cloud):** Render/Fly Pro tier + PostgreSQL = ~$40/month
- **AI cost per customer:** ~$5/month (gpt-4o-mini, 100 explain calls/day)
- **Gross margin:** ~54% at $98/mo → improves with scale (bulk API discounts)
- **CAC target:** ≤ $200 (payback in 2 months)

### Path to $100k ARR (Year 1 conservative)

**100 Pro customers × $98/month × 12 = $117,600 ARR**

- Reach: 100 SMBs from ~450k target pool = **0.02% conversion**
- Feasible? Yes — through targeted outreach to Jordan Cybersecurity
  Association members, LinkedIn direct DMs (200 conversations →
  60 demos → 15 paying customers/quarter × 4 = 60/year, plus organic).

**With MSP channel (Year 2), $100k → $500k ARR** is realistic given
MSPs bring 10-50 tenants each.

## Product moats — why this isn't just a Wazuh clone

1. **AI Copilot** — nobody in the SMB tier ships this. Adding it takes
   6 months of engineering + $50k in prompt-engineering iteration.
2. **Native Arabic** — 2-year head start against any English-first
   incumbent that wants to translate.
3. **15-minute deploy** — Splunk/Wazuh/Sentinel all take days.
   Rebuilding this experience requires re-architecting.
4. **Compliance automation** — SOC 2 evidence reports from live data
   is a $15k-$40k consultant equivalent. Building this properly needs
   a compliance-specialist auditor's input (moat: expensive to replicate).
5. **Open-source pull** — MIT license → free customer acquisition
   channel via GitHub, HN, dev.to. Wazuh proved this works.

## Non-moats (be honest)

- **Detection rules alone** — Splunk ES ships 5000+. Ours is 8. Sigma
  compatibility helps (SigmaHQ = 3000+ community rules) but we
  benefit from a shared pool, not a proprietary one.
- **Storage backend** — SQLite/PostgreSQL/OpenSearch/ClickHouse are
  all commodity. LogStore abstraction is good engineering, not IP.
- **SOAR execution** — every SOAR platform does block_ip. Table stakes.

## Go-to-market — first 90 days

- **Week 1-2:** landing page live (marketing/landing.html), buy
  `aegisiq.io`, publish on Product Hunt + Show HN.
- **Week 3-4:** publish 3 blog posts — "SOC 2 in 30 seconds", "Why
  your Wazuh install is broken", "Arabic-language SOC ops guide".
- **Week 5-8:** 100 LinkedIn DMs to Jordanian/Saudi CTOs of 10-50
  employee firms. Offer 30-min "SIEM readiness assessment" call.
  Target: 20 demo calls, 5 pilots.
- **Week 9-12:** 5 pilots → 3 paying customers at $49/mo. First
  reference logos on the landing page. First $588 of MRR.

## What I need next

- **Domain + branding:** aegisiq.io (~$40/year) + logo ($50-500 on Fiverr).
- **Legal:** register a company in Jordan or Delaware C-Corp for future
  fundraising. Terms of Service + Privacy Policy templates ($200 lawyer review).
- **Payments:** Stripe (Jordan supports Stripe Atlas) for the Pro tier.
- **Support:** Free Slack workspace for Community users, Intercom for Pro.
- **First hire (month 6):** part-time SDR/BDR for the LinkedIn outreach engine.

## Honest risks

1. **AI cost creep** — if per-call cost triples, Pro tier margin dies.
   Mitigation: Ollama fallback + prompt caching + model swap freedom.
2. **Free plan cannibalization** — Community users never upgrade.
   Mitigation: Pro's *managed* value (SLA, backup, no infra headaches).
3. **Enterprise sales cycle** — 6-12 month deals. Don't count on
   Enterprise revenue in Year 1.
4. **Splunk / MS release "AI Copilot"** — they will. Our answer:
   speed (deploy in 15 min vs their days), price (SMB tier they can't
   match), and Arabic native (they won't build).

## The honest valuation math

At $1,176/year ARR/customer × 100 customers = **$117,600 ARR** by
end of Year 1. Applying the median SaaS multiple for pre-seed
security tools (5-8× ARR), that puts the company valuation at
**$580k - $940k** — with real customers, real revenue, real defensible
IP.

The **$100k valuation** the professor mentioned is achievable with
**~85 Pro customers OR 15 Enterprise customers OR 1 acquisition
conversation with a mid-market MSP.** All three are realistic within
12 months of focused execution.

---

*This document is honest, not marketing. It's the plan we'd show a
seed investor, not the customer. Keep it internal.*
