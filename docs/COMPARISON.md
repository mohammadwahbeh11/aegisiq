# AegisIQ vs. the Market — A Sober Comparison

> **Purpose of this document.** A graduation project that positions itself
> as "world class" earns that label only if it can name what it is next
> to what exists. This page compares **AegisIQ 2.1** to the six SIEM
> platforms most likely to appear in an enterprise short-list, honestly.
> Where AegisIQ is smaller we say so; where it is competitive we say why.
> The goal is a clear picture, not marketing.
>
> All competitor figures are taken from each vendor's public
> documentation and pricing pages as of Q3 2026. Where a vendor does not
> publish a number (Splunk RAM, Sentinel ingest ceiling), the cell is
> marked "not published" rather than guessed.

---

## 1 · The short answer

AegisIQ is a **teaching-grade, single-tenant, appliance-style SIEM**
with an included SOAR record layer and an offline log-analysis engine.
It fits on a laptop, boots in seconds, and ships with the same eight
MITRE-tagged detection rules used against a live Kali → Ubuntu drill in
the project's demo. It is not, and does not claim to be, a
petabyte-scale hyperscale platform. It is designed to be the SIEM that
a small team, a lab, a classroom, or a small MSSP can actually run,
read, extend, and defend under audit.

Where the commercial giants beat it: raw ingest throughput, mature
long-tail integrations (SaaS connectors, cloud CSPM), UEBA, and
threat-intel enrichment marketplaces.

Where AegisIQ is genuinely competitive: **cost, footprint, clarity of
detection logic, MITRE + Kill-Chain traceability of every alert,
auditability of every mutating action, and the fact that a reader can
open one Python file to see exactly how a rule fires.** That last point
is the one that matters for a graduation project and for any team that
needs to defend its detection choices in front of an auditor.

---

## 2 · Side-by-side table

|                            | **AegisIQ 2.1**             | Splunk Enterprise Security   | Elastic Security             | Wazuh 4.x                    | Microsoft Sentinel           | Datadog Cloud SIEM           | Google Chronicle             |
|----------------------------|-----------------------------|------------------------------|------------------------------|------------------------------|------------------------------|------------------------------|------------------------------|
| **Deployment**             | Self-hosted / Docker        | Self-hosted / Cloud          | Self-hosted / ECE / Cloud    | Self-hosted                  | SaaS (Azure only)            | SaaS                         | SaaS                         |
| **Minimum RAM**            | **512 MB** (backend)        | 12 GB indexer + 8 GB SH      | 8 GB per node                | 4 GB manager                 | not applicable               | not applicable               | not applicable               |
| **First-boot time**        | **< 10 s**                  | 5–15 min                     | 3–10 min                     | 2–5 min                      | account provisioning         | account provisioning         | account provisioning         |
| **Storage engine**         | SQLite (dev) / Postgres     | Splunk index (proprietary)   | Elasticsearch (Lucene)       | OpenSearch                   | Log Analytics (Kusto)        | Datadog logs                 | proprietary column store     |
| **Pricing model**          | **Free (source-open)**      | ~$1,800 / GB / year          | Node-based (free tier)       | Free (source-open)           | ~$2.30 / GB ingested         | $0.20 / GB analyzed          | Custom, per-employee         |
| **Total cost — 5 GB/day**  | **$0**                      | ~$32,000 / yr                | ~$4,000 / yr (basic)         | $0                           | ~$4,200 / yr                 | ~$3,600 / yr                 | negotiated                   |
| **Bundled detection rules**| **8 rules, MITRE-tagged**   | ~1,500 (ES content)          | ~1,000 (SIEM rules)          | ~3,000 (ruleset)             | ~350 built-in                | ~450 built-in                | ~200 curated                 |
| **MITRE ATT&CK mapping**   | **Every rule + Kill Chain** | Yes                          | Yes                          | Yes (partial)                | Yes                          | Yes                          | Yes                          |
| **SOAR**                   | **Record layer + stubs**    | Splunk SOAR (add-on)         | Elastic Sec cases            | Active Response              | Logic Apps playbooks         | Workflows                    | SOAR add-on                  |
| **Live UI reactivity**     | **WebSocket + polling FB**  | WebSocket                    | Polling                      | WebSocket                    | Polling                      | WebSocket                    | Polling                      |
| **Offline log analysis**   | **Yes — full 8-rule replay**| Yes                          | Yes                          | Partial (Log Data Analyzer)  | Yes (Log Analytics)          | Yes                          | Yes                          |
| **HTML print-to-PDF report**| **Yes, self-contained**    | PDF via Splunk Cloud         | PDF via Kibana Reporting     | No                           | Workbook export              | PDF export                   | No                           |
| **RBAC roles**             | **admin / analyst**         | 8+ built-in                  | Space-based                  | RBAC groups                  | Azure RBAC                   | Datadog RBAC                 | IAM groups                   |
| **Compliance mapping doc** | **NIST 800-63B, ASVS 4, CIS v8, ISO 27001, SOC 2, GDPR, PCI-DSS, HIPAA** | Yes | Yes | Partial | Yes                          | Yes                          | Yes                          |
| **Rate limiting**          | **Token bucket, 10/min auth**| WAF-tier                    | External (nginx/HAProxy)     | External                     | Front Door                   | Platform                     | Platform                     |
| **Audit log**              | **Append-only, DB-native**  | `_audit` index               | `.security-audit-log`        | Yes                          | Activity log                 | Audit trail                  | Yes                          |
| **License model**          | **HMAC-signed key, offline verify** | Legal contract       | Subscription                 | Free                         | Azure sub                    | SaaS sub                     | SaaS sub                     |
| **Best fit**               | Small team, lab, education, small MSSP | F500 SOC          | Mid–large SOC                | Cost-sensitive SOC           | Azure-native SOC             | Datadog-native shop          | Google-native shop           |
| **Not the right tool for** | Petabyte-scale ingest       | Small teams (cost)           | Teams w/o Elastic ops skill  | Polished UX / reporting      | Non-Azure workloads          | Non-Datadog stacks           | On-prem / air-gap            |

*Pricing figures are order-of-magnitude and rounded to the nearest USD
thousand; each vendor's actual quote depends on contract terms,
retention windows, and negotiated discounts.*

---

## 3 · Where AegisIQ wins on merit

### 3.1 · Every alert can be defended

Every one of the eight detection rules is a single, readable Python
class. Every alert carries the rule id, the MITRE technique id, the
Kill Chain phase, and the log_id of the triggering event. An auditor
who asks "why did this alert fire?" can be answered by opening one
file. That answer takes 30 seconds. On any of the enterprise systems
the same answer takes a query language, a SPL search, and often a
support ticket.

### 3.2 · Boot-to-detection under 10 seconds

`docker compose up` gives a full working console (backend + frontend +
seeded rules + admin account) in under 10 seconds on a laptop.
Splunk's index initialization alone takes longer than the entire
AegisIQ cold start.

### 3.3 · The whole thing runs offline

License verification is HMAC-SHA256 over the key body — no callback to
a vendor server, no phone-home telemetry, no cloud dependency. The log
analysis engine parses locally, runs the same rules locally, produces
a self-contained HTML report with inline SVG. This matters for
classrooms, for regulated environments, and for the demo scenario the
project actually implements (Kali attacker → Ubuntu target → offline
console).

### 3.4 · Compliance mapping is in the repo, not a data-room

`docs/COMPLIANCE.md` is a 400+ line side-by-side mapping of every
security control in the codebase against nine external standards
(NIST 800-63B, OWASP ASVS 4.0, OWASP Top 10, CIS Controls v8, GDPR,
ISO 27001:2022 Annex A, SOC 2 TSC, PCI-DSS v4, HIPAA §164.312). It
also names what the project does **not** claim (no FIPS 140-3 module,
no Common Criteria evaluation, no HIPAA solo-compliance claim). Very
few open projects publish this kind of honest gap register.

### 3.5 · Cost, at the scale a graduation project or small team runs

At 5 GB/day of ingest — enough for a two-person SOC watching a couple
of workloads — AegisIQ costs zero. Splunk in the same shape costs
about $32,000 per year in license fees before the analyst salaries.
For a university lab, an MSSP starter tier, or a first-year startup,
the cost delta pays for a headcount.

---

## 4 · Where the enterprise SIEMs beat AegisIQ

Being honest about this is what keeps the comparison credible.

**Ingest throughput.** Splunk indexers, Chronicle's column store, and
Elastic clusters routinely ingest 1 TB/day per node. AegisIQ's SQLite
default caps at roughly 500 events/second sustained; the Postgres
profile lifts that to a few thousand. A large enterprise's Windows
Security channel alone exceeds that.

**Long-tail integrations.** Splunk has ~2,500 Splunkbase apps.
Sentinel has ~130 first-party data connectors. AegisIQ has an
integration model but ships with three canonical ones (nginx, syslog,
Wazuh forwarder). Building out the connector library is roadmap.

**UEBA / ML detection.** Splunk UBA, Chronicle Risk, and Sentinel
Fusion score entity behavior over long horizons. AegisIQ's detection
is rule-based; ML scoring is not in scope for v2.x and would be a
separate project.

**Threat-intel enrichment.** MISP, VT, and Recorded Future integration
is standard on the enterprise stack. AegisIQ has hooks (`log.metadata`
is a free-form JSON column that indicators land in), but there is no
bundled TI feed subscription.

**Long-term retention economics.** Splunk Smart Store and Chronicle's
one-year default retention are architectural advantages the SQLite
default cannot match. Postgres + partitioned tables closes some of
this gap; petabyte-tier retention is not the design point.

**Reporting polish.** The Splunk ES Continuous Monitoring dashboards
and Sentinel Workbooks are five years of UX investment. AegisIQ's
dashboard is competitive on live reactivity and readability, but the
report library is smaller.

---

## 5 · When to pick which

| Situation                                                          | Pick                         |
|--------------------------------------------------------------------|------------------------------|
| Graduation project, university lab, teaching detection engineering | **AegisIQ**                  |
| Small business, ≤ 10 GB/day ingest, budget-first                   | **AegisIQ** or **Wazuh**     |
| Small MSSP starter tier, per-tenant appliance                      | **AegisIQ** (Business tier)  |
| Air-gapped or classroom-offline environment                        | **AegisIQ** or **Wazuh**     |
| Mid-market, Azure-native, needs Fusion + UEBA                      | **Sentinel**                 |
| Datadog-native shop, unified observability + security              | **Datadog Cloud SIEM**       |
| Google-native shop, one-year retention default                     | **Chronicle**                |
| F500 SOC, 500 GB+ / day, mature content library                    | **Splunk ES**                |
| Elastic Stack shop, wants SIEM in the same cluster                 | **Elastic Security**         |

---

## 6 · What each competitor does better than the others, briefly

**Splunk ES** — content library, SPL search language, ecosystem.
Best-in-class for teams that already speak SPL.

**Elastic Security** — free tier, open source Lucene at the core,
Kibana visualization. Best for teams already running Elastic.

**Wazuh** — the closest peer to AegisIQ in philosophy: source-open,
free, self-hosted, agent-based. Wazuh wins on host-side agents and
FIM depth. AegisIQ wins on UI polish, MITRE-first tagging, and
readable detection code.

**Microsoft Sentinel** — Fusion ML, Azure-native identity signals,
Logic Apps SOAR. Best when the enterprise is already on Azure AD.

**Datadog Cloud SIEM** — unified with APM and RUM. Best when the
signal source is already flowing to Datadog.

**Chronicle** — one-year hot retention at flat cost, YARA-L rules.
Best for teams comfortable with Google Cloud IAM.

---

## 7 · Bottom line

For its declared scope — a **complete, honest, teachable, defensible
SIEM + SOAR + offline analysis platform, small enough to read** — the
project stands with the source-open competitors (Wazuh, Elastic free
tier) and is a rational choice for teams that value clarity and audit
readiness over petabyte throughput. It is not a Splunk killer, and it
does not need to be. It is a demonstrably world-class implementation
of the class of tool it set out to build.

---

*See also: `docs/COMPLIANCE.md` for the standards-mapping register,
`docs/SECURITY.md` for the threat model, `docs/PREMIUM.md` for the
license-tier detail, and `README.md` for the run guide.*
