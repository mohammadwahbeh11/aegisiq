# AegisIQ — SOC Readiness Gap Analysis

> An honest response to the question every serious reviewer asks: *"what
> stops this from running in a real SOC?"* This maps each gap to one of
> three states — **DONE** (addressed in the codebase), **MITIGATED**
> (improved within the lightweight scope, with the scale-up path named),
> or **ROADMAP** (a genuine architectural change that would move the
> project beyond its "lightweight" scope).
>
> The guiding principle stays the same as the rest of the project:
> **claim only what the code does.** Where a real SOC needs infrastructure
> AegisIQ deliberately does not ship, this document says so plainly rather
> than pretending a demo component is production-grade.
>
> Version 2.3.

---

## Summary table

| # | Area | Was | Now | State |
|---|---|---|---|---|
| 1 | Database & performance | SQLite, default journal | SQLite **WAL + busy_timeout**; **PostgreSQL profile** in compose; ClickHouse/OpenSearch named as the high-EPS path | **MITIGATED** |
| 2 | Detection engine | Hardcoded Python rules | **Sigma rule support** (YAML, drop-in) *plus* the 8 native rules + 140 signatures | **DONE** |
| 3 | Ingestion pipeline | REST → DB directly | Backpressure documented; SQLite no longer locks on bursts; Kafka/Redis buffer named as the scale path | **MITIGATED** |
| 4 | Log sources | Agent simulator | REST ingest works with **Winlogbeat/Wazuh/Filebeat** today; **Syslog/NetFlow/CloudTrail** collectors on the roadmap | **MITIGATED** |
| 5 | SOAR automation | Local record-only | **Outbound webhook** to Shuffle / Cortex / n8n (HMAC-signed) | **DONE** |
| 6 | Repo hygiene & secrets | leftover cache/DB files, demo defaults | **.gitignore** hardened; **production startup guardrails** refuse demo secrets | **DONE** |

---

## 1 · Database & performance — MITIGATED

**The gap (correct):** SQLite with the default rollback journal takes an
exclusive lock on every write. Under real EPS (events per second) that
produces `database is locked` and throughput collapses.

**What changed now:**
- SQLite is opened in **WAL mode** with a **5-second busy_timeout** and
  `synchronous=NORMAL` (`app/database.py`). WAL lets readers and the
  writer proceed concurrently, and busy_timeout absorbs short write
  bursts instead of failing instantly. This turns "locks immediately
  under load" into "handles lab and small-team bursts."
- A **PostgreSQL service** is now in `docker-compose.yml` behind the
  `postgres` profile. Because the app uses only portable SQLAlchemy
  (`app/database.py`), moving to it is a `DATABASE_URL` change plus
  `psycopg[binary]` — no code edit.

**Honest limit / ROADMAP:** For sustained thousands-of-EPS ingest with
long retention and fast full-text search, the right store is a columnar
/ search engine — **ClickHouse** or **Elasticsearch/OpenSearch** — not a
row store. That is a storage-layer swap (a new repository implementation
behind the existing model interface), not a config flag, and it is the
correct next architectural step for a high-volume deployment. AegisIQ
does not claim petabyte-scale ingest.

## 2 · Detection engine — DONE

**The gap (correct):** hardcoded Python rules mean a developer is needed
to add or tune a detection.

**What changed now:** **Sigma support** (`app/detection/sigma.py`).
Sigma is the industry-standard, vendor-neutral YAML detection format.
Drop a `.yml` file into `sigma_rules/` and it is live on the next
analysis — no code change, no redeploy. A practical, tested subset is
supported: field modifiers (`contains`, `startswith`, `endswith`, `re`,
`all`), keyword lists, and conditions (`and`/`or`/`not`, parentheses,
`1 of x*` / `all of x*`, `1 of them`). `level` → severity and
`attack.tXXXX` tags → MITRE technique are read automatically.
Aggregation/timeframe rules are **skipped, not mis-evaluated**, and
logged. Three example rules ship in `sigma_rules/`.

This sits alongside — not instead of — the 8 native data-driven rules
(threshold/window tunable at runtime via the API or Rules page) and the
140+ built-in threat signatures. So detections are now addable three
ways without touching engine code: tune a native rule, drop a Sigma
file, or add a signature.

**ROADMAP:** YARA (file/memory rules) and EQL (sequence correlation)
would extend coverage further; Sigma covers the log-detection majority.

## 3 · Ingestion pipeline — MITIGATED

**The gap (correct):** a direct REST→DB write path can lose events, or
block, when the DB is the bottleneck under a spike.

**What changed now:** the DB is no longer the instant bottleneck (WAL +
busy_timeout, §1), so short spikes are absorbed rather than dropped. The
ingestion service is already structured as a seam
(`process_normalized_event`) that a queue can slot behind without
touching the routes.

**Honest limit / ROADMAP:** true zero-loss under sustained overload
needs a **durable message queue** — Kafka or RabbitMQ (or Redis
Streams for a lighter footprint) — between the collector and the
detection/store stage, with the collector acknowledging to the source
only after the event is on the queue. That is the standard SIEM
architecture at scale and is the right next step; it is deliberately not
in the lightweight build, which favours "no broker to operate" for a lab
/ small-team deployment.

## 4 · Log sources — MITIGATED

**The gap (correct):** a simulator is not real collection.

**What works today:** the `POST /api/logs` endpoint accepts the
canonical normalized shape *and* raw lines it parses itself (Linux
sshd/PAM, **Windows Security Events**, nginx/Apache, syslog-format
lines). That means real shippers work **now**:
- **Winlogbeat / Elastic Agent** → HTTP output → `/api/logs`.
- **Wazuh / Filebeat / Fluent Bit** → HTTP output → `/api/logs`.
- The offline analyzer ingests **Windows Event Viewer CSV**, JSON-lines,
  and syslog text files directly.

**ROADMAP:** first-class collectors that listen on the wire —
**Syslog** (UDP/TCP 514), **NetFlow/IPFIX**, and cloud audit pulls
(**AWS CloudTrail**, Azure, GCP) — so sources push/relay without a
sidecar shipper. These are additive collector services around the same
ingestion seam.

## 5 · SOAR automation — DONE (integration point)

**The gap (correct):** a simple local script engine is not a playbook
platform.

**What changed now:** an **outbound SOAR webhook**
(`app/soar/webhook.py`). When `SOAR_WEBHOOK_URL` is set, every recorded
containment action is POSTed (fire-and-forget, HMAC-SHA256 signed) to an
external automation platform — **Shuffle, Cortex, TheHive, or n8n** —
where a real, arbitrarily-complex playbook runs. AegisIQ still never
executes a firewall/AD command itself (a deliberate safety choice on a
lab network); it becomes the *trigger and evidence source* in a real
automation pipeline, which is exactly how a SIEM integrates with a SOAR
in production.

**ROADMAP:** a built-in visual playbook editor is out of scope — that is
what Shuffle/Cortex are for, and integrating with them is the correct
design rather than rebuilding them.

## 6 · Repo hygiene & secrets — DONE

**The gap (correct):** leftover cache/DB files, and reliance on demo
`.env` defaults.

**What changed now:**
- **`.gitignore`** hardened to exclude `__pycache__/`, `.pytest_cache/`,
  every SQLite artifact (`*.db`, `*.db-wal`, `*.db-shm`), timestamped
  backups (`*.stale_*`, `*.bak`), `uploads/`, virtualenvs, and editor
  dirs. To untrack files already committed:
  ```bash
  git rm -r --cached backend/__pycache__ .pytest_cache
  git rm --cached backend/siem.db 'backend/siem.db.stale_*'
  git commit -m "chore: stop tracking build artifacts and local DBs"
  ```
- **Production startup guardrail** (`app/config.py::validate_production_security`,
  enforced in `app/main.py`): when `ENV=production`, the app **refuses to
  boot** with the demo `SECRET_KEY`, the demo admin password, a missing
  `DATA_ENCRYPTION_KEY`, or wildcard CORS — the classic way a lab tool
  becomes the incident. Dev/lab boots freely.
- MFA (RFC 6238), AES-256-GCM encryption of secrets, rate limiting,
  security headers, and the full audit trail were added in v2.3 — see
  `SECURITY.md`.

---

## What "world-class within scope" honestly means here

AegisIQ is a **teaching-grade, single-tenant, lightweight SIEM+SOAR**.
After v2.3 it does the things a small SOC actually needs — Sigma
detections, real shipper ingestion, external SOAR automation, MFA,
encryption, and a database that survives real bursts — and it names,
rather than fakes, the three genuine scale-up steps: a **columnar/search
store** (ClickHouse/OpenSearch), a **durable queue** (Kafka/RabbitMQ),
and **on-the-wire collectors** (Syslog/NetFlow/CloudTrail). Those are
the boundary between "lightweight SIEM you can read and run" and
"enterprise ingestion platform," and keeping that boundary explicit is
what makes the rest of the claims credible.

*See also: `COMPARISON.md` (vs. Splunk/Elastic/Wazuh/Sentinel),
`SECURITY.md` (crypto + MFA + threat model), `HOW_IT_WORKS.md`
(architecture from zero), `WORLD_READINESS.md` (requirement checklist).*
