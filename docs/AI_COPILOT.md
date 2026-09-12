# AegisIQ — AI Copilot

> LLM-augmented alert triage. Turns "30 alerts an analyst can't read" into
> "3 investigation stories she has to act on."
>
> **Files:** `backend/app/ai/` (module) · `backend/app/api/routes/copilot.py` (API)
> **Provider-agnostic:** OpenAI, Anthropic, or local Ollama.

---

## Why this exists

A Tier-1 SOC analyst reads 200-500 alerts per shift. 95% are false
positives. She has 3-5 minutes to decide whether each one deserves
Tier-2 escalation. Human triage doesn't scale.

AI Copilot solves two chunks of that:

1. **Explain any alert in plain language** — analyst clicks an alert,
   gets a 4-sentence natural-language summary in Arabic or English,
   with a false-positive likelihood score, recommended actions, and
   questions to investigate.

2. **Cluster alert bursts** — 30 raw alerts → 3 "investigation stories"
   ranked by priority. Instead of scrolling a wall of rows, the
   analyst reads three paragraphs.

---

## Architecture

```
Analyst clicks "Explain" on alert #187
        │
        ▼
POST /api/copilot/explain/187  {lang: "ar"}
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│ CopilotService.explain_alert(db, 187, lang="ar")        │
│   1. load Alert #187 + up to 15 related logs (same IP)  │
│   2. build bilingual prompt (SYSTEM_ANALYST_AR/EN)      │
│   3. call provider.chat(...) with json_mode=true        │
│   4. parse the JSON envelope robustly                   │
│   5. return {ai_status, alert_id, lang, analysis}       │
└─────────────────────────────────────────────────────────┘
        │
        ▼ (returned to UI as JSON)
{
  "ai_status": "ok",
  "analysis": {
    "summary": "محاولة اختراق SSH من 203.0.113.42",
    "why_it_matters": "IP معروف بحملات brute force ...",
    "confidence": "high",
    "false_positive_likelihood": 0.05,
    "attack_narrative": "المهاجم بدأ بـ 6 محاولات فاشلة ...",
    "recommended_actions": ["حظر IP", "تفعيل MFA للحسابات المتأثرة"],
    "questions_to_investigate": ["هل هناك محاولات من IPs أخرى في نفس الشبكة؟"]
  }
}
```

## Provider abstraction

`app/ai/providers.py` implements three backends behind a common `chat()`
interface. Swapping providers is a config change — no code change.

| Provider | When to use | Env vars |
|---|---|---|
| **openai** | Fastest, best-quality, cheapest per call for small models | `OPENAI_API_KEY`, `AI_MODEL=gpt-4o-mini` |
| **anthropic** | Deeper analysis on complex correlated alerts | `ANTHROPIC_API_KEY`, `AI_MODEL=claude-3-5-haiku-latest` |
| **ollama** | **Air-gapped / regulated** — data never leaves the customer premises | `OLLAMA_URL`, `AI_MODEL=llama3.2` |
| **disabled** | AI off — endpoints return `ai_status: "degraded"` with a rules-based fallback | (default) |

### Enable OpenAI (fastest to try)

```bash
export AI_PROVIDER=openai
export OPENAI_API_KEY=sk-...
export AI_MODEL=gpt-4o-mini    # $0.15 per 1M input tokens as of 2026
```

### Enable Ollama (air-gapped, free)

```bash
# On the SIEM host or on a dedicated LLM box
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
ollama serve

# On the SIEM
export AI_PROVIDER=ollama
export OLLAMA_URL=http://<llm-host>:11434
export AI_MODEL=llama3.2
```

## API endpoints

### `GET /api/copilot/status`
Cheap health probe. Does NOT call the LLM. Returns:
```json
{"enabled": true, "provider": "openai", "model": "gpt-4o-mini",
 "note": "AI-augmented triage available"}
```

### `POST /api/copilot/explain/{alert_id}`
Body: `{"lang": "ar" | "en"}`. Returns the deep analysis object shown
above. Rate-limited (mutate_limiter, 60/min/IP).

### `POST /api/copilot/triage`
Body: `{"alert_ids": [1, 2, ...], "lang": "ar" | "en"}`. Returns:
```json
{
  "ai_status": "ok",
  "alerts_analyzed": 30,
  "lang": "ar",
  "stories": [
    {
      "title": "حملة brute force من روسيا",
      "severity": "critical",
      "attacker_profile": "IP: 203.0.113.42 (AS12345, Moscow)",
      "kill_chain_stage": "exploitation",
      "alert_ids": [1, 3, 7, 12, 18],
      "recommended_priority": 10,
      "one_sentence_summary": "..."
    }
  ],
  "outliers": [22, 25],
  "campaign_overlap": "قصتان تبدوان من نفس المهاجم"
}
```

## Fail-open design

Every code path treats the LLM as best-effort. Provider unreachable,
misconfigured, rate-limited, or returning garbage? Endpoints still
return HTTP 200 with `ai_status: "degraded"` and a rules-based
fallback (e.g., group alerts by `source_ip`). **The SIEM must never go
down because OpenAI is having a bad day.**

## Cost model (2026 prices)

| Endpoint | Tokens in | Tokens out | Cost/call (gpt-4o-mini) |
|---|---|---|---|
| explain | ~800 (alert + 15 events) | ~300 | ~$0.0002 |
| triage (30 alerts) | ~2000 | ~1200 | ~$0.001 |

**Per SOC analyst per day** (~200 explain calls + 20 triage): **~$0.06/day**. Ollama = $0.

## Privacy

- No customer data is used for LLM training (documented in providers.py).
- Ollama backend keeps data 100% on-premises.
- Prompts include `raw_log` truncated to 400 chars (see `_log_as_dict`).
- Anthropic and OpenAI have DPAs available — required for GDPR compliance.

*See also: `DEFENSE_LAYERS.md`, `SECURITY.md`, `COMPLIANCE.md`.*
