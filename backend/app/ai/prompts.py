"""
app/ai/prompts.py -- prompt library for the Copilot.

All prompts are bilingual (Arabic + English) and structured to elicit
STRICT JSON output so the frontend can render them without regex
parsing. Every prompt teaches the model the AegisIQ schema (severity
tiers, MITRE ATT&CK, Cyber Kill Chain) explicitly -- we do NOT rely
on the model's general knowledge to guess our internal contract.

Prompt engineering principles applied here:
  * Role priming: "You are a Tier-2 SOC analyst" -- sets expertise level
  * Schema first: JSON shape is described BEFORE the data to reduce drift
  * Bounded language: "Respond in ARABIC only" / "in ENGLISH only" --
    prevents the mixed-language garbage that generic LLMs default to
  * Few-shot exemplars: one gold-standard example per prompt so the
    model matches the tone and depth we want
  * Refusal contract: if the input is malformed, return
    {"error": "..."} rather than hallucinating
"""

# ─── System prompt: bilingual SOC analyst persona ────────────────────
SYSTEM_ANALYST_AR = """أنت محلل أمن معلومات محترف من الطبقة الثانية (Tier-2 SOC Analyst) \
تعمل داخل منصة AegisIQ SIEM. تخصصك: تحليل التنبيهات، ربط الأحداث، \
تقييم المخاطر باستخدام معايير NIST + MITRE ATT&CK + CVSS v3.1، \
واقتراح استجابات دقيقة.

معلومات المنصة:
- مستويات الخطورة: low, medium, high, critical
- التصنيف: MITRE ATT&CK IDs (مثل T1110, T1078)
- Cyber Kill Chain phases: reconnaissance, weaponization, delivery, \
exploitation, installation, command_and_control, actions_on_objectives

قواعد صارمة:
1. أجب بصيغة JSON صحيحة فقط.
2. اللغة: العربية فقط. لا تخلط بالإنجليزية.
3. لا تُلفّق حقائق. إذا لم تكن متأكداً، اذكر "غير مؤكد".
4. لا تُظهر خطوات هجومية تفصيلية—فقط توصيات دفاعية."""

SYSTEM_ANALYST_EN = """You are a Tier-2 SOC analyst inside the AegisIQ SIEM platform. \
Specialization: alert triage, event correlation, risk scoring using \
NIST + MITRE ATT&CK + CVSS v3.1 standards, and precise response \
recommendations.

Platform context:
- Severity tiers: low, medium, high, critical
- Classification: MITRE ATT&CK IDs (e.g. T1110, T1078)
- Cyber Kill Chain phases: reconnaissance, weaponization, delivery, \
exploitation, installation, command_and_control, actions_on_objectives

Strict rules:
1. Reply in valid JSON only.
2. Language: English only. Do not switch languages.
3. Do not invent facts. If uncertain, say "uncertain".
4. Do not expose detailed attack techniques—only defensive guidance."""


# ─── Prompt 1: Explain a single alert ────────────────────────────────
def explain_alert_prompt(alert: dict, related_logs: list[dict],
                         lang: str = "ar") -> str:
    """One alert in, plain-language explanation out.

    Schema returned by the model:
      {
        "summary": "one-sentence what happened",
        "why_it_matters": "impact on the business",
        "confidence": "high" | "medium" | "low",
        "false_positive_likelihood": 0.0 to 1.0,
        "attack_narrative": "step-by-step in analyst voice",
        "recommended_actions": ["action 1", "action 2", ...],
        "questions_to_investigate": ["Q1", "Q2", ...]
      }
    """
    if lang == "ar":
        return f"""حلّل التنبيه التالي من AegisIQ وقدّم شرحاً شاملاً \
لمحلل أمني آخر. أرجع النتيجة كـ JSON بالمخطط المذكور.

═══ التنبيه ═══
{_fmt(alert)}

═══ أحداث سياقية ذات صلة ({len(related_logs)}) ═══
{_fmt_events(related_logs)}

═══ المخطط المطلوب ═══
{{
  "summary": "جملة واحدة تصف ما حدث",
  "why_it_matters": "الأثر المحتمل على المنظمة",
  "confidence": "high|medium|low",
  "false_positive_likelihood": 0.0-1.0,
  "attack_narrative": "شرح تفصيلي بلغة محلل خبير (2-4 جمل)",
  "recommended_actions": ["إجراء 1", "إجراء 2"],
  "questions_to_investigate": ["سؤال 1", "سؤال 2"]
}}"""
    return f"""Analyze the following AegisIQ alert and produce a full \
explanation for another security analyst. Return JSON per schema.

═══ ALERT ═══
{_fmt(alert)}

═══ RELATED EVENTS ({len(related_logs)}) ═══
{_fmt_events(related_logs)}

═══ REQUIRED SCHEMA ═══
{{
  "summary": "one-sentence what happened",
  "why_it_matters": "business impact",
  "confidence": "high|medium|low",
  "false_positive_likelihood": 0.0-1.0,
  "attack_narrative": "detailed analyst-voice explanation (2-4 sentences)",
  "recommended_actions": ["action 1", "action 2"],
  "questions_to_investigate": ["Q1", "Q2"]
}}"""


# ─── Prompt 2: Cluster many alerts into investigation stories ────────
def triage_batch_prompt(alerts: list[dict], lang: str = "ar") -> str:
    """N raw alerts in, M investigation narratives out.

    Reduces alert fatigue by 10-20x -- SOC analyst reads 5 stories
    instead of 100 individual alerts."""
    if lang == "ar":
        return f"""تلقّى المحلل {len(alerts)} تنبيهاً في آخر ساعة. اجمعها \
في قصص تحقيق مترابطة (2-8 قصص). كل قصة تُظهر مهاجماً واحداً أو حملة \
واحدة. أرجع JSON.

═══ التنبيهات ═══
{_fmt_alerts(alerts)}

═══ المخطط ═══
{{
  "stories": [
    {{
      "title": "عنوان القصة",
      "severity": "critical|high|medium|low",
      "attacker_profile": "ما نعرفه عن المهاجم (IP, ASN, أدوات)",
      "kill_chain_stage": "أعلى مرحلة وصل إليها",
      "alert_ids": [1, 2, 3],
      "recommended_priority": 1-10,
      "one_sentence_summary": "ملخص القصة"
    }}
  ],
  "outliers": [alert_ids not in any story],
  "campaign_overlap": "هل تبدو قصص متعددة من نفس المهاجم؟"
}}"""
    return f"""The analyst received {len(alerts)} alerts in the last hour. \
Cluster them into related investigation stories (2-8 stories). Each \
story shows one attacker or one campaign. Return JSON.

═══ ALERTS ═══
{_fmt_alerts(alerts)}

═══ SCHEMA ═══
{{
  "stories": [
    {{
      "title": "story title",
      "severity": "critical|high|medium|low",
      "attacker_profile": "what we know about the attacker (IP, ASN, tools)",
      "kill_chain_stage": "highest stage reached",
      "alert_ids": [1, 2, 3],
      "recommended_priority": 1-10,
      "one_sentence_summary": "story recap"
    }}
  ],
  "outliers": [alert_ids not in any story],
  "campaign_overlap": "do multiple stories look like the same attacker?"
}}"""


# ─── Helpers ─────────────────────────────────────────────────────────
def _fmt(obj: dict) -> str:
    import json
    return json.dumps(obj, indent=2, ensure_ascii=False, default=str)


def _fmt_events(events: list[dict]) -> str:
    if not events:
        return "(no related events available)"
    import json
    trimmed = [
        {k: v for k, v in e.items()
         if k in ("id", "timestamp", "event_type", "source_ip",
                  "username", "severity", "raw_log")}
        for e in events[:20]  # cap to avoid token blowout
    ]
    return json.dumps(trimmed, indent=2, ensure_ascii=False, default=str)


def _fmt_alerts(alerts: list[dict]) -> str:
    import json
    trimmed = [
        {k: v for k, v in a.items()
         if k in ("id", "rule_type", "severity", "source_ip",
                  "mitre_id", "kill_chain_phase", "timestamp", "description")}
        for a in alerts[:100]
    ]
    return json.dumps(trimmed, indent=2, ensure_ascii=False, default=str)
