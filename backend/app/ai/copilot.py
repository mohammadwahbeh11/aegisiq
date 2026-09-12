"""
app/ai/copilot.py -- the CopilotService.

Thin, opinionated service that wires prompts + a provider together
and returns structured JSON to API callers. Two features today:

  * explain_alert(alert_id, lang) -> per-alert deep explanation
  * triage_batch(alert_ids, lang) -> N alerts -> M investigation stories

Every call is fail-open: if the AI is disabled, misconfigured, or the
provider is down, the caller gets a well-formed response with
`ai_status="degraded"` and a rules-based fallback -- NEVER a 500. The
SIEM must keep working even without AI.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.ai.prompts import (
    SYSTEM_ANALYST_AR,
    SYSTEM_ANALYST_EN,
    explain_alert_prompt,
    triage_batch_prompt,
)
from app.ai.providers import (
    AIProviderError,
    ChatMessage,
    get_provider,
)
from app.models.alert import Alert
from app.models.log import Log

log = logging.getLogger("aegisiq.ai")


def _degraded(reason: str, fallback_payload: dict | None = None) -> dict:
    """Uniform shape for degraded responses so the frontend can render
    a graceful notice instead of an error toast."""
    payload = fallback_payload or {}
    return {
        "ai_status": "degraded",
        "reason": reason,
        **payload,
    }


def _parse_json_response(raw: str) -> dict:
    """Robust JSON parser -- some models wrap the JSON in markdown
    fences or add a preamble. Extract the largest {...} substring."""
    raw = raw.strip()
    # strip ```json ... ``` fences that some models emit
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    # find the outermost JSON object
    first = raw.find("{")
    last = raw.rfind("}")
    if first < 0 or last <= first:
        raise ValueError(f"no JSON object found in: {raw[:200]}")
    return json.loads(raw[first:last + 1])


class CopilotService:
    """Facade the API layer talks to.

    Instantiated per-request so the LRU config is picked up. Cheap:
    only reads env vars, doesn't hold sockets."""

    def __init__(self) -> None:
        try:
            self.provider = get_provider()
        except AIProviderError as exc:
            log.warning("AI provider init failed: %s", exc)
            self.provider = None

    @property
    def enabled(self) -> bool:
        return self.provider is not None

    # ─── explain_alert ───────────────────────────────────────────────
    def explain_alert(self, db: Session, alert_id: int,
                      lang: str = "ar") -> dict:
        """Deep single-alert explanation.

        Returns the parsed JSON from the model plus `ai_status` and
        `alert_id`. Never raises for provider outages -- returns a
        degraded response."""
        alert = db.get(Alert, alert_id)
        if not alert:
            return {"ai_status": "error", "reason": f"alert {alert_id} not found"}

        # gather related evidence: same source_ip, ±10 min window
        related: list[dict] = []
        if alert.log_id is not None:
            trig = db.get(Log, alert.log_id)
            if trig is not None:
                related.append(_log_as_dict(trig))
        if alert.source_ip:
            rows = (db.query(Log)
                      .filter(Log.source_ip == alert.source_ip)
                      .order_by(Log.timestamp.desc())
                      .limit(15)
                      .all())
            for r in rows:
                if r.id != alert.log_id:
                    related.append(_log_as_dict(r))

        alert_dict = _alert_as_dict(alert)

        if not self.enabled:
            return _degraded("AI provider not configured (AI_PROVIDER=disabled)",
                             fallback_payload={
                                 "alert_id": alert_id,
                                 "alert": alert_dict,
                                 "related_events_count": len(related),
                             })

        system = SYSTEM_ANALYST_AR if lang == "ar" else SYSTEM_ANALYST_EN
        user = explain_alert_prompt(alert_dict, related, lang=lang)

        try:
            raw = self.provider.chat(
                [ChatMessage("system", system), ChatMessage("user", user)],
                max_tokens=700,
                temperature=0.2,
                json_mode=True,
            )
            parsed = _parse_json_response(raw)
        except AIProviderError as exc:
            log.warning("explain_alert: provider error: %s", exc)
            return _degraded(str(exc), {"alert_id": alert_id, "alert": alert_dict})
        except (ValueError, json.JSONDecodeError) as exc:
            log.warning("explain_alert: parse error: %s", exc)
            return _degraded(f"AI returned unparseable JSON: {exc}",
                             {"alert_id": alert_id, "alert": alert_dict})

        return {
            "ai_status": "ok",
            "alert_id": alert_id,
            "lang": lang,
            "analysis": parsed,
        }

    # ─── triage_batch ────────────────────────────────────────────────
    def triage_batch(self, db: Session, alert_ids: list[int],
                     lang: str = "ar") -> dict:
        """Group N alerts into M narrative stories.

        Sweet spot: 10-100 alerts in, 3-8 stories out. Beyond 100
        alerts the token budget hurts; the endpoint slices to 100."""
        alerts = (db.query(Alert)
                    .filter(Alert.id.in_(alert_ids[:100]))
                    .all())
        if not alerts:
            return {"ai_status": "error", "reason": "no matching alerts"}

        alert_dicts = [_alert_as_dict(a) for a in alerts]

        if not self.enabled:
            # Rules-based fallback: group by source_ip so the caller
            # still gets a useful clustering.
            groups: dict[str, list[int]] = {}
            for a in alerts:
                key = a.source_ip or f"no-ip-{a.rule_type}"
                groups.setdefault(key, []).append(a.id)
            stories = [
                {
                    "title": f"Activity from {ip}",
                    "severity": "medium",
                    "attacker_profile": f"IP {ip}",
                    "kill_chain_stage": "unknown",
                    "alert_ids": ids,
                    "recommended_priority": 5,
                    "one_sentence_summary": f"{len(ids)} alerts grouped by source IP",
                }
                for ip, ids in groups.items()
            ]
            return _degraded("AI disabled — grouped by source_ip only",
                             {"stories": stories, "outliers": [],
                              "campaign_overlap": "n/a"})

        system = SYSTEM_ANALYST_AR if lang == "ar" else SYSTEM_ANALYST_EN
        user = triage_batch_prompt(alert_dicts, lang=lang)
        try:
            raw = self.provider.chat(
                [ChatMessage("system", system), ChatMessage("user", user)],
                max_tokens=1500,
                temperature=0.2,
                json_mode=True,
            )
            parsed = _parse_json_response(raw)
        except AIProviderError as exc:
            log.warning("triage_batch: provider error: %s", exc)
            return _degraded(str(exc))
        except (ValueError, json.JSONDecodeError) as exc:
            log.warning("triage_batch: parse error: %s", exc)
            return _degraded(f"AI returned unparseable JSON: {exc}")

        return {
            "ai_status": "ok",
            "alerts_analyzed": len(alerts),
            "lang": lang,
            **parsed,
        }


# ─── dict shape helpers (avoid pulling in Pydantic here) ────────────
def _alert_as_dict(a: Alert) -> dict[str, Any]:
    return {
        "id": a.id,
        "rule_type": a.rule_type,
        "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
        "source_ip": a.source_ip,
        "mitre_id": a.mitre_id,
        "kill_chain_phase": a.kill_chain_phase,
        "timestamp": a.timestamp.isoformat() if a.timestamp else None,
        "description": a.description,
        "status": a.status.value if hasattr(a.status, "value") else str(a.status),
    }


def _log_as_dict(log_row: Log) -> dict[str, Any]:
    return {
        "id": log_row.id,
        "timestamp": log_row.timestamp.isoformat() if log_row.timestamp else None,
        "event_type": log_row.event_type,
        "source_ip": log_row.source_ip,
        "destination_port": log_row.destination_port,
        "username": log_row.username,
        "severity": (log_row.severity.value if hasattr(log_row.severity, "value")
                     else str(log_row.severity)),
        "raw_log": (log_row.raw_log or "")[:400],  # cap for token budget
    }
