"""
app/api/routes/copilot.py -- REST surface for the AI Copilot.

Endpoints:
  POST /api/copilot/explain/{alert_id}     -- single-alert deep dive
  POST /api/copilot/triage                 -- N alerts -> M stories
  GET  /api/copilot/status                 -- provider health / config

All endpoints require an authenticated user (Depends(get_current_user))
and are rate-limited via the shared mutate_limiter to prevent an
analyst from accidentally burning through their LLM quota.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.dependencies import get_current_user
from app.ai.copilot import CopilotService
from app.ai.providers import get_provider
from app.security.rate_limit import mutate_limiter, _identity

router = APIRouter(prefix="/api/copilot", tags=["copilot"])


class TriageRequest(BaseModel):
    alert_ids: list[int] = Field(..., min_length=1, max_length=200)
    lang: str = Field("ar", pattern="^(ar|en)$")


class ExplainRequest(BaseModel):
    lang: str = Field("ar", pattern="^(ar|en)$")


async def _enforce(request: Request) -> None:
    """Reuse the mutate limiter (60/min per IP) — copilot calls are
    more expensive than regular API calls, so we cap them."""
    await mutate_limiter.check(_identity(request))


@router.get("/status")
def status(_user=Depends(get_current_user)):
    """Report which provider is active and whether it's reachable.

    Does NOT make a real LLM call — cheap probe suitable for the
    frontend to show a badge ("AI: on / off / degraded")."""
    try:
        p = get_provider()
    except Exception as exc:  # noqa: BLE001
        return {"enabled": False, "provider": None,
                "model": None, "error": str(exc)}
    if p is None:
        return {"enabled": False, "provider": None, "model": None,
                "note": "Set AI_PROVIDER=openai|anthropic|ollama to enable."}
    return {
        "enabled": True,
        "provider": type(p).__name__.replace("Provider", "").lower(),
        "model": getattr(p, "model", None),
        "note": "AI-augmented triage available",
    }


@router.post("/explain/{alert_id}")
async def explain(alert_id: int, payload: ExplainRequest, request: Request,
                  _rate=Depends(_enforce),
                  db: Session = Depends(get_db),
                  _user=Depends(get_current_user)):
    """Deep-dive explanation of one alert. Fail-open: degraded response
    when AI is down, but never a 500 that would take the UI offline."""
    svc = CopilotService()
    return svc.explain_alert(db, alert_id, lang=payload.lang)


@router.post("/triage")
async def triage(payload: TriageRequest, request: Request,
                 _rate=Depends(_enforce),
                 db: Session = Depends(get_db),
                 _user=Depends(get_current_user)):
    """Cluster N alerts into M investigation stories. Reduces analyst
    fatigue -- one narrative to read instead of 30 individual alerts."""
    svc = CopilotService()
    return svc.triage_batch(db, payload.alert_ids, lang=payload.lang)
