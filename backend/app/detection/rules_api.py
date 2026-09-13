"""
/api/rules/library and /api/rules/sync — the endpoints RulesLibrary.tsx consumes.

Kept intentionally thin: it delegates loading to rule_pack_loader (which
does the tarball fetch + parse) and shape-conversion to the response
model here. No detection execution logic lives in this file — it's
strictly the read-plane over the rule inventory.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from ..auth.dependencies import get_current_user
from ..config import get_settings
from ..models.user import User
from .rule_pack_loader import LoadedRule, load_all_rules, load_community_rules

router = APIRouter(prefix="/api/rules", tags=["rules"])

# In-memory cache so we don't re-download the tarball on every request.
# Refreshed on server start and after each POST /sync.
_CACHE: dict = {"loaded": None}


class RuleOut(BaseModel):
    id: str
    sigma_id: str
    title: str
    description: str
    level: str
    source: str
    tags: list[str]
    ingestable: bool
    logsource_product: str | None = None
    logsource_service: str | None = None


class LibraryResponse(BaseModel):
    total: int
    by_source: dict[str, int]
    by_level: dict[str, int]
    rules: list[RuleOut]


class SyncResponse(BaseModel):
    added: int
    total: int


def _refresh_cache() -> dict:
    settings = get_settings()
    rules_dir = Path(settings.SIGMA_RULES_DIR)
    result = load_all_rules(rules_dir)
    _CACHE["loaded"] = result
    return result


def _to_out(rule: LoadedRule, source: str) -> RuleOut:
    return RuleOut(
        id=rule.sigma_id,
        sigma_id=rule.sigma_id,
        title=rule.title,
        description=rule.description[:400],
        level=rule.level,
        source=source,
        tags=rule.tags,
        ingestable=rule.ingestable,
        logsource_product=rule.logsource.get("product"),
        logsource_service=rule.logsource.get("service"),
    )


def _source_of(rule: LoadedRule) -> str:
    if "aegisiq" in rule.filepath.lower():
        return "aegisiq"
    if rule.filepath.startswith("rules/"):
        return "sigma_community"
    return "core"


@router.get("/library", response_model=LibraryResponse)
def library(current_user: User = Depends(get_current_user)) -> LibraryResponse:
    data = _CACHE.get("loaded") or _refresh_cache()
    outs = [_to_out(r, _source_of(r)) for r in data["rules"]]
    return LibraryResponse(
        total=len(outs),
        by_source=dict(Counter(o.source for o in outs)),
        by_level=dict(Counter(o.level for o in outs)),
        rules=outs,
    )


@router.post("/sync", response_model=SyncResponse)
def sync(current_user: User = Depends(get_current_user)) -> SyncResponse:
    if current_user.role != "administrator":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin_only")
    before = len((_CACHE.get("loaded") or {}).get("rules", []))
    community = load_community_rules()
    if not community:
        raise HTTPException(status_code=502, detail="community_download_failed")
    refreshed = _refresh_cache()
    after = len(refreshed["rules"])
    return SyncResponse(added=max(0, after - before), total=after)
