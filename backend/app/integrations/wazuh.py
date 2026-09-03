"""
app/integrations/wazuh.py -- optional Wazuh Manager connector.

Context (see docs/architecture.md): this project deliberately does NOT
run Wazuh + Elasticsearch + Kibana, because that stack cannot honestly
meet the document's own < 2 GB RAM target. Wazuh is instead supported as
an OPTIONAL upstream: if a Wazuh Manager exists on the lab network, the
console can show its agents alongside the ones registered locally, and
its alerts can be shipped into this SIEM through the normal
POST /api/logs pipeline (see scripts/wazuh_forwarder.py).

Honesty rules this module follows, because a "connected" badge that
lights up when nothing is connected is worse than no badge at all:

  * WAZUH_URL unset            -> status "not_configured"
  * configured but unreachable -> status "unreachable" + the actual error
  * configured, bad credentials-> status "unauthorized"
  * configured and reachable   -> status "connected" + the real agent list

Nothing here fabricates agents. If the manager cannot be reached, the
console shows locally registered agents only and says so.

Wazuh's API is versioned and token-based: POST /security/user/authenticate
returns a JWT, which is then sent as a bearer token to /agents. Both
calls are made with httpx, already a dependency for the test client.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

STATUS_NOT_CONFIGURED = "not_configured"
STATUS_CONNECTED = "connected"
STATUS_UNREACHABLE = "unreachable"
STATUS_UNAUTHORIZED = "unauthorized"
STATUS_ERROR = "error"


def _base_url() -> str:
    return settings.WAZUH_URL.strip().rstrip("/")


def _client() -> httpx.Client:
    # verify=False is the default because a lab Wazuh Manager serves a
    # self-signed certificate; WAZUH_VERIFY_SSL=true turns real
    # verification back on for a deployment that has a proper cert.
    return httpx.Client(
        base_url=_base_url(),
        verify=settings.WAZUH_VERIFY_SSL,
        timeout=settings.WAZUH_TIMEOUT_SECONDS,
    )


def _authenticate(client: httpx.Client) -> str:
    response = client.post(
        "/security/user/authenticate",
        auth=(settings.WAZUH_USERNAME, settings.WAZUH_PASSWORD),
    )
    response.raise_for_status()
    return response.json()["data"]["token"]


def _not_configured() -> dict[str, Any]:
    return {
        "status": STATUS_NOT_CONFIGURED,
        "url": None,
        "detail": (
            "No Wazuh Manager configured. Set WAZUH_URL, WAZUH_USERNAME and "
            "WAZUH_PASSWORD in .env to pull agents from an existing manager."
        ),
        "agent_count": None,
    }


def _classify(exc: Exception) -> dict[str, Any]:
    """Turns whatever went wrong into a status the console can show. Kept
    separate so both entry points classify identically, and so a failure
    costs one round trip rather than a retry."""
    if isinstance(exc, httpx.HTTPStatusError):
        if exc.response.status_code in (401, 403):
            return {
                "status": STATUS_UNAUTHORIZED,
                "url": _base_url(),
                "detail": "Wazuh Manager reachable but rejected the configured credentials.",
                "agent_count": None,
            }
        return {
            "status": STATUS_ERROR,
            "url": _base_url(),
            "detail": f"Wazuh Manager returned HTTP {exc.response.status_code}.",
            "agent_count": None,
        }
    if isinstance(exc, httpx.HTTPError):
        return {
            "status": STATUS_UNREACHABLE,
            "url": _base_url(),
            "detail": f"Could not reach the Wazuh Manager: {exc}",
            "agent_count": None,
        }
    logger.exception("Unexpected error talking to Wazuh", exc_info=exc)
    return {
        "status": STATUS_ERROR,
        "url": _base_url(),
        "detail": f"Unexpected error talking to the Wazuh Manager: {exc}",
        "agent_count": None,
    }


def _fetch_agents(limit: int) -> list[dict[str, Any]]:
    with _client() as client:
        token = _authenticate(client)
        response = client.get(
            "/agents", headers={"Authorization": f"Bearer {token}"}, params={"limit": limit}
        )
        response.raise_for_status()
        return response.json().get("data", {}).get("affected_items", [])


def get_status() -> dict[str, Any]:
    """Never raises. Returns a dict the console can render directly."""
    if not settings.wazuh_configured:
        return _not_configured()
    try:
        items = _fetch_agents(limit=500)
    except Exception as exc:  # noqa: BLE001 - an integration must never 500 the console
        return _classify(exc)
    return {
        "status": STATUS_CONNECTED,
        "url": _base_url(),
        "detail": "Wazuh Manager API reachable and authenticated.",
        "agent_count": len(items),
    }


def list_agents() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Returns (agents, status). `agents` is empty whenever the manager
    is not reachable -- callers merge it with locally registered agents
    and show `status` so the analyst knows which half is missing."""
    if not settings.wazuh_configured:
        return [], _not_configured()

    try:
        items = _fetch_agents(limit=500)
    except Exception as exc:  # noqa: BLE001 - classified, never raised at the caller
        return [], _classify(exc)

    agents = [
        {
            "source": "wazuh",
            "agent_id": item.get("id"),
            "hostname": item.get("name"),
            "ip_address": item.get("ip"),
            "operating_system": (item.get("os") or {}).get("name")
            or (item.get("os") or {}).get("platform"),
            "status": item.get("status"),
            "last_seen": item.get("lastKeepAlive"),
            "version": item.get("version"),
        }
        for item in items
    ]
    status = {
        "status": STATUS_CONNECTED,
        "url": _base_url(),
        "detail": "Wazuh Manager API reachable and authenticated.",
        "agent_count": len(agents),
    }
    return agents, status
