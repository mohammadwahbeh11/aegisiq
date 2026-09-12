"""
app/enrichment/otx.py -- AlienVault OTX pulse lookups.

Community threat-intel feed. Free, no API key needed for basic IP
lookups. Returns the "pulses" (campaign groupings) an IP appears in
-- turns a raw IP into a name like "Emotet C2 infrastructure".
"""
from __future__ import annotations

import json
import logging
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone

log = logging.getLogger("aegisiq.enrichment")


def check_ip(ip: str, max_pulses: int = 5) -> dict:
    """Return the top OTX pulses that reference this IP.

    Free endpoint. Rate-limited by AlienVault; a well-behaved SIEM
    caches results (see enrichment_service.py)."""
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8,
                                     context=ssl.create_default_context()) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        # 404 means "unknown IP" -- that's actually good news
        if exc.code == 404:
            return {"enabled": True, "source": "otx", "pulse_count": 0, "pulses": []}
        return {"enabled": False, "reason": f"HTTP {exc.code}"}
    except urllib.error.URLError as exc:
        return {"enabled": False, "reason": f"network: {exc.reason}"}
    except (ValueError, KeyError) as exc:
        return {"enabled": False, "reason": f"parse: {exc}"}

    pulse_info = body.get("pulse_info", {})
    pulses = pulse_info.get("pulses", [])[:max_pulses]
    return {
        "enabled": True,
        "source": "otx",
        "pulse_count": pulse_info.get("count", len(pulses)),
        "pulses": [
            {
                "name": p.get("name"),
                "author": p.get("author_name"),
                "tags": p.get("tags", [])[:5],
                "created": p.get("created"),
                "adversary": p.get("adversary"),
            }
            for p in pulses
        ],
        "reputation": body.get("reputation", 0),
        "country_name": body.get("country_name"),
        "asn": body.get("asn"),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
