"""
app/enrichment/abuseipdb.py -- AbuseIPDB reputation lookups.

Free tier: 1000 checks/day. Register: https://www.abuseipdb.com/register
Set ABUSEIPDB_API_KEY env var. Without a key, the module returns
{"enabled": False, ...} so callers skip enrichment gracefully.
"""
from __future__ import annotations

import json
import logging
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

log = logging.getLogger("aegisiq.enrichment")


def check_ip(ip: str, max_age_days: int = 90) -> dict:
    """Query AbuseIPDB for the IP's abuse-confidence score.

    Returns a dict with `enabled` flag, `abuse_confidence` (0-100),
    `total_reports`, `country_code`, `usage_type`, `is_tor`, `is_public`,
    and `last_reported_at`. Any failure returns a well-formed dict with
    `enabled=False` -- the caller must never crash on enrichment errors."""
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return {"enabled": False, "reason": "ABUSEIPDB_API_KEY not set"}

    url = (f"https://api.abuseipdb.com/api/v2/check"
           f"?ipAddress={urllib.parse.quote(ip)}"
           f"&maxAgeInDays={max_age_days}"
           f"&verbose")
    req = urllib.request.Request(url, headers={
        "Key": api_key,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=8,
                                     context=ssl.create_default_context()) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        log.warning("abuseipdb %s: HTTP %s", ip, exc.code)
        return {"enabled": False, "reason": f"HTTP {exc.code}"}
    except urllib.error.URLError as exc:
        log.warning("abuseipdb %s: %s", ip, exc.reason)
        return {"enabled": False, "reason": f"network: {exc.reason}"}
    except (ValueError, KeyError) as exc:
        return {"enabled": False, "reason": f"parse: {exc}"}

    data = body.get("data", {})
    return {
        "enabled": True,
        "source": "abuseipdb",
        "abuse_confidence": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "is_tor": bool(data.get("isTor", False)),
        "is_public": bool(data.get("isPublic", True)),
        "last_reported_at": data.get("lastReportedAt"),
        "domain": data.get("domain"),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
