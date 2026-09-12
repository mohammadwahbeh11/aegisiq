"""
app/enrichment/enrichment_service.py -- orchestrator + cache.

Combines AbuseIPDB + OTX into one call, caches per-IP for CACHE_TTL
seconds so we stay well under the free-tier daily limits even under
a burst of alerts against a single attacker.
"""
from __future__ import annotations

import logging
import time
from threading import Lock
from typing import Any

from app.enrichment.abuseipdb import check_ip as abuseipdb_check
from app.enrichment.otx import check_ip as otx_check

log = logging.getLogger("aegisiq.enrichment")

# 6-hour cache: for a live attacker, first lookup enriches all
# subsequent alerts from the same IP for the rest of the shift.
CACHE_TTL_SECONDS = 6 * 3600


class EnrichmentService:
    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, dict]] = {}
        self._lock = Lock()

    def enrich_ip(self, ip: str) -> dict[str, Any]:
        """Return combined enrichment dict for a source IP.

        Shape:
          {
            "ip": "...",
            "risk_score": 0-100,   # composite of AbuseIPDB + OTX
            "risk_label": "clean" | "low" | "medium" | "high" | "critical",
            "abuseipdb": {...},
            "otx": {...},
            "cached": bool,
            "checked_at": ISO
          }
        """
        now = time.time()
        with self._lock:
            entry = self._cache.get(ip)
            if entry and (now - entry[0]) < CACHE_TTL_SECONDS:
                return {**entry[1], "cached": True}

        ab = abuseipdb_check(ip)
        ot = otx_check(ip)
        composite = self._compute_risk(ab, ot)
        result = {
            "ip": ip,
            "risk_score": composite,
            "risk_label": self._label(composite),
            "abuseipdb": ab,
            "otx": ot,
            "cached": False,
        }
        with self._lock:
            self._cache[ip] = (now, result)
            # bound cache size
            if len(self._cache) > 2000:
                oldest = sorted(self._cache.items(), key=lambda kv: kv[1][0])[:500]
                for k, _ in oldest:
                    del self._cache[k]
        return result

    @staticmethod
    def _compute_risk(ab: dict, ot: dict) -> int:
        """Weighted composite: AbuseIPDB 70% + OTX 30%.

        AbuseIPDB is direct (0-100 confidence). OTX is derived: 20
        points per pulse (capped at 100)."""
        ab_score = int(ab.get("abuse_confidence", 0)) if ab.get("enabled") else 0
        pulse_count = int(ot.get("pulse_count", 0)) if ot.get("enabled") else 0
        ot_score = min(100, pulse_count * 20)
        composite = int(0.7 * ab_score + 0.3 * ot_score)
        return max(0, min(100, composite))

    @staticmethod
    def _label(score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        if score >= 5:
            return "low"
        return "clean"


# Module-level singleton (safe: internal state is a locked dict)
service = EnrichmentService()
