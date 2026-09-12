"""
app/api/routes/enrichment.py -- threat intelligence lookup API.

Analyst hovers over an IP in the console -> frontend calls
GET /api/enrichment/ip/{ip} -> panel shows AbuseIPDB score + OTX
pulses + composite risk badge. Cached 6 hours to protect free-tier
API quotas.
"""
from __future__ import annotations

import ipaddress
from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.dependencies import get_current_user
from app.enrichment import EnrichmentService
from app.enrichment.enrichment_service import service as enrichment_singleton

router = APIRouter(prefix="/api/enrichment", tags=["enrichment"])


@router.get("/ip/{ip}")
def lookup_ip(ip: str, _user=Depends(get_current_user)):
    """Return composite threat-intel enrichment for an IP.

    Never blocks the SIEM: if all upstream feeds are down, the response
    still contains `risk_score: 0` and per-source `enabled: false`."""
    # Validate — refuse to hand arbitrary strings to upstream APIs.
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"invalid IP: {exc}",
        )
    return enrichment_singleton.enrich_ip(ip)
