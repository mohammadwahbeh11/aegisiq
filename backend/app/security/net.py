"""
app/security/net.py -- one authoritative answer to "who is calling?".

Every control that keys off a source address — the per-IP auth rate
limiter, the audit trail's ``source_ip`` column, the lockout records —
is only as trustworthy as the way that address is derived.

The naive implementation (used before v3.2, in three separate copies)
was::

    fwd = request.headers.get("x-forwarded-for", "").split(",")[0]
    return fwd or request.client.host

``X-Forwarded-For`` is a client-supplied header. When the app is exposed
directly, an attacker rotates it per request and

  * the per-IP token bucket never fills, so the rate limit on
    /api/auth/login is gone entirely, and
  * every audit row about the attack names an address of the attacker's
    choosing — the log says the break-in came from 10.0.0.7.

So the header is honoured only when the operator states that this
instance really is behind a reverse proxy that overwrites it
(``TRUST_PROXY_HEADERS=true``). Otherwise the peer address of the TCP
connection is used, which cannot be forged over a completed handshake.

Controls: NIST SP 800-53 AU-3 (content of audit records), SI-10
(information input validation), SC-5 (denial-of-service protection);
OWASP ASVS V13.2.
"""
from __future__ import annotations

import ipaddress

from starlette.requests import Request

from app.config import get_settings

settings = get_settings()

_UNKNOWN = "unknown"


def _valid_ip(candidate: str) -> str | None:
    try:
        return str(ipaddress.ip_address(candidate.strip()))
    except ValueError:
        return None


def client_ip(request: Request) -> str | None:
    """Best trustworthy source address for this request.

    Returns a validated IP string, or None when the address cannot be
    determined (an ASGI transport with no peer, e.g. the TestClient).
    """
    if settings.TRUST_PROXY_HEADERS:
        # Left-most entry is the original client as recorded by the first
        # proxy in the chain. Validated as an IP so a junk header cannot
        # inject arbitrary text into the audit trail.
        forwarded = request.headers.get("x-forwarded-for", "")
        for part in forwarded.split(","):
            ip = _valid_ip(part)
            if ip:
                return ip
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            ip = _valid_ip(real_ip)
            if ip:
                return ip

    if request.client and request.client.host:
        return _valid_ip(request.client.host) or request.client.host
    return None


def rate_limit_identity(request: Request) -> str:
    """Identity string for the token-bucket limiter. Never None, so a
    caller with no resolvable address still shares one bucket rather
    than bypassing the limiter."""
    return client_ip(request) or _UNKNOWN
