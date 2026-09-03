"""
app/security/rate_limit.py -- in-process token bucket rate limiter.

Purpose: protect the auth endpoint from credential-stuffing at the API
itself (as distinct from the login_after_failure DETECTION rule, which
watches logs the SIEM has collected). Without a limiter, an attacker
could hammer /api/auth/login as fast as HTTP will allow -- 401s do not
generate any log the detection engine sees, because they are rejected
before ingestion runs.

Algorithm: classic token bucket, one bucket per identity (source IP by
default). A bucket refills at `rate_per_minute` tokens per minute up to
`burst`. Each protected call consumes 1 token; when empty, the call is
refused with 429 and a Retry-After header stating exactly when the next
token becomes available.

Concurrency: a single process-wide dict guarded by an asyncio Lock. This
suits the single-uvicorn-worker deployment the project targets. A
multi-worker setup would need a shared store (Redis) -- documented here
so the swap point is obvious rather than surprising.

Failure mode: if the limiter itself raises, the call is allowed through.
A limiter that DoS's the login page it was meant to protect is worse
than one that occasionally lets an extra request past.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


@dataclass
class RateLimiter:
    """A token bucket keyed by a caller-supplied identity string.

    Attributes:
      rate_per_minute: refill rate. 30 = one token every 2 seconds.
      burst:           maximum accumulated tokens (initial fill).
      name:            included in log messages so multi-limiter setups
                       can be told apart in production logs.
    """

    rate_per_minute: int = 20
    burst: int = 10
    name: str = "default"
    _buckets: dict[str, _Bucket] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def check(self, identity: str) -> None:
        """Consume 1 token for `identity`. Raises HTTPException 429 if
        the bucket is empty, with Retry-After set to the seconds until
        the next token."""
        try:
            wait = await self._consume(identity)
            if wait > 0:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=(
                        f"Too many requests. Try again in {int(wait) + 1}s. "
                        "This limit exists to prevent credential stuffing "
                        "against the authentication endpoint."
                    ),
                    headers={"Retry-After": str(int(wait) + 1)},
                )
        except HTTPException:
            raise
        except Exception:  # noqa: BLE001 - never DoS ourselves
            logger.exception("rate-limiter %r raised; failing open", self.name)

    async def _consume(self, identity: str) -> float:
        """Returns 0 on success; seconds-until-next-token when refused."""
        now = time.monotonic()
        refill_per_second = self.rate_per_minute / 60.0

        async with self._lock:
            bucket = self._buckets.get(identity)
            if bucket is None:
                bucket = _Bucket(tokens=self.burst - 1, last_refill=now)
                self._buckets[identity] = bucket
                return 0.0

            # Refill to full since last check.
            elapsed = now - bucket.last_refill
            bucket.tokens = min(self.burst, bucket.tokens + elapsed * refill_per_second)
            bucket.last_refill = now

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return 0.0

            # Not enough tokens. Report how long until we have one.
            needed = 1.0 - bucket.tokens
            return needed / refill_per_second

    def reset(self, identity: str | None = None) -> None:
        """Testing helper. Empty the bucket store, or one identity."""
        if identity is None:
            self._buckets.clear()
        else:
            self._buckets.pop(identity, None)


# Module-level limiters. Tuned for a lab: strict enough that a brute-force
# is obvious; loose enough that a real analyst who mistypes a password 3
# times in a row is not locked out for hours.
auth_limiter = RateLimiter(rate_per_minute=10, burst=5, name="auth")
mutate_limiter = RateLimiter(rate_per_minute=60, burst=20, name="mutate")


def _identity(request: Request) -> str:
    """Prefer the forwarded client IP so a shared proxy doesn't collapse
    everyone into one bucket; fall back to the socket peer."""
    fwd = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if fwd:
        return fwd
    if request.client is not None:
        return request.client.host
    return "unknown"


async def enforce_auth(request: Request) -> None:
    """Dependency alias for the auth-login route."""
    await auth_limiter.check(_identity(request))
