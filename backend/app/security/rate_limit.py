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


# ── v3.2 · shared store for multi-worker deployments ────────────────
#
# The buckets above live in ONE process's memory. Run two uvicorn workers
# (or two Render instances behind the load balancer) and each keeps its
# own counters, so the effective limit silently becomes N × the configured
# rate — the limiter reports 10/min and permits 20. That is the kind of
# control that passes an audit on paper and fails in production.
#
# When REDIS_URL is set, the buckets move to Redis and every worker shares
# them. The implementation is a single atomic Lua script (read, refill,
# consume, store) so two workers cannot interleave a read-modify-write.
# Without REDIS_URL — or if Redis is unreachable — the in-process buckets
# are used exactly as before, and /health reports which store is live so
# the difference is never a surprise.

_REFILL_AND_CONSUME = """
local tokens_key = KEYS[1]
local ts_key     = KEYS[2]
local rate       = tonumber(ARGV[1])   -- tokens per second
local burst      = tonumber(ARGV[2])
local now        = tonumber(ARGV[3])
local ttl        = tonumber(ARGV[4])

local tokens = tonumber(redis.call('get', tokens_key))
local last   = tonumber(redis.call('get', ts_key))
if tokens == nil then tokens = burst end
if last == nil then last = now end

local elapsed = math.max(0, now - last)
tokens = math.min(burst, tokens + elapsed * rate)

local wait = 0
if tokens >= 1 then
  tokens = tokens - 1
else
  wait = (1 - tokens) / rate
end

redis.call('set', tokens_key, tokens, 'EX', ttl)
redis.call('set', ts_key, now, 'EX', ttl)
return tostring(wait)
"""


class RedisRateLimiter:
    """Token bucket backed by Redis, API-compatible with RateLimiter.

    Fails OPEN on any Redis error, like the in-process limiter: a limiter
    that takes the login page down when its cache blips is a worse outage
    than the abuse it prevents. Each failure is logged once per minute
    rather than per request, so a Redis outage does not also produce a log
    flood.
    """

    def __init__(self, client, rate_per_minute: int, burst: int, name: str):
        self._client = client
        self.rate_per_minute = rate_per_minute
        self.burst = burst
        self.name = name
        self._script = None
        self._last_error_log = 0.0

    def _prepare(self):
        if self._script is None:
            self._script = self._client.register_script(_REFILL_AND_CONSUME)
        return self._script

    async def check(self, identity: str) -> None:
        try:
            script = self._prepare()
            wait = float(
                await script(
                    keys=[f"aegisiq:rl:{self.name}:{identity}:t",
                          f"aegisiq:rl:{self.name}:{identity}:s"],
                    args=[self.rate_per_minute / 60.0, self.burst, time.time(),
                          max(60, int(self.burst / max(self.rate_per_minute / 60.0, 1e-6)) * 2)],
                )
            )
        except HTTPException:
            raise
        except Exception:  # noqa: BLE001 - never DoS ourselves
            now = time.monotonic()
            if now - self._last_error_log > 60:
                self._last_error_log = now
                logger.exception("redis rate-limiter %r failed; failing open", self.name)
            return

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

    def reset(self, identity: str | None = None) -> None:  # pragma: no cover - test helper
        """Best effort; used by the test suite only."""
        try:
            import asyncio

            pattern = (f"aegisiq:rl:{self.name}:{identity}:*" if identity
                       else f"aegisiq:rl:{self.name}:*")

            async def _clear():
                keys = [k async for k in self._client.scan_iter(match=pattern)]
                if keys:
                    await self._client.delete(*keys)

            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(_clear())
            else:
                loop.run_until_complete(_clear())
        except Exception:  # noqa: BLE001
            logger.debug("redis limiter reset skipped", exc_info=True)


_store_kind = "in_process"


def store_kind() -> str:
    """Which store the limiters are actually using — reported by /health."""
    return _store_kind


def install_shared_store() -> str:
    """Swap the module-level limiters onto Redis when REDIS_URL is set.

    Called once at startup (app/main.py lifespan). Returns the store kind
    actually in use so the caller can log it.
    """
    global auth_limiter, mutate_limiter, _store_kind

    from app.config import get_settings

    settings = get_settings()
    url = (settings.REDIS_URL or "").strip()
    if not url:
        return _store_kind

    try:
        import redis.asyncio as redis_asyncio  # lazy: optional dependency
    except ImportError:
        logger.warning(
            "REDIS_URL is set but the redis package is not installed — "
            "falling back to in-process rate limiting. Install it with: "
            "pip install 'redis>=5.0'"
        )
        return _store_kind

    try:
        client = redis_asyncio.from_url(url, decode_responses=True)
    except Exception:  # noqa: BLE001
        logger.exception("could not connect to REDIS_URL; using in-process rate limiting")
        return _store_kind

    auth_limiter = RedisRateLimiter(
        client, settings.RATE_LIMIT_AUTH_PER_MINUTE, settings.RATE_LIMIT_AUTH_BURST, "auth")
    mutate_limiter = RedisRateLimiter(client, 60, 20, "mutate")
    _store_kind = "redis"
    return _store_kind


def _identity(request: Request) -> str:
    """Bucket key for this caller.

    v3.2 — this used to read X-Forwarded-For unconditionally, so an
    attacker could send a different forged value on every request and
    never exhaust a bucket: the limiter protected nothing against the one
    adversary it exists for. app/security/net.py honours the header only
    when the operator declares a reverse proxy in front
    (TRUST_PROXY_HEADERS), and validates it as an IP address.
    """
    from app.security.net import rate_limit_identity  # local: avoids a cycle
    return rate_limit_identity(request)


async def enforce_auth(request: Request) -> None:
    """Dependency alias for the auth-login route.

    Reads the module global at call time so install_shared_store() can swap
    in the Redis-backed limiter after the routes are already bound.
    """
    await auth_limiter.check(_identity(request))


async def enforce_mutate(request: Request) -> None:
    """Dependency for DESTRUCTIVE console actions (deletes, bulk deletes,
    retention purge).

    mutate_limiter was defined here from the start but never attached to a
    route, so it protected nothing. It is applied only to the destructive
    endpoints, deliberately NOT to log ingestion: a SIEM's ingest path has
    to absorb bursts (the Simulation Lab alone posts a dozen events in a
    couple of seconds, and a real shipper far more), so rate-limiting it
    would break normal operation to defend against an already-authenticated
    caller. Mass deletion is the operation where abuse actually destroys
    evidence, and no legitimate analyst workflow approaches 60/min there.
    """
    await mutate_limiter.check(_identity(request))
