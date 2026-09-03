import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    agents,
    alerts,
    analysis,       # v2.1 (premium)
    audit,          # v2.0
    auth,
    dashboard,
    health,
    integrations,
    logs,
    mfa,            # v2.3 multi-factor auth
    retention,
    rules,
    simulation,
    soar,
    stream,
)
from app.config import get_settings
from app.core.init_db import init_db
from app.realtime.hub import hub
from app.security.headers import SecureHeadersMiddleware

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # v2.3 — production security guardrails. In ENV=production, refuse to
    # boot with demo defaults (SECRET_KEY, admin password, missing
    # encryption key, wildcard CORS). A lab tool that ships to a network
    # with its demo secrets intact is how a SIEM becomes the incident.
    from app.config import validate_production_security
    _problems = validate_production_security(settings)
    if _problems:
        msg = "Refusing to start in production with insecure configuration:\n  - " + \
              "\n  - ".join(_problems)
        logging.getLogger("aegisiq").critical(msg)
        raise RuntimeError(msg)

    init_db()

    # v2.3 — surface the data-at-rest encryption posture at boot so an
    # operator never assumes secrets are encrypted when they are not.
    from app.security import crypto  # local import: avoids a cycle at module load
    if crypto.is_enabled():
        logging.getLogger("aegisiq").info(
            "Data-at-rest encryption ACTIVE (AES-256-GCM); MFA secrets are encrypted."
        )
    else:
        logging.getLogger("aegisiq").warning(
            "DATA_ENCRYPTION_KEY is not set — running in PLAINTEXT mode. "
            "Set it in production so MFA secrets and (optionally) log payloads "
            "are encrypted at rest. See docs/SECURITY.md."
        )

    # Hand the running event loop to the realtime hub. The ingestion path
    # is synchronous and therefore runs on FastAPI's worker threads, which
    # cannot touch a WebSocket directly -- they schedule the broadcast
    # onto this loop instead. See app/realtime/hub.py.
    hub.bind_loop(asyncio.get_running_loop())
    try:
        yield
    finally:
        hub.unbind_loop()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        f"{settings.PROJECT_NAME} — {settings.PROJECT_TAGLINE}. "
        "Resource-efficient SIEM & SOAR for constrained environments. "
        "Native FastAPI/SQLite implementation with 8 detection rules, "
        "MITRE ATT&CK + Cyber Kill Chain mapping, record-only SOAR, "
        "rate-limited auth, security-headers middleware, and an "
        "append-only audit trail. See docs/CHANGELOG.md for v2.0 "
        "additions and docs/SECURITY.md for the hardening posture."
    ),
    version=settings.PROJECT_VERSION,
    lifespan=lifespan,
)

# Security-headers middleware first so it also stamps the CORS
# preflight response. Order matters: last-added runs first (Starlette
# wraps inside-out), so SecureHeaders runs OUTERMOST, meaning its
# headers land on every response including 4xx/5xx from downstream.
app.add_middleware(SecureHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(mfa.router)            # v2.3 MFA enrolment/management
app.include_router(agents.router)
app.include_router(dashboard.router)
app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(rules.router)
app.include_router(soar.router)
app.include_router(integrations.router)
app.include_router(retention.router)
app.include_router(audit.router)          # v2.0
app.include_router(analysis.router)       # v2.1 premium
app.include_router(analysis.license_router)  # v2.1 license API
app.include_router(simulation.router)
app.include_router(stream.router)
