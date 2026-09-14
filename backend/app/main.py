import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from .detection import rules_api
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    copilot,
    compliance,
    enrichment,
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
    # Before anything can log a request: the live socket authenticates via
    # ?token=<JWT>, which uvicorn's access logger would otherwise write out
    # in full. See app/security/log_redaction.py.
    from app.security.log_redaction import install as install_log_redaction
    install_log_redaction()

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

    # v3.2 — move the rate-limit buckets to Redis when REDIS_URL is set.
    # With more than one worker the in-process buckets multiply the
    # configured limit by the worker count; /health reports which store
    # actually took effect.
    from app.security.rate_limit import install_shared_store
    _store = install_shared_store()
    logging.getLogger("aegisiq").info("rate-limit store: %s", _store)

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

# Routers. One registration each — until v3.2 `rules_api.router` was
# included fifteen times (a copy-paste that grew with every release),
# which duplicated every one of its operations in the OpenAPI schema and
# in the /docs page. FastAPI matches the first registration, so the
# behaviour was unaffected; the generated contract was not.
for _router in (
    health.router,
    auth.router,
    mfa.router,              # v2.3 MFA enrolment/management
    agents.router,
    dashboard.router,
    logs.router,
    alerts.router,
    rules.router,
    rules_api.router,        # Sigma / community rule library
    soar.router,
    integrations.router,
    retention.router,
    audit.router,            # v2.0
    analysis.router,         # v2.1 premium
    analysis.license_router,  # v2.1 license API
    simulation.router,
    stream.router,
    copilot.router,          # v2.5 AI copilot
    enrichment.router,       # v2.5 threat-intel enrichment
    compliance.router,       # v2.5 compliance evidence
):
    app.include_router(_router)
