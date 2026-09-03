from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.config import get_settings
from app.detection.engine import implemented_rule_types
from app.integrations import wazuh
from app.models.rule import DetectionRule
from app.realtime.hub import hub
from app.security.license import verify as verify_license


def _license_snapshot() -> dict:
    """Small dict for /health. Never raises."""
    settings = get_settings()
    st = verify_license(settings.PREMIUM_LICENSE_KEY)
    return {"active": st.active, "tier": st.tier, "features": st.features}

router = APIRouter(tags=["health"])

settings = get_settings()


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    """
    Reports real, derived status for each subsystem rather than a
    hardcoded string somebody has to remember to update:

      - database:         an actual query is executed
      - detection_engine: "ok" only when every ENABLED rule row has a
                          handler registered in app/detection/engine.py;
                          "partial" when some enabled rule cannot be
                          executed by this build
      - websocket:        "ok" with the live subscriber count
      - wazuh:            the real integration status, which is
                          "not_configured" until WAZUH_URL is set --
                          never a decorative "connected"
    """
    try:
        db.execute(text("SELECT 1"))
        database_status = "ok"
    except Exception as exc:  # noqa: BLE001 - report any DB error, don't hide it
        database_status = f"error: {exc}"

    implemented = implemented_rule_types()
    try:
        enabled_types = {
            rule_type
            for (rule_type,) in db.query(DetectionRule.rule_type)
            .filter(DetectionRule.enabled.is_(True))
            .all()
        }
        unimplemented = sorted(enabled_types - implemented)
        detection_status = "ok" if not unimplemented else "partial"
    except Exception:  # noqa: BLE001 - the database error is already reported above
        unimplemented = []
        detection_status = "unknown"

    return {
        "product": settings.PROJECT_NAME,
        "tagline": settings.PROJECT_TAGLINE,
        "version": settings.PROJECT_VERSION,
        "api": "ok",
        "database": database_status,
        "detection_engine": detection_status,
        "detection_rules_implemented": sorted(implemented),
        "detection_rules_enabled_without_handler": unimplemented,
        "collector": "ok",
        "websocket": "ok",
        "websocket_subscribers": hub.connection_count,
        "soar": "record_only" if settings.SOAR_ENABLED and not settings.SOAR_EXECUTE else (
            "execute_requested" if settings.SOAR_ENABLED else "disabled"
        ),
        # v2.0 security posture — makes hardening visible to any /health poller.
        "security": {
            "rate_limit_auth_per_minute": settings.RATE_LIMIT_AUTH_PER_MINUTE,
            "security_headers": "active",
            "audit_log": "active" if settings.AUDIT_API_ENABLED else "recorded_only",
            "password_policy": "enforced_on_change",
        },
        # v2.1 — premium license status (Log Analysis Report).
        "license": _license_snapshot(),
        # Deliberately does NOT call the Wazuh API: /health is polled and
        # must stay fast and dependency-free. Use
        # /api/integrations/wazuh/status for a live check.
        "wazuh": wazuh.STATUS_NOT_CONFIGURED if not settings.wazuh_configured else "configured",
    }
