"""
Status of the optional external integrations, so the console can state
plainly what is and is not connected instead of showing a decorative
"connected" badge.
"""
from fastapi import APIRouter, Depends

from app.auth.dependencies import get_current_user
from app.config import get_settings
from app.integrations import wazuh

router = APIRouter(prefix="/api/integrations", tags=["integrations"])

settings = get_settings()


@router.get("/wazuh/status")
def wazuh_status(_user=Depends(get_current_user)):
    """Performs a real call to the configured Wazuh Manager. Never
    raises -- see app/integrations/wazuh.py, which classifies every
    failure mode (not configured / unreachable / unauthorized / error)
    rather than letting an integration take the console down."""
    return wazuh.get_status()


@router.get("")
def list_integrations(_user=Depends(get_current_user)):
    """A single call the console uses to render its integration panel."""
    return {
        "wazuh": wazuh.get_status(),
        "soar": {
            "enabled": settings.SOAR_ENABLED,
            "execution_mode": "execute_requested" if settings.SOAR_EXECUTE else "record_only",
            "detail": (
                "Containment actions are decided and recorded, not executed. "
                "This build ships no code that changes a firewall or an account; "
                "see app/soar/engine.py."
            ),
        },
    }
