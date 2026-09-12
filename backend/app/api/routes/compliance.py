"""
app/api/routes/compliance.py -- one-click compliance evidence.

  GET /api/compliance/frameworks           -- list of supported frameworks
  GET /api/compliance/soc2                 -- SOC 2 evidence JSON
  GET /api/compliance/soc2/report          -- SOC 2 report as HTML
  GET /api/compliance/iso27001             -- ISO 27001 evidence JSON
  GET /api/compliance/iso27001/report      -- ISO 27001 report as HTML
  GET /api/compliance/gdpr                 -- GDPR RoPA JSON
  GET /api/compliance/gdpr/report          -- GDPR RoPA as HTML

Requires administrator role — customer sensitivity, not for viewers.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.dependencies import get_current_user
from app.compliance import (
    generate_gdpr_records,
    generate_iso27001_evidence,
    generate_soc2_evidence,
)
from app.compliance.report import render_html
from app.models.user import User

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


def _require_admin(user: User = Depends(get_current_user)) -> User:
    role = user.role.value if hasattr(user.role, "value") else str(user.role)
    if role != "administrator":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="administrator role required")
    return user


@router.get("/frameworks")
def frameworks(_user=Depends(get_current_user)):
    """List frameworks with a one-line description."""
    return {
        "frameworks": [
            {"id": "soc2", "name": "SOC 2 Type I", "standard": "AICPA Trust Services Criteria 2017"},
            {"id": "iso27001", "name": "ISO/IEC 27001:2022", "standard": "Annex A controls"},
            {"id": "gdpr", "name": "GDPR Article 30", "standard": "Records of Processing"},
        ]
    }


@router.get("/soc2")
def soc2(window_days: int = Query(90, ge=1, le=365),
         db: Session = Depends(get_db),
         _admin=Depends(_require_admin)):
    return generate_soc2_evidence(db, window_days=window_days)


@router.get("/soc2/report", response_class=HTMLResponse)
def soc2_report(window_days: int = Query(90, ge=1, le=365),
                db: Session = Depends(get_db),
                _admin=Depends(_require_admin)):
    return HTMLResponse(render_html(generate_soc2_evidence(db, window_days=window_days)))


@router.get("/iso27001")
def iso(window_days: int = Query(90, ge=1, le=365),
        db: Session = Depends(get_db),
        _admin=Depends(_require_admin)):
    return generate_iso27001_evidence(db, window_days=window_days)


@router.get("/iso27001/report", response_class=HTMLResponse)
def iso_report(window_days: int = Query(90, ge=1, le=365),
               db: Session = Depends(get_db),
               _admin=Depends(_require_admin)):
    return HTMLResponse(render_html(generate_iso27001_evidence(db, window_days=window_days)))


@router.get("/gdpr")
def gdpr(db: Session = Depends(get_db),
         _admin=Depends(_require_admin)):
    return generate_gdpr_records(db)


@router.get("/gdpr/report", response_class=HTMLResponse)
def gdpr_report(db: Session = Depends(get_db),
                _admin=Depends(_require_admin)):
    return HTMLResponse(render_html(generate_gdpr_records(db)))
