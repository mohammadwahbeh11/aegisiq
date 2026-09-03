"""
app/api/routes/analysis.py -- Log Analysis Report API (PREMIUM).

All endpoints under this router require an active license that grants
the "log_analysis" feature. Without a valid key, every call returns
402 Payment Required with an unlock CTA.

Endpoints:
  POST   /api/analysis/upload           multipart upload -> report_id
  GET    /api/analysis                  paginated list of past reports
  GET    /api/analysis/{id}             full report as JSON
  GET    /api/analysis/{id}/download    the printable HTML report
  DELETE /api/analysis/{id}             delete a report (admin only)

The analysis runs SYNCHRONOUSLY in the request thread because the
work is CPU-bound and short (a 5 MB log file takes ~1-2 s on a
single-vCPU VM). A file exceeding MAX_BYTES is truncated with a
clear flag in the report.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import (
    APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status,
)
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.analysis import engine as analysis_engine
from app.analysis import report as analysis_report
from app.api.deps import get_db
from app.auth.dependencies import get_current_user, require_role
from app.config import get_settings
from app.models.analysis import AnalysisReport, AnalysisStatus
from app.models.user import User, UserRole
from app.security import audit
from app.security.license import require_feature, verify

router = APIRouter(prefix="/api/analysis", tags=["analysis (premium)"])
settings = get_settings()
logger = logging.getLogger(__name__)

ACT_ANALYSIS_UPLOAD = "analysis.upload"
ACT_ANALYSIS_DELETE = "analysis.delete"


def _source_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if fwd:
        return fwd
    return request.client.host if request.client else None


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_and_analyze(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Upload a log file, run the analysis, return the created report."""
    license_status = require_feature("log_analysis", settings.PREMIUM_LICENSE_KEY)

    raw = await file.read()
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )
    if len(raw) > analysis_engine.MAX_BYTES:
        # We DO accept the file but truncate; the report says so.
        pass

    filename = file.filename or "unnamed.log"

    report_row = AnalysisReport(
        filename=filename,
        total_bytes=len(raw),
        status=AnalysisStatus.RUNNING,
        uploaded_by=user.id,
        license_tier=license_status.tier,
    )
    db.add(report_row)
    db.commit()
    db.refresh(report_row)

    try:
        raw_results = analysis_engine.analyze(raw, db)
        summary = analysis_report.build_summary(raw_results)
        report_row.summary = summary
        report_row.status = AnalysisStatus.COMPLETE
        report_row.finished_at = datetime.now(timezone.utc)
        db.commit()

        audit.record(
            db, action=ACT_ANALYSIS_UPLOAD, outcome="success",
            username=user.username, source_ip=_source_ip(request),
            target=str(report_row.id),
            details={"filename": filename, "bytes": len(raw),
                     "findings": summary["findings_count"],
                     "worst": summary.get("worst_severity")},
        )
    except Exception as exc:  # noqa: BLE001
        report_row.status = AnalysisStatus.FAILED
        report_row.error = str(exc)[:500]
        report_row.finished_at = datetime.now(timezone.utc)
        db.commit()
        logger.exception("analysis failed for report %s", report_row.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {exc}",
        )

    return _serialize(report_row)


@router.get("")
def list_reports(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    require_feature("log_analysis", settings.PREMIUM_LICENSE_KEY)
    query = db.query(AnalysisReport)
    # Analyst sees their own reports; admin sees all.
    if user.role != UserRole.ADMINISTRATOR:
        query = query.filter(AnalysisReport.uploaded_by == user.id)
    total = query.count()
    rows = (query.order_by(AnalysisReport.created_at.desc())
                 .offset(offset).limit(limit).all())
    return {"total": total, "items": [_serialize(r, brief=True) for r in rows]}


@router.get("/{report_id}")
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    require_feature("log_analysis", settings.PREMIUM_LICENSE_KEY)
    report = _load(report_id, db, user)
    return _serialize(report)


@router.get("/{report_id}/download", response_class=HTMLResponse)
def download_report(
    report_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Printable HTML report. The browser 'Save as PDF' does the rest."""
    require_feature("log_analysis", settings.PREMIUM_LICENSE_KEY)
    report = _load(report_id, db, user)
    if report.status != AnalysisStatus.COMPLETE or not report.summary:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Report {report_id} is not complete (status: {report.status.value}).",
        )
    # Rebuild the HTML from the stored summary. We could re-run engine,
    # but the summary already carries every field render_html needs.
    html_doc = analysis_report.render_html(_summary_to_raw(report.summary), report.filename)
    return HTMLResponse(content=html_doc)


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(
    report_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(UserRole.ADMINISTRATOR)),
):
    require_feature("log_analysis", settings.PREMIUM_LICENSE_KEY)
    report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    db.delete(report)
    db.commit()
    audit.record(
        db, action=ACT_ANALYSIS_DELETE, outcome="success",
        username=user.username, source_ip=_source_ip(request),
        target=str(report_id),
    )


# ─── helpers ──────────────────────────────────────────────────────────

def _load(report_id: int, db: Session, user: User) -> AnalysisReport:
    report = db.query(AnalysisReport).filter(AnalysisReport.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    if user.role != UserRole.ADMINISTRATOR and report.uploaded_by != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not your report")
    return report


def _serialize(report: AnalysisReport, brief: bool = False) -> dict:
    out = {
        "id": report.id,
        "filename": report.filename,
        "status": report.status.value,
        "total_bytes": report.total_bytes,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "finished_at": report.finished_at.isoformat() if report.finished_at else None,
        "license_tier": report.license_tier,
        "error": report.error,
    }
    if not brief and report.summary:
        out["summary"] = report.summary
    elif brief and report.summary:
        # Small view for the list page
        out["findings_count"] = report.summary.get("findings_count", 0)
        out["worst_severity"] = report.summary.get("worst_severity")
        out["parsed_events"] = report.summary.get("parsed_events", 0)
    return out


def _summary_to_raw(summary: dict) -> dict:
    """The HTML renderer expects the raw dict shape; summary IS a
    superset of it, so this is essentially identity + fill-ins."""
    return {
        **summary,
        "format": summary.get("input_format", "text"),
    }


# ═════ License management (small sibling router mounted separately) ═════
license_router = APIRouter(prefix="/api/license", tags=["license"])


@license_router.get("/status")
def license_status(_user: User = Depends(get_current_user)):
    """Current license status. Safe for both roles to read."""
    st = verify(settings.PREMIUM_LICENSE_KEY)
    return {
        "active": st.active,
        "tier": st.tier,
        "features": st.features,
        "key_masked": st.key_masked,
        "detail": st.detail,
    }


@license_router.patch("/activate")
def activate_license(
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(UserRole.ADMINISTRATOR)),
):
    """Activate a license key at runtime. Persists to the in-memory
    settings object; a proper deployment would write to .env or a KMS.
    """
    key = payload.get("key", "").strip()
    if not key:
        raise HTTPException(status_code=400, detail="Missing 'key' in body")

    st = verify(key)
    if not st.active:
        return {"active": False, "detail": st.detail, "tier": "free", "features": []}

    # Persist for THIS process lifetime. Restart-safe persistence would
    # write to .env or a secrets store.
    settings.PREMIUM_LICENSE_KEY = key

    audit.record(
        db, action="license.activate", outcome="success",
        username=user.username, source_ip=_source_ip(request),
        details={"tier": st.tier, "features": st.features, "key_masked": st.key_masked},
    )
    return {
        "active": True, "tier": st.tier, "features": st.features,
        "key_masked": st.key_masked, "detail": st.detail,
    }
