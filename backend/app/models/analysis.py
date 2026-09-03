"""
Analysis report — one row per uploaded log file.

The report itself is stored as JSON on the row so the frontend can
render the whole thing without a second query, and the historic view
is one query away no matter how many reports accumulate.
"""
import enum
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, Integer, JSON, String, ForeignKey

from app.database import Base


class AnalysisStatus(str, enum.Enum):
    PENDING = "pending"       # accepted, worker hasn't picked it up
    RUNNING = "running"       # analysis in progress
    COMPLETE = "complete"     # done, report ready
    FAILED = "failed"


class AnalysisReport(Base):
    __tablename__ = "analysis_reports"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    finished_at = Column(DateTime, nullable=True)
    filename = Column(String(255), nullable=False)
    total_bytes = Column(Integer, nullable=False, default=0)
    status = Column(Enum(AnalysisStatus), nullable=False, default=AnalysisStatus.PENDING, index=True)
    # The compressed summary the console renders. Shape is documented
    # in app/analysis/report.py::Report.
    summary = Column(JSON, nullable=True)
    # A short error string when status=FAILED; NULL otherwise.
    error = Column(String(500), nullable=True)
    # Which user uploaded this report -- for audit + RBAC.
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    license_tier = Column(String(32), nullable=True)  # captured at run time
