"""
app/compliance/gdpr.py -- GDPR Article 30 records of processing.

Article 30 requires every organization processing personal data to
maintain a record of processing activities (RoPA). The SIEM is
technically a processor of personal data (usernames, IP addresses).

This module returns a machine-readable RoPA that an auditor can
attach to their report.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.log import Log
from app.models.user import User


def generate_gdpr_records(db: Session) -> dict[str, Any]:
    users_count = db.query(func.count(User.id)).scalar() or 0
    log_count = db.query(func.count(Log.id)).scalar() or 0
    return {
        "framework": "GDPR — Regulation (EU) 2016/679, Article 30",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "processing_activities": [
            {
                "activity": "Security event ingestion and detection",
                "purpose": "Detect and respond to information-security incidents "
                           "(GDPR Art. 6(1)(f) — legitimate interest of the controller "
                           "in the security of processing per Art. 32).",
                "categories_of_data_subjects": [
                    "employees (usernames)",
                    "network correspondents (source IPs)",
                ],
                "categories_of_personal_data": [
                    "usernames",
                    "source and destination IP addresses",
                    "authentication timestamps",
                    "hostnames",
                ],
                "recipients": [
                    "SOC analysts (RBAC-restricted)",
                    "administrators (audit access)",
                    "no external transfers unless customer configures Wazuh/webhook integration",
                ],
                "retention": {
                    "logs": "configurable — default 30 days (LOG_RETENTION_DAYS)",
                    "alerts": "configurable — default 90 days (ALERT_RETENTION_DAYS)",
                    "audit_log": "recommended 365 days (regulatory practice)",
                },
                "security_measures": [
                    "TLS 1.3 in transit",
                    "AES-256-GCM at rest (MFA secrets, optional log payload encryption)",
                    "Bcrypt cost=12 for passwords",
                    "MFA (TOTP RFC 6238)",
                    "Rate limiting on authentication",
                    "8-layer defense-in-depth architecture (docs/DEFENSE_LAYERS.md)",
                ],
                "record_count_snapshot": {
                    "users": users_count,
                    "logs": log_count,
                },
            }
        ],
        "data_subject_rights_support": {
            "access": "GET /api/logs?username=<subject> — retrieves all events tied to the subject",
            "erasure": "DELETE /api/logs/{id} + retention purge API",
            "portability": "CSV export (GET /api/logs.csv, /api/alerts.csv)",
            "objection": "customer procedure — supported by RBAC to restrict data access",
        },
    }
