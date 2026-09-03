"""
app/security/license.py -- premium-feature license gating (AegisIQ v2.1+).

The Log Analysis Report is offered as an OPTIONAL PAID FEATURE:
customers activate it by setting AEGISIQ_LICENSE_KEY in .env (or the
UI writes it there via the /api/license/activate endpoint). Without
a valid key, the analysis routes return 402 Payment Required with a
JSON body the console renders as an unlock CTA.

The license mechanism is deliberately simple for the graduation
demo — a shared-secret HMAC over the tier + expiry date. A production
deployment would replace `verify()` with a call to a licensing server
(Keygen, Paddle, LemonSqueezy, or a self-hosted equivalent) without
changing anything else in the codebase.

Anti-abuse: verify() is constant-time (`hmac.compare_digest`), so an
attacker cannot brute-force a valid key by measuring response time.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

# Shared secret used to sign license keys. Rotated per-release to
# invalidate leaked keys. For the graduation demo it's baked in; a real
# deployment reads it from a KMS.
_LICENSE_SECRET = os.environ.get(
    "AEGISIQ_LICENSE_SECRET",
    "aegisiq-demo-secret-2026-graduation-not-for-production",
)

# Demo license keys that ship with the project so the paid features
# can be tried out. Documented in docs/PREMIUM.md. In a real release
# these would not exist -- customers would receive a key by email.
DEMO_KEYS = {
    "AEGIS-DEMO-3G4H-8K2L-P0RT": "trial",       # 30-day trial
    "AEGIS-EDUC-6M9N-4W7X-C1AV": "educational",  # for the graduation panel
}


LicenseTier = Literal["free", "trial", "educational", "business", "enterprise"]

# What tier unlocks what.
_TIER_FEATURES: dict[LicenseTier, set[str]] = {
    "free":         set(),
    "trial":        {"log_analysis"},
    "educational":  {"log_analysis"},
    "business":     {"log_analysis", "pdf_export"},
    "enterprise":   {"log_analysis", "pdf_export", "api_batch", "priority_support"},
}


@dataclass
class LicenseStatus:
    active: bool
    tier: LicenseTier
    features: list[str]
    key_masked: str | None
    detail: str


def _mask(key: str) -> str:
    """AEGIS-EDUC-6M9N-4W7X-C1AV  ->  AEGIS-EDUC-****-****-C1AV"""
    parts = key.split("-")
    if len(parts) < 3:
        return "****"
    return "-".join(parts[:2] + ["****"] * (len(parts) - 3) + parts[-1:])


def verify(key: str | None) -> LicenseStatus:
    """Validate `key` and return its status. Never raises."""
    if not key or not isinstance(key, str):
        return LicenseStatus(
            active=False, tier="free", features=[], key_masked=None,
            detail="No license key configured; running on the free tier.",
        )

    normalized = key.strip().upper()

    # Check the demo/hardcoded keys first (constant-time match against
    # each). These are documented in docs/PREMIUM.md.
    for demo_key, demo_tier in DEMO_KEYS.items():
        if hmac.compare_digest(normalized, demo_key):
            features = _TIER_FEATURES.get(demo_tier, set())
            return LicenseStatus(
                active=True, tier=demo_tier, features=sorted(features),
                key_masked=_mask(normalized),
                detail=f"Active demo license ({demo_tier} tier).",
            )

    # HMAC-signed key format: AEGIS-<TIER4>-<PAYLOAD>-<SIG8>
    # where PAYLOAD is base32-encoded (tier|expiry_iso) and SIG8 is the
    # first 8 chars of an HMAC-SHA256 over the payload with _LICENSE_SECRET.
    try:
        parts = normalized.split("-")
        if len(parts) < 4 or parts[0] != "AEGIS":
            raise ValueError("bad shape")
        sig_provided = parts[-1]
        payload = "-".join(parts[1:-1])
        expected_sig = hmac.new(
            _LICENSE_SECRET.encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()[:8].upper()
        if not hmac.compare_digest(sig_provided, expected_sig):
            raise ValueError("signature mismatch")

        # Decode payload: base32("<tier>|<iso-expiry>")
        try:
            decoded = base64.b32decode(payload.encode() + b"=" * ((8 - len(payload) % 8) % 8)).decode()
            tier_str, expiry_str = decoded.split("|", 1)
            tier: LicenseTier = tier_str.lower()  # type: ignore[assignment]
            if tier not in _TIER_FEATURES:
                raise ValueError("unknown tier")
            expiry = datetime.fromisoformat(expiry_str)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expiry:
                return LicenseStatus(
                    active=False, tier="free", features=[],
                    key_masked=_mask(normalized),
                    detail=f"License expired on {expiry.date().isoformat()}.",
                )
        except Exception:
            # Signature was good but payload malformed -- treat as invalid.
            raise ValueError("payload malformed")

        return LicenseStatus(
            active=True, tier=tier, features=sorted(_TIER_FEATURES[tier]),
            key_masked=_mask(normalized),
            detail=f"Active license (tier: {tier}, expires {expiry.date().isoformat()}).",
        )
    except Exception:  # noqa: BLE001
        return LicenseStatus(
            active=False, tier="free", features=[],
            key_masked=_mask(normalized),
            detail="License key format not recognized or signature invalid.",
        )


def require_feature(feature: str, current_key: str | None) -> LicenseStatus:
    """Raise 402 if the current key does not grant `feature`.
    Returns the LicenseStatus on success so the caller can log tier."""
    status_ = verify(current_key)
    if not status_.active or feature not in status_.features:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "premium_feature",
                "feature": feature,
                "message": (
                    f"'{feature}' is a premium feature. Activate a license "
                    f"from Settings → License, or try a demo key. See "
                    f"docs/PREMIUM.md for details."
                ),
                "current_tier": status_.tier,
                "current_features": status_.features,
                "how_to_activate": {
                    "endpoint": "PATCH /api/license/activate",
                    "body": {"key": "AEGIS-EDUC-6M9N-4W7X-C1AV"},
                    "docs": "docs/PREMIUM.md",
                },
            },
        )
    return status_
