"""
app/soar/webhook.py -- outbound SOAR webhook (AegisIQ v2.3).

Bridges AegisIQ's record-only SOAR layer to an external automation
platform — Shuffle, Cortex, TheHive, n8n, or any HTTP receiver. When
`SOAR_WEBHOOK_URL` is configured, each recorded containment action is
POSTed as JSON so a real playbook can run there (block the IP at the
firewall, disable the account in AD, open a case…). This keeps AegisIQ
itself safe (it still never runs a firewall command on its own) while
making it a first-class citizen in a real automation pipeline.

Design:
  * OFF by default — no URL, no calls (record-only, as before).
  * NON-BLOCKING — the POST runs on a short-lived daemon thread so a slow
    or dead receiver never delays log ingestion. Failures are logged, not
    raised.
  * AUTHENTICATED — if `SOAR_WEBHOOK_SECRET` is set, the body is signed
    with HMAC-SHA256 and sent in the `X-AegisIQ-Signature` header
    (``sha256=<hex>``), so the receiver can verify the call really came
    from this SIEM (the same scheme GitHub/Stripe webhooks use).
  * SELF-CONTAINED — uses urllib from the stdlib; no extra dependency.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import urllib.request
from typing import Any

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


def _sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _post(url: str, payload: dict[str, Any], secret: str, timeout: float) -> None:
    body = json.dumps(payload, default=str).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "AegisIQ-SOAR/2.3",
    }
    if secret:
        headers["X-AegisIQ-Signature"] = _sign(body, secret)
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-configured URL
            logger.info("SOAR webhook delivered action=%s status=%s",
                        payload.get("action_type"), resp.status)
    except Exception as exc:  # noqa: BLE001 - never propagate into ingestion
        logger.warning("SOAR webhook delivery failed: %s", exc)


def dispatch(action_payload: dict[str, Any]) -> None:
    """Fire-and-forget delivery of one serialized SOAR action to the
    configured webhook. Returns immediately; the network call runs on a
    daemon thread. No-op when no URL is configured."""
    url = (settings.SOAR_WEBHOOK_URL or "").strip()
    if not url:
        return
    secret = settings.SOAR_WEBHOOK_SECRET or ""
    timeout = settings.SOAR_WEBHOOK_TIMEOUT_SECONDS
    envelope = {
        "source": "AegisIQ",
        "kind": "soar_action",
        "action": action_payload,
    }
    threading.Thread(
        target=_post, args=(url, envelope, secret, timeout), daemon=True,
    ).start()
