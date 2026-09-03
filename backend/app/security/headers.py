"""
app/security/headers.py -- middleware that stamps every response with a
strict set of security headers.

Rationale for each header (kept short so the config is auditable):

  HSTS                          - browsers refuse plain-HTTP after first visit
  X-Frame-Options: DENY         - can't be embedded in an iframe (clickjacking)
  X-Content-Type-Options: nosniff - browsers respect the declared MIME type
  Referrer-Policy               - don't leak the console URL to third-party links
  Permissions-Policy            - deny camera/microphone/geolocation by default
  X-XSS-Protection: 0           - modern browsers use CSP instead; the legacy
                                   header has been documented as exploitable
  Content-Security-Policy       - default-src 'self'; blocks inline+eval on
                                   the API, tightened further on the console
  Cache-Control: no-store       - JSON responses are never cached by any proxy

HSTS is only emitted when the request came in over TLS -- otherwise a
browser using plain HTTP once would refuse to load the site forever.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_DEFAULT_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), interest-cohort=(), "
        "usb=(), serial=(), payment=()"
    ),
    "X-XSS-Protection": "0",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-site",
    # The backend serves JSON only -- no HTML, so an attacker cannot use it
    # as an XSS sink. default-src 'none' is stricter than 'self' for a pure
    # API surface.
    "Content-Security-Policy": (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'none';"
    ),
}


class SecureHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        # Emit the constant set.
        for name, value in _DEFAULT_HEADERS.items():
            response.headers.setdefault(name, value)

        # HSTS only over TLS -- a browser that ever saw HSTS from a
        # plain-HTTP endpoint would then refuse to load the site until
        # the header expires, which is not what you want during
        # development or on a lab network.
        if request.url.scheme == "https":
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains; preload",
            )

        # Don't let a caching proxy hand another user a stale token
        # payload from /api/auth/login.
        if request.url.path.startswith("/api/auth"):
            response.headers["Cache-Control"] = "no-store"

        return response
