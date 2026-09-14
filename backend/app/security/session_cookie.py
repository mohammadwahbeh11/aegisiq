"""
app/security/session_cookie.py -- httpOnly session cookies with CSRF
protection (v3.2).

Why
---
Until v3.2 the console kept its JWT in ``localStorage``. That is readable
by any JavaScript running on the page, so a single XSS anywhere in the
console — an npm dependency, a rendered log line, a future careless
``dangerouslySetInnerHTML`` — hands the attacker a valid SOC analyst
token they can use from their own machine. The audit named this as the
remaining structural weakness (docs/SECURITY_AUDIT_v32.md), and this
module is the fix rather than the promise of one.

The design
----------
Two cookies, which is the standard "double-submit" pattern:

  ``aegisiq_session``  — the JWT. **httpOnly**, so script cannot read it,
                         which is the entire point. SameSite=Lax by
                         default (Strict breaks the OAuth-style return
                         navigations the console may grow), Secure
                         whenever the request arrived over TLS.
  ``aegisiq_csrf``     — a random value, readable by script *on purpose*.

The browser attaches the session cookie to any request to this origin,
including one a malicious page triggers — that is CSRF. So every
state-changing request must ALSO carry the CSRF value in the
``X-AegisIQ-CSRF`` header, which only same-origin script can read and
set. A cross-site form post can send the cookie but cannot set the
header, so it is refused.

Bearer tokens are **not** removed. Log shippers, the agent, the smoke
test and every API client keep working exactly as before; the cookie is
an additional accepted credential, and ``AUTH_COOKIE_ENABLED`` controls
whether login also issues one. The console prefers the cookie when it is
there.

Controls: NIST SP 800-53 SC-8, SC-23 (session authenticity), AC-12;
OWASP ASVS V3.4 (cookie-based session management), V4.2.2 (CSRF).
"""
from __future__ import annotations

import secrets

from fastapi import HTTPException, Request, Response, status

from app.config import get_settings

settings = get_settings()

SESSION_COOKIE = "aegisiq_session"
CSRF_COOKIE = "aegisiq_csrf"
CSRF_HEADER = "x-aegisiq-csrf"

# Methods that cannot change state, so they need no CSRF token.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def _secure_flag(request: Request) -> bool:
    """Secure on TLS. Forcing it on plain HTTP would make the cookie
    unusable on a lab network, which is how a security control gets
    switched off wholesale instead of scoped."""
    if settings.AUTH_COOKIE_SECURE_ALWAYS:
        return True
    forwarded_proto = request.headers.get("x-forwarded-proto", "") if settings.TRUST_PROXY_HEADERS else ""
    return request.url.scheme == "https" or forwarded_proto.split(",")[0].strip() == "https"


def issue(response: Response, request: Request, token: str) -> str:
    """Attach the session + CSRF cookies to a successful login response.
    Returns the CSRF value so the body can carry it too (a client that
    cannot read cookies — a native app — still gets what it needs)."""
    csrf = secrets.token_urlsafe(24)
    max_age = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    secure = _secure_flag(request)
    same_site = settings.AUTH_COOKIE_SAMESITE.lower()
    # SameSite=None is meaningless (and rejected by browsers) without
    # Secure; a console on a different origin from its API needs both.
    if same_site == "none":
        secure = True

    response.set_cookie(
        SESSION_COOKIE, token,
        max_age=max_age, httponly=True, secure=secure,
        samesite=same_site, path="/",
    )
    response.set_cookie(
        CSRF_COOKIE, csrf,
        max_age=max_age, httponly=False, secure=secure,
        samesite=same_site, path="/",
    )
    return csrf


def clear(response: Response) -> None:
    """Sign out: remove both cookies."""
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


def token_from_request(request: Request) -> str | None:
    """The session JWT carried by a cookie, if any."""
    return request.cookies.get(SESSION_COOKIE)


def enforce_csrf(request: Request) -> None:
    """Refuse a state-changing COOKIE-authenticated request that does not
    echo the CSRF cookie in the header.

    Deliberately scoped: a request authenticated by an ``Authorization``
    header is not subject to CSRF at all — the browser never attaches that
    header on its own, so there is nothing to forge. Applying the check
    there would break every API client for no security gain.
    """
    if request.method.upper() in SAFE_METHODS:
        return
    if request.headers.get("authorization"):
        return  # bearer request: not cookie-driven, not forgeable
    cookie_token = request.cookies.get(SESSION_COOKIE)
    if not cookie_token:
        return  # unauthenticated or non-cookie; the auth layer decides

    expected = request.cookies.get(CSRF_COOKIE)
    presented = request.headers.get(CSRF_HEADER)
    if not expected or not presented or not secrets.compare_digest(expected, presented):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Missing or invalid CSRF token. A state-changing request "
                "authenticated by cookie must echo the aegisiq_csrf cookie "
                "in the X-AegisIQ-CSRF header."
            ),
        )
