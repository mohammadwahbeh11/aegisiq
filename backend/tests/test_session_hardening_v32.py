"""
tests/test_session_hardening_v32.py — evidence for the second v3.2 pass:
cookie sessions, CSRF, server-side logout, first-run MFA enrolment and
the shared rate-limit store.

  SC-23 / ASVS V3.4  session travels as an httpOnly cookie
  ASVS V4.2.2        CSRF required on cookie-authenticated writes
  AC-12              logout revokes every token for the account
  IA-2(1)            a user forced to use MFA can actually enrol
  SC-5               the limiter reports which store is authoritative
"""
import os

import pytest

from app.config import get_settings
from app.models.user import User
from app.security import session_cookie

USERNAME = os.environ["DEFAULT_ADMIN_USERNAME"]
PASSWORD = os.environ["DEFAULT_ADMIN_PASSWORD"]


def _login(client):
    response = client.post("/api/auth/login",
                           json={"username": USERNAME, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return response


@pytest.fixture(autouse=True)
def _restore_admin(client, db_session):
    yield
    user = db_session.query(User).filter(User.username == USERNAME).first()
    if user is not None:
        user.is_active = True
        user.failed_login_count = 0
        user.locked_until = None
        db_session.commit()


# ── SC-23 · the session is an httpOnly cookie ───────────────────────
def test_login_sets_an_httponly_session_cookie(client):
    response = _login(client)
    raw = response.headers.get("set-cookie", "")
    assert session_cookie.SESSION_COOKIE in raw
    # The session cookie must be unreadable by page script — that is the
    # entire reason it exists.
    session_directive = [part for part in raw.split(",")
                         if session_cookie.SESSION_COOKIE in part]
    assert session_directive, raw
    assert "httponly" in session_directive[0].lower()


def test_login_also_sets_a_readable_csrf_cookie(client):
    response = _login(client)
    assert response.cookies.get(session_cookie.CSRF_COOKIE)
    # ...and echoes it in the body for clients that cannot read cookies.
    assert response.json()["csrf_token"]


def test_cookie_alone_authenticates_a_read(client):
    _login(client)
    # TestClient keeps the cookie jar; no Authorization header is sent.
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200


# ── ASVS V4.2.2 · CSRF ──────────────────────────────────────────────
def test_cookie_write_without_csrf_header_is_refused(client):
    _login(client)
    response = client.patch("/api/auth/password",
                            json={"current_password": PASSWORD,
                                  "new_password": "Irrelevant-Because-Refused!9"})
    assert response.status_code == 403
    assert "csrf" in response.json()["detail"].lower()


def test_cookie_write_with_csrf_header_is_allowed(client):
    login = _login(client)
    csrf = login.json()["csrf_token"]
    # Wrong current password → 401 from the handler, NOT 403 from the CSRF
    # gate: proof the request got past the anti-forgery check.
    response = client.patch(
        "/api/auth/password",
        json={"current_password": "not-the-password", "new_password": "Whatever-Pass!9"},
        headers={session_cookie.CSRF_HEADER: csrf},
    )
    assert response.status_code == 401


def test_bearer_write_needs_no_csrf_header(client):
    """An Authorization header cannot be attached by a cross-site page, so
    requiring CSRF there would break API clients for no gain."""
    token = _login(client).json()["access_token"]
    client.cookies.clear()
    response = client.patch(
        "/api/auth/password",
        json={"current_password": "not-the-password", "new_password": "Whatever-Pass!9"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401  # handler, not the CSRF gate


# ── AC-12 · logout really ends the session ──────────────────────────
def test_logout_revokes_tokens_issued_before_it(client):
    login = _login(client)
    token = login.json()["access_token"]
    csrf = login.json()["csrf_token"]

    out = client.post("/api/auth/logout", headers={session_cookie.CSRF_HEADER: csrf})
    assert out.status_code == 200 and out.json()["ok"] is True

    client.cookies.clear()
    response = client.get("/api/dashboard/stats",
                          headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


# ── IA-2(1) · a mandated second factor can actually be set up ───────
def test_challenge_token_can_enrol_mfa_but_nothing_else(client, db_session, monkeypatch):
    """With MFA_REQUIRED on, an un-enrolled user holds only a challenge
    token. It must open /api/mfa/enroll (or the policy locks the
    administrator out of their own console) and must open nothing else."""
    from app.auth.security import create_mfa_challenge_token

    challenge = create_mfa_challenge_token(subject=USERNAME)
    client.cookies.clear()
    auth = {"Authorization": f"Bearer {challenge}"}

    enrolled = client.post("/api/mfa/enroll", headers=auth)
    assert enrolled.status_code == 200, enrolled.text
    body = enrolled.json()
    assert body["secret"] and body["otpauth_uri"].startswith("otpauth://")

    # The same token opens no SOC data.
    assert client.get("/api/dashboard/stats", headers=auth).status_code == 401
    assert client.get("/api/alerts", headers=auth).status_code == 401

    # Clean up the pending enrolment so later tests see a fresh account.
    from app.models.mfa import MfaStatus, UserMFA
    row = (db_session.query(UserMFA)
           .join(User, User.id == UserMFA.user_id)
           .filter(User.username == USERNAME).first())
    if row is not None:
        row.status = MfaStatus.DISABLED
        row.secret_enc = None
        db_session.commit()


def test_enrolment_confirmation_returns_a_usable_access_token(client, db_session):
    """Finishing enrolment completes the login it started from — both
    factors were just proven, so sending the user back to the password
    box proves nothing."""
    from app.auth.security import create_mfa_challenge_token
    from app.models.mfa import MfaStatus, UserMFA
    from app.security import totp

    challenge = create_mfa_challenge_token(subject=USERNAME)
    client.cookies.clear()
    auth = {"Authorization": f"Bearer {challenge}"}

    secret = client.post("/api/mfa/enroll", headers=auth).json()["secret"]
    confirmed = client.post("/api/mfa/confirm",
                            json={"code": totp.now_code(secret)}, headers=auth)
    assert confirmed.status_code == 200, confirmed.text
    body = confirmed.json()
    assert body["status"] == "active"
    assert len(body["backup_codes"]) == 10
    assert body["access_token"], "enrolment should hand back a real session"

    client.cookies.clear()
    assert client.get(
        "/api/dashboard/stats",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    ).status_code == 200

    row = (db_session.query(UserMFA)
           .join(User, User.id == UserMFA.user_id)
           .filter(User.username == USERNAME).first())
    row.status = MfaStatus.DISABLED
    row.secret_enc = None
    row.backup_codes_enc = None
    db_session.commit()


# ── SC-5 · the limiter says which store is authoritative ────────────
def test_health_reports_the_rate_limit_store_and_posture(client):
    body = client.get("/health").json()
    security = body["security"]
    assert security["rate_limit_store"] in ("in_process", "redis")
    # The posture fields an operator has to verify after a deploy.
    for field in ("environment", "encryption_at_rest", "account_lockout",
                  "mfa", "session_transport", "trust_proxy_headers",
                  "max_upload_mb"):
        assert field in security, field
    assert security["max_upload_mb"] == get_settings().MAX_UPLOAD_MB


def test_production_guardrail_rejects_an_unsecured_cookie_policy():
    """SameSite=None without Secure is silently dropped by browsers: the
    session would never persist and every login would look like it did
    nothing. The production guard catches it at boot."""
    from app.config import Settings, validate_production_security

    settings = Settings(
        ENV="production",
        SECRET_KEY="x" * 48,
        DEFAULT_ADMIN_PASSWORD="An-Actually-Set-Password!42",
        DATA_ENCRYPTION_KEY="y" * 64,
        CORS_ORIGINS="https://console.example.org",
        AUTH_COOKIE_ENABLED=True,
        AUTH_COOKIE_SAMESITE="none",
        AUTH_COOKIE_SECURE_ALWAYS=False,
    )
    problems = validate_production_security(settings)
    assert any("SAMESITE" in p.upper() for p in problems), problems

    settings = settings.model_copy(update={"AUTH_COOKIE_SECURE_ALWAYS": True})
    assert validate_production_security(settings) == []
