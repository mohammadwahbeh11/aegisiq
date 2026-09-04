import os
import tempfile

# Environment variables must be set BEFORE any `app.*` module is imported,
# since app.config.get_settings() and app.database's engine are both
# constructed at import time from the environment.
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix=".db")
os.environ["DATABASE_URL"] = f"sqlite:///{_test_db_path}"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["DEFAULT_ADMIN_USERNAME"] = "admin"
os.environ["DEFAULT_ADMIN_PASSWORD"] = "TestAdmin123!"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """Empty the auth/mutate token buckets before every test.

    The limiters in app/security/rate_limit.py are module-level singletons
    keyed by source IP. Every test in the suite talks to the app from the
    same process and the same TestClient peer address, so their buckets are
    shared: past ~10 logins the whole run collapses into 429s and every
    later test errors in `admin_token` setup rather than exercising the code
    it was written for. Resetting per test isolates them without weakening
    the limiter itself -- rate limiting is still asserted explicitly by the
    tests that care about it.
    """
    from app.security.rate_limit import auth_limiter, mutate_limiter

    auth_limiter.reset()
    mutate_limiter.reset()
    yield


@pytest.fixture()
def client():
    # Entering the context manager runs the app's lifespan (init_db()),
    # so tables + the default admin + default rules exist for every test.
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def admin_token(client):
    response = client.post(
        "/api/auth/login",
        json={"username": os.environ["DEFAULT_ADMIN_USERNAME"], "password": os.environ["DEFAULT_ADMIN_PASSWORD"]},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture()
def db_session(client):
    """A raw SQLAlchemy session bound to the same test database the API
    used within this test (client's lifespan already ran init_db()), for
    tests that need to assert directly against the database instead of
    only checking API responses."""
    from app.database import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def pytest_sessionfinish(session, exitstatus):
    # Dispose the engine first: on Windows an open SQLite connection keeps
    # a lock on the file, so os.remove() below raises WinError 32, which
    # pytest reports as an internal error and which hides the real test
    # results. Both steps are best-effort -- a leftover temp file must
    # never mask the actual outcome of the suite.
    try:
        from app.database import engine

        engine.dispose()
    except Exception:
        pass

    os.close(_test_db_fd)
    try:
        if os.path.exists(_test_db_path):
            os.remove(_test_db_path)
    except OSError:
        pass
