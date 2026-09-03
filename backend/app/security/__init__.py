"""
app/security/ -- transversal security controls that apply across the whole
application, independent of any single route.

Contents:
  rate_limit.py      -- token-bucket rate limiter (per source IP)
  headers.py         -- SecureHeadersMiddleware (HSTS, X-Frame-Options, CSP, ...)
  password_policy.py -- password strength + rotation rules
  audit.py           -- append-only audit log helpers

Each module is self-contained and imports only from the standard library or
SQLAlchemy -- no cross-imports inside app/security/ -- so a subsystem can be
disabled by removing the include in app/main.py without breaking anything else.
"""
