"""
app/security/log_redaction.py -- keep credentials out of the access log.

The console's live socket authenticates with `?token=<JWT>` because a
browser cannot set an Authorization header on a WebSocket handshake (the
trade-off is documented in app/api/routes/stream.py). The unavoidable
consequence is that uvicorn's access logger writes the full request line
-- query string included -- so every socket connection printed a VALID
bearer token into the log. On a hosted deployment those logs are retained
and readable from the provider's dashboard, which turns "can read logs"
into "can impersonate any analyst until the token expires".

Fixing the auth mechanism properly means issuing a single-use ticket for
the socket, which is a larger change to a working path. Redacting the
value at the logging boundary removes the exposure now, costs nothing,
and stays correct even after the mechanism changes -- so it is worth
having either way.

The filter is deliberately total: it never raises, because a logging
filter that throws would take down request logging entirely.
"""
from __future__ import annotations

import logging
import re

# Matches a sensitive query parameter and its value, keeping the key so the
# log still shows that a token WAS supplied -- useful when debugging an auth
# failure, which is exactly when someone reaches for these logs.
_SENSITIVE_QUERY = re.compile(
    r"(?i)([?&](?:token|access_token|api[_-]?key|password|secret)=)[^&\s\"']+"
)
_REPLACEMENT = r"\1[REDACTED]"

# Loggers that carry request lines. The root logger is included so anything
# that propagates there is covered too.
_TARGET_LOGGERS = ("uvicorn.access", "uvicorn.error", "uvicorn", "")


def _scrub(value: str) -> str:
    return _SENSITIVE_QUERY.sub(_REPLACEMENT, value)


class RedactSecretsFilter(logging.Filter):
    """Strips sensitive query-string values from a log record in place."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            if isinstance(record.msg, str):
                record.msg = _scrub(record.msg)
            # uvicorn.access passes the request line through record.args, so
            # scrubbing only record.msg would miss the actual token.
            if isinstance(record.args, tuple):
                record.args = tuple(
                    _scrub(arg) if isinstance(arg, str) else arg for arg in record.args
                )
            elif isinstance(record.args, dict):
                record.args = {
                    key: _scrub(val) if isinstance(val, str) else val
                    for key, val in record.args.items()
                }
        except Exception:  # noqa: BLE001 - never break logging
            pass
        return True


def install() -> None:
    """Attach the filter to every logger that can emit a request line."""
    log_filter = RedactSecretsFilter()
    for name in _TARGET_LOGGERS:
        logging.getLogger(name).addFilter(log_filter)
