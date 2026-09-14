"""
app/api/routes/stream.py -- the console's live connection.

Authentication over WebSocket, and why the token is a query parameter:
a browser's WebSocket API cannot set an Authorization header on the
handshake, so the standard options are a cookie or `?token=`. This
project keeps its JWT in localStorage (a documented trade-off, see
frontend/src/api/client.ts) and has no cookie session, so `?token=` is
the only option available without inventing a second auth mechanism.

The consequence is worth naming rather than glossing over: query strings
appear in server access logs and proxy logs, so this token can leak into
logs in a way a header would not. That is acceptable for a lab/graduation
deployment with short-lived tokens (60 minutes by default); a production
deployment should terminate TLS at a proxy and prefer an httpOnly cookie
or a short-lived single-use ticket issued specifically for the socket.

An unauthenticated or invalid token is closed with 1008 (policy
violation) rather than silently accepted, so the frontend can tell the
difference between "your session expired" and "the server is down".
"""
import logging

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from app.auth.security import decode_access_token
from app.database import SessionLocal
from app.models.user import User
from app.realtime.hub import EVENT_HELLO, hub
from app.security import lockout, session_cookie

logger = logging.getLogger(__name__)

router = APIRouter(tags=["realtime"])

WS_POLICY_VIOLATION = 1008


def _authenticate(token: str | None) -> User | None:
    """Authenticate the socket handshake with exactly the same rules the
    REST dependency applies.

    v3.2 — this used to accept ANY signature-valid token, which meant the
    short-lived ``mfa_pending`` challenge token (issued after the password
    step but *before* the second factor) opened the live alert stream: a
    stolen password alone was enough to watch the SOC in real time, with
    MFA bypassed. The socket now rejects challenge tokens, disabled
    accounts, locked accounts and superseded token versions.
    """
    if not token:
        return None
    payload = decode_access_token(token)
    if payload is None or "sub" not in payload:
        return None

    # Challenge tokens authorise /api/auth/mfa/verify and /api/mfa/enroll
    # — never a data channel.
    if payload.get("mfa_pending"):
        return None

    # A short-lived session of its own: the socket may stay open for a
    # long time, but the user lookup happens once, at connect.
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == payload["sub"]).first()
        if user is None:
            return None
        if not getattr(user, "is_active", True):
            return None
        if int(payload.get("ver", 1)) != int(getattr(user, "token_version", 1) or 1):
            return None
        if lockout.is_locked(user):
            return None
        return user
    finally:
        db.close()


@router.websocket("/ws/stream")
async def stream(websocket: WebSocket, token: str | None = Query(default=None)):
    # v3.2 — prefer the httpOnly session cookie, which the browser sends
    # on the handshake automatically. That removes the JWT from the query
    # string entirely for console users, and with it the "the token ends
    # up in proxy access logs" trade-off documented above. ?token= stays
    # supported for non-browser clients and for deployments running with
    # AUTH_COOKIE_ENABLED=false.
    if not token:
        token = websocket.cookies.get(session_cookie.SESSION_COOKIE)
    user = _authenticate(token)
    if user is None:
        # accept() then close() rather than close() alone: a plain close
        # before the handshake completes surfaces in the browser as an
        # opaque network error with no code, which is indistinguishable
        # from the backend being unreachable.
        await websocket.accept()
        await websocket.close(code=WS_POLICY_VIOLATION, reason="Invalid or missing token")
        return

    if not await hub.connect(websocket):
        # Hub at capacity; it has already closed the socket with 1013.
        return

    try:
        # Replay whatever happened in the last few seconds, so a tab that
        # reconnected after a blip doesn't show a suspicious gap. The
        # REST endpoints remain the source of truth for real history.
        await websocket.send_json(
            {
                "type": EVENT_HELLO,
                "data": {
                    "username": user.username,
                    "role": user.role.value,
                    "subscribers": hub.connection_count,
                    "replay": hub.recent_events(),
                },
            }
        )

        while True:
            # This server pushes; it does not take commands over the
            # socket. Reading is still necessary so that a client
            # disconnect is noticed promptly instead of the connection
            # lingering in the hub's set until the next broadcast fails.
            # A client-sent "ping" is answered so browsers behind idle
            # proxies can keep the connection warm.
            message = await websocket.receive_text()
            if message.strip().lower() == "ping":
                await websocket.send_json({"type": "pong", "data": {}})
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 - one bad socket must not affect the others
        logger.debug("WebSocket stream closed unexpectedly", exc_info=True)
    finally:
        hub.disconnect(websocket)
        if websocket.client_state is not WebSocketState.DISCONNECTED:
            try:
                await websocket.close()
            except RuntimeError:
                pass
