"""
app/realtime/hub.py -- the live event bus behind the console's real-time
updates (project section 3.4.2: "the dashboard updates without the
analyst refreshing the page").

Why a hub rather than the frontend polling: an analyst watching an
attack unfold needs the alert to appear at the moment the rule fires,
not up to N seconds later. Polling every second to achieve that would
mean a database round-trip per second per open browser tab on a system
whose whole premise is running in a resource-constrained environment.
One broadcast per actual event costs nothing when nothing is happening.

Threading model -- the part that is easy to get wrong:
FastAPI runs `def` (non-async) route handlers in a worker thread, and
this project's ingestion path is deliberately synchronous (SQLAlchemy's
sync Session). So `publish()` is nearly always called from a worker
thread, NOT from the event loop, and must not touch WebSocket objects
directly. It hands the work to the loop with
`asyncio.run_coroutine_threadsafe`, using the loop captured at startup
(see `bind_loop`, called from the app's lifespan in app/main.py).

If no loop has been bound -- which is the case under the test suite's
TestClient for plain synchronous requests -- `publish()` records the
event in the replay buffer and returns. Broadcasting is an additive
notification channel; failing to deliver it must never break ingestion,
which is the system's actual job.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Any

from starlette.websockets import WebSocket

logger = logging.getLogger(__name__)

# How many recent events a newly connected client is replayed. Small on
# purpose: this is a "what did I just miss" buffer for a browser tab that
# reconnected after a blip, not a substitute for the REST history
# endpoints (/api/alerts, /api/logs), which are the real source of truth.
REPLAY_BUFFER_SIZE = 50

# Event type names, referenced by the frontend's WebSocket client.
EVENT_LOG = "log"
EVENT_ALERT = "alert"
EVENT_SOAR = "soar_action"
EVENT_HELLO = "hello"


class EventHub:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._recent: deque[dict[str, Any]] = deque(maxlen=REPLAY_BUFFER_SIZE)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._sequence = 0

    # --- lifecycle -------------------------------------------------------

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Called once from the app lifespan so worker threads know which
        loop to schedule broadcasts on."""
        self._loop = loop

    def unbind_loop(self) -> None:
        self._loop = None

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections.discard(websocket)

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    def recent_events(self) -> list[dict[str, Any]]:
        return list(self._recent)

    # --- publishing ------------------------------------------------------

    def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        """Fire-and-forget. Safe to call from a worker thread or from the
        event loop, and safe to call when nothing is listening."""
        self._sequence += 1
        message = {
            "seq": self._sequence,
            "type": event_type,
            "at": datetime.now(timezone.utc).isoformat(),
            "data": payload,
        }
        self._recent.append(message)

        if not self._connections:
            return

        loop = self._loop
        if loop is None:
            # No event loop bound (e.g. the synchronous test client).
            # The event is still buffered above; nothing to deliver to.
            return

        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop in this thread -- i.e. we are on a FastAPI
            # worker thread, the normal case for this project's sync
            # routes. That is precisely what run_coroutine_threadsafe is
            # for.
            running_loop = None

        try:
            if running_loop is loop:
                loop.create_task(self._broadcast(message))
            else:
                asyncio.run_coroutine_threadsafe(self._broadcast(message), loop)
        except RuntimeError as exc:  # loop already closed during shutdown
            logger.debug("Dropped realtime event during shutdown: %s", exc)

    async def _broadcast(self, message: dict[str, Any]) -> None:
        if not self._connections:
            return
        encoded = json.dumps(message, default=str)
        # Iterate over a copy: a failing send mutates the set below.
        for websocket in list(self._connections):
            try:
                await websocket.send_text(encoded)
            except Exception:  # noqa: BLE001 - a dead socket must not stop the rest
                self.disconnect(websocket)


# Module-level singleton: one hub per process, imported directly by the
# ingestion/detection/SOAR paths that need to announce something.
hub = EventHub()
