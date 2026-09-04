"""
Regression tests for the live-stream socket's security controls.

These cover behaviour that is easy to break silently and expensive to
discover in production: an unauthenticated socket being accepted, and the
hub's connection set growing without bound.
"""
import os

import pytest

from app.realtime import hub as hub_module
from app.realtime.hub import hub


def _auth(client) -> str:
    r = client.post(
        "/api/auth/login",
        json={
            "username": os.environ["DEFAULT_ADMIN_USERNAME"],
            "password": os.environ["DEFAULT_ADMIN_PASSWORD"],
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_websocket_without_token_is_refused(client):
    """No token must never reach the event stream."""
    with client.websocket_connect("/ws/stream") as ws:
        with pytest.raises(Exception):
            ws.receive_json()


def test_websocket_with_invalid_token_is_refused(client):
    """A forged/expired token is closed rather than silently accepted, so
    the console can distinguish 'session expired' from 'server down'."""
    with client.websocket_connect("/ws/stream?token=not-a-real-jwt") as ws:
        with pytest.raises(Exception):
            ws.receive_json()


def test_authenticated_websocket_receives_hello_and_answers_ping(client):
    token = _auth(client)
    with client.websocket_connect(f"/ws/stream?token={token}") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello"
        assert hello["data"]["username"] == os.environ["DEFAULT_ADMIN_USERNAME"]
        assert hello["data"]["role"] == "administrator"

        # The keepalive the deployed console sends every 25 s to stop a
        # hosting proxy closing an idle socket. If this stops being
        # answered, the production live feed dies quietly.
        ws.send_text("ping")
        assert ws.receive_json()["type"] == "pong"


def test_hub_refuses_connections_past_the_cap(client, monkeypatch):
    """The hub's connection set was unbounded, so an authenticated client
    could exhaust the process's file descriptors. Cap is lowered here so
    the test does not need to open the real limit."""
    monkeypatch.setattr(hub_module, "MAX_CONNECTIONS", 1)
    token = _auth(client)

    with client.websocket_connect(f"/ws/stream?token={token}") as first:
        assert first.receive_json()["type"] == "hello"
        assert hub.connection_count == 1

        # The second socket is over the cap: it must be closed, not registered.
        with client.websocket_connect(f"/ws/stream?token={token}") as second:
            with pytest.raises(Exception):
                second.receive_json()

        assert hub.connection_count == 1, "refused socket must not join the hub"
