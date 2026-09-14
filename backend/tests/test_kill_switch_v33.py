"""
tests/test_kill_switch_v33.py — evidence that containment is real.

The protocol under test is the one `agent/kill_switch_agent_v2.py`
speaks, so these tests impersonate that agent exactly: poll for orders,
verify the SIEM's signature, sign a result and post it back.

  IR-4(2)  an alert's containment decision reaches a real endpoint
  AC-3     only an administrator enrols an agent or issues an order
  SC-13    both directions are HMAC-SHA256 signed; replay is rejected
  SI-4(7)  guard rails refuse dangerous targets, with a recorded reason
  CM-3     every order and result is audited, and every block reversible
"""
import hashlib
import hmac
import json
import os
import time

import pytest

from app.models.endpoint_agent import EndpointAgent, OrderStatus, SoarOrder
from app.models.soar import SoarAction, SoarActionStatus, SoarActionType

USERNAME = os.environ["DEFAULT_ADMIN_USERNAME"]
PASSWORD = os.environ["DEFAULT_ADMIN_PASSWORD"]
ENDPOINT = "test-endpoint-01"


def _auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


def _sign(secret: str, body: bytes) -> str:
    ts = str(int(time.time()))
    nonce = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
    mac = hmac.new(secret.encode(), f"{ts}.{nonce}.".encode() + body,
                   hashlib.sha256).hexdigest()
    return f"t={ts},n={nonce},v1={mac}"


@pytest.fixture()
def enrolled(client, admin_token, db_session):
    """An enrolled agent, plus the one-time secret it was given."""
    db_session.query(SoarOrder).delete()
    db_session.query(EndpointAgent).delete()
    db_session.commit()

    response = client.post(
        "/api/agents/endpoints",
        json={"endpoint_id": ENDPOINT, "hostname": "smoketest-host",
              "platform": "linux", "label": "Lab Ubuntu"},
        headers=_auth(admin_token),
    )
    assert response.status_code == 201, response.text
    secret = response.json()["shared_secret"]
    yield secret
    db_session.query(SoarOrder).delete()
    db_session.query(EndpointAgent).delete()
    db_session.commit()


def _make_action(db, action_type=SoarActionType.BLOCK_IP, target="203.0.113.77"):
    action = SoarAction(
        action_type=action_type, target=target,
        status=SoarActionStatus.SIMULATED, detail="recorded by a test",
        execution_requested=False,
    )
    db.add(action)
    db.commit()
    db.refresh(action)
    return action


# ── AC-3 · only an administrator operates containment ───────────────
def test_enrolment_requires_an_administrator(client):
    assert client.post("/api/agents/endpoints",
                       json={"endpoint_id": "nope"}).status_code == 401


def test_secret_is_shown_once_and_never_returned_again(client, admin_token, enrolled):
    listing = client.get("/api/agents/endpoints", headers=_auth(admin_token))
    assert listing.status_code == 200
    body = json.dumps(listing.json())
    assert enrolled not in body, "the shared secret must never be readable back"


# ── IR-4(2) · the decision reaches the endpoint ─────────────────────
def test_execute_queues_an_order_the_agent_then_collects(client, admin_token,
                                                         db_session, enrolled):
    action = _make_action(db_session)

    issued = client.post(f"/api/soar/actions/{action.id}/execute",
                         headers=_auth(admin_token))
    assert issued.status_code == 200, issued.text
    assert issued.json()["executed"] is True

    # The action now says "queued", not "simulated".
    db_session.expire_all()
    refreshed = db_session.query(SoarAction).filter(SoarAction.id == action.id).first()
    assert refreshed.status is SoarActionStatus.PENDING

    # The agent polls — unauthenticated, but the response is signed.
    polled = client.get(f"/api/soar/agent/orders?endpoint={ENDPOINT}")
    assert polled.status_code == 200
    orders = polled.json()["orders"]
    assert len(orders) == 1
    assert orders[0]["action"] == "block_ip"
    assert orders[0]["target"] == "203.0.113.77"

    # SC-13: the agent verifies us before applying anything.
    header = polled.headers["x-aegisiq-signature"]
    parts = dict(kv.split("=", 1) for kv in header.split(","))
    expected = hmac.new(enrolled.encode(),
                        f"{parts['t']}.{parts['n']}.".encode() + polled.content,
                        hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expected, parts["v1"])

    # The agent applies it and reports back.
    result = {"endpoint_id": ENDPOINT, "order_id": orders[0]["id"],
              "success": True, "output": "iptables -I INPUT 1 -s 203.0.113.77 -j DROP"}
    raw = json.dumps(result).encode()
    reported = client.post("/api/soar/agent/result", content=raw,
                           headers={"Content-Type": "application/json",
                                    "X-AegisIQ-Signature": _sign(enrolled, raw)})
    assert reported.status_code == 200, reported.text
    assert reported.json()["order"]["status"] == "succeeded"

    db_session.expire_all()
    final = db_session.query(SoarAction).filter(SoarAction.id == action.id).first()
    assert final.status is SoarActionStatus.EXECUTED
    assert "203.0.113.77" in final.detail


def test_an_order_is_delivered_only_once(client, admin_token, db_session, enrolled):
    action = _make_action(db_session, target="203.0.113.78")
    client.post(f"/api/soar/actions/{action.id}/execute", headers=_auth(admin_token))

    first = client.get(f"/api/soar/agent/orders?endpoint={ENDPOINT}").json()["orders"]
    second = client.get(f"/api/soar/agent/orders?endpoint={ENDPOINT}").json()["orders"]
    assert len(first) == 1 and second == []


# ── SC-13 · forged and replayed results are refused ─────────────────
def test_result_with_a_wrong_signature_is_refused(client, admin_token,
                                                  db_session, enrolled):
    action = _make_action(db_session, target="203.0.113.79")
    client.post(f"/api/soar/actions/{action.id}/execute", headers=_auth(admin_token))
    order = client.get(f"/api/soar/agent/orders?endpoint={ENDPOINT}").json()["orders"][0]

    raw = json.dumps({"endpoint_id": ENDPOINT, "order_id": order["id"],
                      "success": True, "output": "pwned"}).encode()
    response = client.post("/api/soar/agent/result", content=raw,
                           headers={"Content-Type": "application/json",
                                    "X-AegisIQ-Signature": _sign("not-the-secret", raw)})
    assert response.status_code == 401


def test_a_replayed_result_is_refused(client, admin_token, db_session, enrolled):
    action = _make_action(db_session, target="203.0.113.80")
    client.post(f"/api/soar/actions/{action.id}/execute", headers=_auth(admin_token))
    order = client.get(f"/api/soar/agent/orders?endpoint={ENDPOINT}").json()["orders"][0]

    raw = json.dumps({"endpoint_id": ENDPOINT, "order_id": order["id"],
                      "success": True, "output": "applied"}).encode()
    signature = _sign(enrolled, raw)
    headers = {"Content-Type": "application/json", "X-AegisIQ-Signature": signature}
    assert client.post("/api/soar/agent/result", content=raw, headers=headers).status_code == 200
    # Same signature, same nonce → replay.
    assert client.post("/api/soar/agent/result", content=raw, headers=headers).status_code == 401


def test_polling_an_unknown_endpoint_leaks_nothing(client, enrolled):
    response = client.get("/api/soar/agent/orders?endpoint=does-not-exist")
    assert response.status_code == 200
    assert response.json() == {"orders": []}
    assert "x-aegisiq-signature" not in {k.lower() for k in response.headers}


# ── SI-4(7) · guard rails ───────────────────────────────────────────
@pytest.mark.parametrize("target,fragment", [
    ("127.0.0.1", "loopback"),
    ("169.254.1.5", "link-local"),
    ("not-an-ip", "not an IP"),
])
def test_dangerous_block_targets_are_refused(client, admin_token, db_session,
                                             enrolled, target, fragment):
    action = _make_action(db_session, target=target)
    response = client.post(f"/api/soar/actions/{action.id}/execute",
                           headers=_auth(admin_token))
    assert response.status_code == 409
    assert fragment in response.json()["detail"]

    db_session.expire_all()
    refreshed = db_session.query(SoarAction).filter(SoarAction.id == action.id).first()
    assert refreshed.status is SoarActionStatus.SIMULATED
    assert "NOT executed" in refreshed.detail


def test_protected_accounts_are_never_disabled(client, admin_token, db_session, enrolled):
    action = _make_action(db_session, action_type=SoarActionType.DISABLE_ACCOUNT,
                          target="root")
    response = client.post(f"/api/soar/actions/{action.id}/execute",
                           headers=_auth(admin_token))
    assert response.status_code == 409
    assert "protected account" in response.json()["detail"]


def test_execution_without_a_registered_agent_records_the_reason(client, admin_token,
                                                                 db_session):
    db_session.query(EndpointAgent).delete()
    db_session.commit()
    action = _make_action(db_session, target="203.0.113.81")
    response = client.post(f"/api/soar/actions/{action.id}/execute",
                           headers=_auth(admin_token))
    assert response.status_code == 409
    assert "no response agent registered" in response.json()["detail"]


# ── CM-3 · containment is reversible and audited ────────────────────
def test_an_applied_block_can_be_revoked(client, admin_token, db_session, enrolled):
    action = _make_action(db_session, target="203.0.113.82")
    client.post(f"/api/soar/actions/{action.id}/execute", headers=_auth(admin_token))
    order = client.get(f"/api/soar/agent/orders?endpoint={ENDPOINT}").json()["orders"][0]
    raw = json.dumps({"endpoint_id": ENDPOINT, "order_id": order["id"],
                      "success": True, "output": "blocked"}).encode()
    client.post("/api/soar/agent/result", content=raw,
                headers={"Content-Type": "application/json",
                         "X-AegisIQ-Signature": _sign(enrolled, raw)})

    revoked = client.post(f"/api/soar/orders/{order['id']}/revoke",
                          headers=_auth(admin_token))
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["action"] == "unblock_ip"
    assert revoked.json()["target"] == "203.0.113.82"

    # …and the agent collects the undo on its next poll.
    pending = client.get(f"/api/soar/agent/orders?endpoint={ENDPOINT}").json()["orders"]
    assert [o["action"] for o in pending] == ["unblock_ip"]


def test_orders_and_results_are_audited(client, admin_token, db_session, enrolled):
    action = _make_action(db_session, target="203.0.113.83")
    client.post(f"/api/soar/actions/{action.id}/execute", headers=_auth(admin_token))

    page = client.get("/api/audit?limit=200", headers=_auth(admin_token))
    actions = {row["action"] for row in page.json()["items"]}
    assert "response.agent.enrol" in actions
    assert "response.order.issued" in actions


def test_disabled_agent_receives_nothing(client, admin_token, db_session, enrolled):
    action = _make_action(db_session, target="203.0.113.84")
    client.post(f"/api/soar/actions/{action.id}/execute", headers=_auth(admin_token))
    client.patch(f"/api/agents/endpoints/{ENDPOINT}", json={"enabled": False},
                 headers=_auth(admin_token))

    assert client.get(f"/api/soar/agent/orders?endpoint={ENDPOINT}").json()["orders"] == []


def test_endpoint_listing_reports_liveness(client, admin_token, enrolled):
    body = client.get("/api/agents/endpoints", headers=_auth(admin_token)).json()
    row = body["items"][0]
    assert row["endpoint_id"] == ENDPOINT
    assert row["status"] == "never_seen"
    assert body["execution_enabled"] is False  # SOAR_EXECUTE off in tests

    client.get(f"/api/soar/agent/orders?endpoint={ENDPOINT}")
    row = client.get("/api/agents/endpoints", headers=_auth(admin_token)).json()["items"][0]
    assert row["status"] == "online"
