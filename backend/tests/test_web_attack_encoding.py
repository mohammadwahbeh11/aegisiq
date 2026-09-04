"""Regression: the web_attack rule must catch URL-ENCODED payloads, not
just plaintext ones. A real HTTP request percent-encodes spaces, so an
encoded UNION SELECT is the common attack form -- missing it is an
evasion, which this locks shut."""
import os

import pytest


def _token(client):
    for _ in range(6):
        r = client.post("/api/auth/login", json={
            "username": os.environ["DEFAULT_ADMIN_USERNAME"],
            "password": os.environ["DEFAULT_ADMIN_PASSWORD"]})
        if r.status_code == 200:
            return r.json()["access_token"]
    raise AssertionError("login failed")


def _ingest(client, token, raw, ip):
    return client.post("/api/logs", headers={"Authorization": f"Bearer {token}"},
                       json={"raw_log": raw, "hostname": "t", "source": "test"})


@pytest.mark.parametrize("label,payload,ip", [
    ("plaintext", "/p?id=1 UNION SELECT a,b FROM users", "203.0.113.31"),
    ("url-encoded", "/p?id=1%20UNION%20SELECT%20a%2Cb%20FROM%20users", "203.0.113.32"),
    ("double-encoded", "/p?id=1%2520UNION%2520SELECT%2520a", "203.0.113.33"),
])
def test_sqli_detected_in_every_encoding(client, label, payload, ip):
    token = _token(client)
    raw = f'{ip} - - [10/Oct/2026:14:00:00 +0000] "GET {payload} HTTP/1.1" 200 5 "-" "curl/8"'
    r = _ingest(client, token, raw, ip)
    assert r.status_code in (200, 201), r.text
    assert r.json().get("alerts_generated", 0) >= 1, f"{label} SQLi did not raise a web_attack alert"
