import os


def test_login_with_correct_credentials_returns_token(client):
    response = client.post(
        "/api/auth/login",
        json={
            "username": os.environ["DEFAULT_ADMIN_USERNAME"],
            "password": os.environ["DEFAULT_ADMIN_PASSWORD"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["role"] == "administrator"
    assert body["token_type"] == "bearer"
    assert len(body["access_token"]) > 0


def test_login_with_wrong_password_is_rejected(client):
    response = client.post(
        "/api/auth/login",
        json={"username": os.environ["DEFAULT_ADMIN_USERNAME"], "password": "wrong-password"},
    )
    assert response.status_code == 401


def test_login_with_unknown_username_is_rejected(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "nobody", "password": "irrelevant"},
    )
    assert response.status_code == 401


def test_dashboard_stats_requires_authentication(client):
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 401


def test_dashboard_stats_returns_real_zero_counts_on_empty_db(client, admin_token):
    response = client.get(
        "/api/dashboard/stats",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total_events"] == 0
    assert body["active_alerts"] == 0
    # Undefined until real alerts exist -- not faked as 0.
    assert body["detection_rate"] is None


def test_agent_registration_requires_administrator_role(client, admin_token):
    response = client.post(
        "/api/agents",
        json={"hostname": "ubuntu-server-01", "operating_system": "Ubuntu 22.04", "ip_address": "192.168.1.10"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["hostname"] == "ubuntu-server-01"
    assert body["status"] == "offline"

    # Listing should now include it, and should work for any authenticated user
    list_response = client.get("/api/agents", headers={"Authorization": f"Bearer {admin_token}"})
    assert list_response.status_code == 200
    assert len(list_response.json()) == 1
