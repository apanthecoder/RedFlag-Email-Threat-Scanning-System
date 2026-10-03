"""End-to-end tests for the admin routes: login, logout, me,
analytics, and rate limiting. Each test uses its own X-Forwarded-For
value so they don't share the module-level rate limiter's counters.
"""

import bcrypt
import pytest

import config
from database import models
from database.db import init_db

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "correct horse battery staple"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test_admin.db"))
    monkeypatch.setattr(config, "UPLOAD_DIR", str(tmp_path / "uploads"))
    init_db()

    password_hash = bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt()).decode()
    models.create_admin_user(ADMIN_USERNAME, password_hash)

    import app as app_module
    flask_app = app_module.create_app()
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


def _ip_headers(ip: str) -> dict:
    return {"X-Forwarded-For": ip}


def test_me_without_login_returns_401(client):
    response = client.get("/api/admin/me", headers=_ip_headers("10.0.0.1"))
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "UNAUTHENTICATED"


def test_login_with_correct_credentials_succeeds(client):
    response = client.post(
        "/api/admin/login",
        json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        headers=_ip_headers("10.0.0.2"),
    )
    assert response.status_code == 200
    assert response.get_json()["data"]["username"] == ADMIN_USERNAME

    me = client.get("/api/admin/me", headers=_ip_headers("10.0.0.2"))
    assert me.status_code == 200
    assert me.get_json()["data"]["username"] == ADMIN_USERNAME


def test_login_with_wrong_password_returns_401(client):
    response = client.post(
        "/api/admin/login",
        json={"username": ADMIN_USERNAME, "password": "wrong"},
        headers=_ip_headers("10.0.0.3"),
    )
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_login_with_unknown_username_returns_401_not_404(client):
    response = client.post(
        "/api/admin/login",
        json={"username": "nobody", "password": "whatever"},
        headers=_ip_headers("10.0.0.4"),
    )
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_logout_clears_session(client):
    ip = _ip_headers("10.0.0.5")
    client.post("/api/admin/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}, headers=ip)
    assert client.get("/api/admin/me", headers=ip).status_code == 200

    logout = client.post("/api/admin/logout", headers=ip)
    assert logout.status_code == 200

    assert client.get("/api/admin/me", headers=ip).status_code == 401


def test_removed_logs_endpoint_is_gone(client):
    """The system logs view was removed: nothing ever wrote to the table,
    so the panel could only ever be empty. The route must be gone rather
    than returning an empty list that looks like working functionality."""
    ip = _ip_headers("10.0.0.7")
    client.post("/api/admin/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}, headers=ip)
    assert client.get("/api/admin/logs", headers=ip).status_code == 404


def test_analytics_endpoint_requires_admin(client):
    response = client.get("/api/admin/analytics", headers=_ip_headers("10.0.0.9"))
    assert response.status_code == 401


def test_analytics_endpoint_shape_when_authenticated(client):
    ip = _ip_headers("10.0.0.10")
    client.post("/api/admin/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}, headers=ip)
    response = client.get("/api/admin/analytics", headers=ip)
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert "provider_calls" in data
    assert "scan_stats" in data
    assert "total_scans" in data["scan_stats"]


def test_login_is_rate_limited_after_five_attempts(client):
    ip = _ip_headers("10.0.0.11")
    for _ in range(5):
        response = client.post(
            "/api/admin/login", json={"username": ADMIN_USERNAME, "password": "wrong"}, headers=ip
        )
        assert response.status_code == 401

    sixth = client.post(
        "/api/admin/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}, headers=ip
    )
    assert sixth.status_code == 429
    assert sixth.get_json()["error"]["code"] == "RATE_LIMITED"


def test_rate_limit_is_scoped_per_ip(client):
    blocked_ip = _ip_headers("10.0.0.12")
    for _ in range(5):
        client.post("/api/admin/login", json={"username": ADMIN_USERNAME, "password": "wrong"}, headers=blocked_ip)
    assert client.post(
        "/api/admin/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}, headers=blocked_ip
    ).status_code == 429

    other_ip = _ip_headers("10.0.0.13")
    response = client.post(
        "/api/admin/login", json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}, headers=other_ip
    )
    assert response.status_code == 200
