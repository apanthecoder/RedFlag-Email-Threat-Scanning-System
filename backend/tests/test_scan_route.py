"""Tests the /api/scan routes with a real Flask test client and a real
temporary SQLite database. The pipeline is mocked so no live provider is
called. The client and orchestrator tests cover those parts.
"""

import io
import os

import pytest

import config
from database.db import init_db


class ImmediateThread:
    """Stand-in for threading.Thread that runs synchronously, so the test
    doesn't need to sleep/poll waiting for a background thread to finish."""

    def __init__(self, target, args=(), kwargs=None, daemon=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        self._target(*self._args, **self._kwargs)


class _FakeThreadingModule:
    """Swaps in for routes.scan's `threading` name only; NOT the real
    global `threading` module, which `monkeypatch.setattr("routes.scan.threading.Thread", ...)`
    would otherwise mutate (import just binds a reference, not a copy)."""

    Thread = ImmediateThread


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test_redflag.db"))
    monkeypatch.setattr(config, "UPLOAD_DIR", str(tmp_path / "uploads"))
    init_db()

    monkeypatch.setattr("routes.scan.threading", _FakeThreadingModule())
    monkeypatch.setattr(
        "routes.scan.run_pipeline",
        lambda parsed, scan_id=None: {
            "header_result": {"from_address": "sender@example.com", "spf_result": "PASS"},
            "url_results": [],
            "attachment_results": [],
            "verdict": {
                "risk_score": 5,
                "risk_level": "SAFE",
                "partial_scan": False,
                "unavailable_providers": [],
                "override_applied": None,
                "signals": [],
            },
        },
    )

    import app as app_module
    flask_app = app_module.create_app()
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


SAMPLE_EML = (
    b"From: sender@example.com\r\n"
    b"To: clerk@example.com\r\n"
    b"Subject: Test email\r\n"
    b"Date: Mon, 10 Aug 2026 00:00:00 +0000\r\n"
    b"Message-ID: <test@example.com>\r\n"
    b"\r\n"
    b"Hello, this is a test.\r\n"
)


def _upload(client):
    data = {"file": (io.BytesIO(SAMPLE_EML), "test.eml")}
    return client.post("/api/scan", data=data, content_type="multipart/form-data")


def test_upload_returns_202_and_scan_id_and_sets_cookie(client):
    response = _upload(client)
    assert response.status_code == 202
    body = response.get_json()
    assert body["success"] is True
    assert "scan_id" in body["data"]
    assert "rf_session" in response.headers.get("Set-Cookie", "")


def test_scan_completes_and_report_is_fetchable(client):
    response = _upload(client)
    scan_id = response.get_json()["data"]["scan_id"]

    report = client.get(f"/api/scan/{scan_id}")
    assert report.status_code == 200
    body = report.get_json()
    assert body["data"]["scan"]["status"] == "COMPLETE"
    assert body["data"]["scan"]["risk_level"] == "SAFE"
    assert body["data"]["header_result"]["from_address"] == "sender@example.com"


def test_scan_status_endpoint(client):
    response = _upload(client)
    scan_id = response.get_json()["data"]["scan_id"]

    status = client.get(f"/api/scan/{scan_id}/status")
    assert status.status_code == 200
    assert status.get_json()["data"]["status"] == "COMPLETE"


def test_unknown_scan_id_returns_404(client):
    response = client.get("/api/scan/does-not-exist")
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "NOT_FOUND"


def test_wrong_file_type_returns_400(client):
    data = {"file": (io.BytesIO(b"not an email"), "invoice.pdf")}
    response = client.post("/api/scan", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "INVALID_FILE_TYPE"


def test_history_reflects_uploaded_scan(client):
    _upload(client)  # sets the session cookie on the client's cookie jar
    history = client.get("/api/history")
    assert history.status_code == 200
    scans = history.get_json()["data"]
    assert len(scans) == 1
    assert scans[0]["status"] == "COMPLETE"


def test_upload_is_never_written_to_disk(client):
    """The email is held in memory for the whole scan, so UPLOAD_DIR is
    never even created."""
    _upload(client)
    if os.path.exists(config.UPLOAD_DIR):
        assert os.listdir(config.UPLOAD_DIR) == []
