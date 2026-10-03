"""Error-path coverage, plus the guarantee that an uploaded email is never
written to disk on any code path, failures included.
"""

import io
import os

import pytest

import config
from database.db import init_db


class ImmediateThread:
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
def app_and_client(tmp_path, monkeypatch):
    """Returns (flask_app, client) with TESTING off, so unhandled
    exceptions actually go through app.py's 500 handler instead of
    propagating out of the test client; needed to test the no-leak
    guarantee for real."""
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test_hardening.db"))
    monkeypatch.setattr(config, "UPLOAD_DIR", str(tmp_path / "uploads"))
    init_db()
    monkeypatch.setattr("routes.scan.threading", _FakeThreadingModule())

    import app as app_module
    flask_app = app_module.create_app()
    flask_app.config["TESTING"] = False
    flask_app.config["PROPAGATE_EXCEPTIONS"] = False
    return flask_app, flask_app.test_client()


@pytest.fixture
def client(app_and_client):
    return app_and_client[1]


SAMPLE_EML = (
    b"From: sender@example.com\r\nTo: clerk@example.com\r\nSubject: Test\r\n"
    b"Date: Mon, 10 Aug 2026 00:00:00 +0000\r\nMessage-ID: <t@example.com>\r\n\r\n"
    b"Hello.\r\n"
)


# ---------------------------------------------------------------------
# Error-path coverage
# ---------------------------------------------------------------------


def test_oversized_upload_returns_413_with_envelope(client):
    oversized = b"x" * (config.MAX_UPLOAD_SIZE_BYTES + 1024)
    data = {"file": (io.BytesIO(oversized), "big.eml")}
    response = client.post("/api/scan", data=data, content_type="multipart/form-data")
    assert response.status_code == 413
    body = response.get_json()
    assert body["success"] is False
    assert body["error"]["code"] == "FILE_TOO_LARGE"


def test_unknown_route_returns_404_envelope_not_flask_html(client):
    response = client.get("/api/this-route-does-not-exist")
    assert response.status_code == 404
    assert response.content_type.startswith("application/json")
    body = response.get_json()
    assert body["success"] is False
    assert body["error"]["code"] == "NOT_FOUND"


def test_missing_file_field_returns_400(client):
    response = client.post("/api/scan", data={}, content_type="multipart/form-data")
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "NO_FILE"


def test_admin_login_with_no_json_body_does_not_500(client):
    response = client.post("/api/admin/login", data="not json", content_type="text/plain")
    assert response.status_code in (400, 401)
    assert response.get_json()["success"] is False


def test_500_handler_returns_envelope_without_stack_trace(app_and_client, monkeypatch):
    flask_app, client = app_and_client

    def _boom(scan_id):
        raise RuntimeError("simulated database outage")

    monkeypatch.setattr("routes.scan.models.get_scan", _boom)
    response = client.get("/api/scan/some-id")

    assert response.status_code == 500
    body = response.get_json()
    assert body["success"] is False
    assert body["error"]["code"] == "INTERNAL_ERROR"
    # Never leak a stack trace or the raw exception message to the client.
    assert "simulated database outage" not in response.get_data(as_text=True)
    assert "Traceback" not in response.get_data(as_text=True)


# ---------------------------------------------------------------------
# The upload is never written to disk, on any path
#
# The email used to be saved to backend/uploads/ and deleted in a finally
# block. With real-time antivirus that broke on exactly the files that
# mattered: the antivirus locked a file with a real malware signature, the
# read failed, then the delete failed and the file was left behind. Uploads
# now stay in memory, so these tests check that nothing is written at all.
# ---------------------------------------------------------------------


def assert_nothing_written_to_disk():
    """UPLOAD_DIR must not even be created, let alone hold a file."""
    if os.path.exists(config.UPLOAD_DIR):
        assert os.listdir(config.UPLOAD_DIR) == [], "an upload was written to disk"


def test_nothing_written_after_successful_scan(client, monkeypatch):
    monkeypatch.setattr(
        "routes.scan.run_pipeline",
        lambda parsed, scan_id=None: {
            "header_result": {"from_address": "a@b.com"},
            "url_results": [],
            "attachment_results": [],
            "verdict": {
                "risk_score": 0, "risk_level": "SAFE", "partial_scan": False,
                "unavailable_providers": [], "override_applied": None, "signals": [],
            },
        },
    )
    data = {"file": (io.BytesIO(SAMPLE_EML), "clean.eml")}
    client.post("/api/scan", data=data, content_type="multipart/form-data")
    assert_nothing_written_to_disk()


def test_nothing_written_when_parsing_fails(client):
    malformed = b"\x00\x01\x02 not an email \xff\xfe" * 5
    data = {"file": (io.BytesIO(malformed), "bad.eml")}
    response = client.post("/api/scan", data=data, content_type="multipart/form-data")
    scan_id = response.get_json()["data"]["scan_id"]

    status = client.get(f"/api/scan/{scan_id}/status").get_json()["data"]
    assert status["status"] == "FAILED"
    assert status["error_message"]
    assert_nothing_written_to_disk()


def test_nothing_written_when_pipeline_raises_unexpected_exception(client, monkeypatch):
    def _boom(parsed, scan_id=None):
        raise RuntimeError("simulated orchestrator crash")

    monkeypatch.setattr("routes.scan.run_pipeline", _boom)
    data = {"file": (io.BytesIO(SAMPLE_EML), "clean.eml")}
    response = client.post("/api/scan", data=data, content_type="multipart/form-data")
    scan_id = response.get_json()["data"]["scan_id"]

    status = client.get(f"/api/scan/{scan_id}/status").get_json()["data"]
    assert status["status"] == "FAILED"
    assert_nothing_written_to_disk()


def test_nothing_written_when_save_to_database_fails(client, monkeypatch):
    def _boom(**kwargs):
        raise RuntimeError("simulated write failure")

    monkeypatch.setattr(
        "routes.scan.run_pipeline",
        lambda parsed, scan_id=None: {
            "header_result": None, "url_results": [], "attachment_results": [],
            "verdict": {
                "risk_score": 0, "risk_level": "SAFE", "partial_scan": False,
                "unavailable_providers": [], "override_applied": None, "signals": [],
            },
        },
    )
    monkeypatch.setattr("routes.scan.models.save_full_scan_result", _boom)
    data = {"file": (io.BytesIO(SAMPLE_EML), "clean.eml")}
    response = client.post("/api/scan", data=data, content_type="multipart/form-data")
    scan_id = response.get_json()["data"]["scan_id"]

    status = client.get(f"/api/scan/{scan_id}/status").get_json()["data"]
    assert status["status"] == "FAILED"
    assert_nothing_written_to_disk()
