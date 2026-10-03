"""Runs every sample in docs/test-samples/ through the real Flask route,
parser, orchestrator, risk engine and advisory module. Only outgoing HTTP
is mocked, so everything else runs for real without using any live
provider quota.
"""

import io
import json
import os

import pytest

import config
from database.db import init_db

SAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "docs", "test-samples",
)

ALL_SAMPLES = sorted(f for f in os.listdir(SAMPLES_DIR) if f.endswith(".eml"))


class ImmediateThread:
    def __init__(self, target, args=(), kwargs=None, daemon=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        self._target(*self._args, **self._kwargs)


class _FakeThreadingModule:
    """Swaps in for routes.scan's `threading` name only; NOT the real
    global `threading` module. `monkeypatch.setattr("routes.scan.threading.Thread", ...)`
    would mutate the actual stdlib module (import just binds a reference,
    not a copy), which breaks orchestrator.run_pipeline's real
    ThreadPoolExecutor when it's genuinely exercised, as it is here."""

    Thread = ImmediateThread


class FakeResponse:
    def __init__(self, status_code: int, json_body=None):
        self.status_code = status_code
        self.ok = 200 <= status_code < 400
        self._json_body = json_body
        self.content = b"{}" if json_body is None else json.dumps(json_body).encode()

    def json(self):
        return self._json_body if self._json_body is not None else {}


def _fake_provider_response(method, url, **kwargs):
    """Every provider comes back clean/harmless; this test is about
    pipeline correctness end-to-end, not about scoring particular
    verdicts (that's risk_scoring's and advisory's own test suites)."""
    if "virustotal.com/api/v3/files/" in url and method == "GET":
        return FakeResponse(404)  # unknown hash -> triggers upload path once
    if "virustotal.com/api/v3/files" in url and method == "POST":
        return FakeResponse(200, {"data": {"id": "analysis-1"}})
    if "virustotal.com/api/v3/analyses/" in url:
        return FakeResponse(200, {"data": {"attributes": {
            "status": "completed",
            "stats": {"malicious": 0, "suspicious": 0, "undetected": 70, "harmless": 2},
        }}})
    if "safebrowsing.googleapis.com" in url:
        return FakeResponse(200, {})  # empty body = clean
    if "urlscan.io/api/v1/scan/" in url:
        return FakeResponse(200, {"uuid": "scan-uuid"})
    if "urlscan.io/api/v1/result/" in url:
        return FakeResponse(200, {"verdicts": {"overall": {"malicious": False, "score": 0}}, "task": {}})
    if "abuseipdb.com" in url:
        return FakeResponse(200, {"data": {
            "abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "MY", "isWhitelisted": False,
        }})
    raise AssertionError(f"Unexpected outbound call in end-to-end test: {method} {url}")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test_e2e.db"))
    monkeypatch.setattr(config, "UPLOAD_DIR", str(tmp_path / "uploads"))
    init_db()

    monkeypatch.setattr("routes.scan.threading", _FakeThreadingModule())
    monkeypatch.setattr(
        "requests.request",
        lambda method, url, **kwargs: _fake_provider_response(method, url, **kwargs),
    )
    # Keep the (mocked-network) run fast: no real polling delays.
    monkeypatch.setattr("api_clients._http.time.sleep", lambda *_: None)
    monkeypatch.setattr("api_clients.urlscan.time.sleep", lambda *_: None)
    monkeypatch.setattr("services.attachment_analysis.time.sleep", lambda *_: None)

    import app as app_module
    flask_app = app_module.create_app()
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


def test_every_sample_file_is_present():
    # 18 plain .eml fixtures; the EICAR sample is base64-wrapped (.b64) and
    # is exercised by scripts/materialise_eicar.py instead.
    assert len(ALL_SAMPLES) == 18, f"expected 18 samples, found {ALL_SAMPLES}"


@pytest.mark.parametrize("filename", ALL_SAMPLES)
def test_sample_scans_without_crashing(client, filename):
    path = os.path.join(SAMPLES_DIR, filename)
    with open(path, "rb") as f:
        content = f.read()

    data = {"file": (io.BytesIO(content), filename)}
    upload = client.post("/api/scan", data=data, content_type="multipart/form-data")
    assert upload.status_code == 202
    scan_id = upload.get_json()["data"]["scan_id"]

    status = client.get(f"/api/scan/{scan_id}/status").get_json()["data"]
    assert status["status"] in ("COMPLETE", "FAILED")

    # The malformed sample should fail to parse. Every other sample has to
    # reach a full report.
    if filename == "18_malformed.eml":
        assert status["status"] == "FAILED"
        assert status["error_message"]
    else:
        assert status["status"] == "COMPLETE", f"{filename} failed: {status.get('error_message')}"

        report = client.get(f"/api/scan/{scan_id}").get_json()["data"]
        assert report["scan"]["risk_level"] in ("SAFE", "SUSPICIOUS", "DANGEROUS")
        assert isinstance(report["scan"]["risk_score"], int)
        assert 0 <= report["scan"]["risk_score"] <= 100
        # Every completed scan gets at least one advisory step (SAFE included).
        assert len(report["advisory"]) >= 1

    # The upload is never written to disk at all, success or failure.
    if os.path.exists(config.UPLOAD_DIR):
        assert os.listdir(config.UPLOAD_DIR) == []


def test_dangerous_sample_actually_scores_dangerous_with_a_working_safe_browsing(client, monkeypatch):
    """Sanity check that the mocked-clean baseline above isn't hiding a
    broken scoring path: force Safe Browsing to flag the display-mismatch
    sample's URL as malicious and confirm the override actually fires
    end-to-end, through real HTTP-shaped JSON this time."""

    def _malicious_safe_browsing(method, url, **kwargs):
        if "safebrowsing.googleapis.com" in url:
            payload = kwargs.get("json", {})
            entries = payload.get("threatInfo", {}).get("threatEntries", [])
            return FakeResponse(200, {
                "matches": [
                    {"threat": {"url": entries[0]["url"]}, "threatType": "SOCIAL_ENGINEERING"}
                ] if entries else []
            })
        return _fake_provider_response(method, url, **kwargs)

    monkeypatch.setattr("requests.request", _malicious_safe_browsing)

    path = os.path.join(SAMPLES_DIR, "07_link_display_mismatch.eml")
    with open(path, "rb") as f:
        content = f.read()

    data = {"file": (io.BytesIO(content), "07_link_display_mismatch.eml")}
    upload = client.post("/api/scan", data=data, content_type="multipart/form-data")
    scan_id = upload.get_json()["data"]["scan_id"]

    status = client.get(f"/api/scan/{scan_id}/status").get_json()["data"]
    assert status["status"] == "COMPLETE"

    report = client.get(f"/api/scan/{scan_id}").get_json()["data"]
    assert report["scan"]["risk_level"] == "DANGEROUS"
    assert report["scan"]["override_applied"] == "SAFE_BROWSING_MALICIOUS_THRESHOLD"

    triggers = [step["triggered_by"] for step in report["advisory"]]
    assert "MALICIOUS_URL" in triggers
    assert "DANGEROUS_VERDICT" in triggers
