"""Mocked tests for every provider client. No network access, so nothing
here uses up live quota. requests.request, log_api_call and time.sleep are
all patched out.
"""

from __future__ import annotations

import json as jsonlib

import pytest
import requests

from api_clients import abuseipdb, safe_browsing, urlscan, virustotal
from utils.exceptions import ProviderError, ProviderTimeout


class FakeResponse:
    def __init__(self, status_code: int, json_body=None, content: bytes = b"{}"):
        self.status_code = status_code
        self.ok = 200 <= status_code < 400
        self._json_body = json_body
        self.content = content if json_body is None else jsonlib.dumps(json_body).encode()

    def json(self):
        if self._json_body is None:
            raise ValueError("no json body")
        return self._json_body


@pytest.fixture(autouse=True)
def no_db_logging(mocker):
    """Every client call logs to api_call_logs; stub it out so tests never
    touch the real database."""
    return mocker.patch("api_clients._http.log_api_call")


@pytest.fixture(autouse=True)
def no_sleep(mocker):
    """Retry backoff and URLScan's polling both call time.sleep; make
    tests instant."""
    mocker.patch("api_clients._http.time.sleep")
    mocker.patch("api_clients.urlscan.time.sleep")


# ---------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------


def test_virustotal_known_hash_returns_parsed_stats(mocker):
    mocker.patch(
        "requests.request",
        return_value=FakeResponse(200, {
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 18, "suspicious": 2, "undetected": 52, "harmless": 0},
                "popular_threat_classification": {"suggested_threat_label": "trojan.generic"},
            }}
        }),
    )
    result = virustotal.get_file_report("a" * 64)
    assert result["malicious"] == 18
    assert result["threat_label"] == "trojan.generic"


def test_virustotal_unknown_hash_returns_none():
    import unittest.mock as mock
    with mock.patch("requests.request", return_value=FakeResponse(404)):
        assert virustotal.get_file_report("a" * 64) is None


def test_virustotal_bad_key_raises_provider_error(mocker):
    mocker.patch("requests.request", return_value=FakeResponse(401))
    with pytest.raises(ProviderError):
        virustotal.get_file_report("a" * 64)


def test_virustotal_upload_returns_analysis_id(mocker):
    mocker.patch(
        "requests.request",
        return_value=FakeResponse(200, {"data": {"id": "analysis-123", "type": "analysis"}}),
    )
    analysis_id = virustotal.upload_file(b"fake-bytes", "invoice.exe")
    assert analysis_id == "analysis-123"


def test_virustotal_analysis_completed(mocker):
    mocker.patch(
        "requests.request",
        return_value=FakeResponse(200, {
            "data": {"attributes": {"status": "completed", "stats": {"malicious": 5, "suspicious": 0, "undetected": 60, "harmless": 0}}}
        }),
    )
    result = virustotal.get_analysis("analysis-123")
    assert result["status"] == "completed"
    assert result["malicious"] == 5


def test_virustotal_analysis_queued(mocker):
    mocker.patch(
        "requests.request",
        return_value=FakeResponse(200, {"data": {"attributes": {"status": "queued"}}}),
    )
    result = virustotal.get_analysis("analysis-123")
    assert result["status"] == "queued"
    assert "malicious" not in result


# ---------------------------------------------------------------------
# Safe Browsing
# ---------------------------------------------------------------------


def test_safe_browsing_empty_body_means_clean(mocker):
    mocker.patch("requests.request", return_value=FakeResponse(200, content=b""))
    result = safe_browsing.check_urls(["https://example.com"])
    assert result == {}


def test_safe_browsing_matches_are_parsed(mocker):
    mocker.patch(
        "requests.request",
        return_value=FakeResponse(200, {
            "matches": [
                {"threat": {"url": "http://evil.example"}, "threatType": "SOCIAL_ENGINEERING"},
            ]
        }),
    )
    result = safe_browsing.check_urls(["http://evil.example"])
    assert result == {"http://evil.example": ["SOCIAL_ENGINEERING"]}


def test_safe_browsing_no_urls_short_circuits(mocker):
    mock_request = mocker.patch("requests.request")
    result = safe_browsing.check_urls([])
    assert result == {}
    mock_request.assert_not_called()


def test_safe_browsing_bad_request_raises(mocker):
    mocker.patch("requests.request", return_value=FakeResponse(400))
    with pytest.raises(ProviderError):
        safe_browsing.check_urls(["https://example.com"])


# ---------------------------------------------------------------------
# URLScan
# ---------------------------------------------------------------------


def test_urlscan_submit_then_immediate_result(mocker):
    responses = [
        FakeResponse(200, {"uuid": "scan-uuid-1"}),  # submit
        FakeResponse(200, {  # first poll: ready
            "verdicts": {"overall": {"malicious": True, "score": 90}},
            "task": {"screenshotURL": "https://urlscan.io/screenshots/scan-uuid-1.png"},
        }),
    ]
    mocker.patch("requests.request", side_effect=responses)
    result = urlscan.scan_url("http://suspicious.example")
    assert result["malicious"] is True
    assert result["score"] == 90


def test_urlscan_polls_past_initial_404(mocker):
    responses = [
        FakeResponse(200, {"uuid": "scan-uuid-2"}),  # submit
        FakeResponse(404),  # not ready yet
        FakeResponse(404),  # still not ready
        FakeResponse(200, {"verdicts": {"overall": {"malicious": False, "score": 0}}, "task": {}}),
    ]
    mocker.patch("requests.request", side_effect=responses)
    result = urlscan.scan_url("http://slow-to-scan.example")
    assert result["malicious"] is False


def test_urlscan_gives_up_after_poll_budget(mocker, monkeypatch):
    monkeypatch.setattr("config.URLSCAN_MAX_POLL_ATTEMPTS", 2)
    responses = [FakeResponse(200, {"uuid": "scan-uuid-3"})] + [FakeResponse(404)] * 5
    mocker.patch("requests.request", side_effect=responses)
    with pytest.raises(ProviderTimeout):
        urlscan.scan_url("http://never-finishes.example")


# ---------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------


def test_abuseipdb_parses_confidence_score(mocker):
    mocker.patch(
        "requests.request",
        return_value=FakeResponse(200, {
            "data": {
                "abuseConfidenceScore": 92,
                "totalReports": 47,
                "countryCode": "RU",
                "isWhitelisted": False,
            }
        }),
    )
    result = abuseipdb.check_ip("198.51.100.7")
    assert result["confidence_score"] == 92
    assert result["total_reports"] == 47
    assert result["country_code"] == "RU"


def test_abuseipdb_bad_key_raises(mocker):
    mocker.patch("requests.request", return_value=FakeResponse(401))
    with pytest.raises(ProviderError):
        abuseipdb.check_ip("198.51.100.7")


# ---------------------------------------------------------------------
# Shared retry behaviour (exercised via AbuseIPDB, but generic to _http.py)
# ---------------------------------------------------------------------


def test_retries_on_500_then_succeeds(mocker):
    responses = [FakeResponse(500), FakeResponse(200, {"data": {"abuseConfidenceScore": 10, "totalReports": 1, "countryCode": "MY", "isWhitelisted": False}})]
    mock_request = mocker.patch("requests.request", side_effect=responses)
    result = abuseipdb.check_ip("198.51.100.7")
    assert result["confidence_score"] == 10
    assert mock_request.call_count == 2


def test_gives_up_after_max_retries_on_persistent_500(mocker):
    mocker.patch("requests.request", return_value=FakeResponse(500))
    with pytest.raises(ProviderError):
        abuseipdb.check_ip("198.51.100.7")


def test_does_not_retry_on_404(mocker):
    mock_request = mocker.patch("requests.request", return_value=FakeResponse(404))
    assert virustotal.get_file_report("a" * 64) is None
    assert mock_request.call_count == 1


def test_timeout_raises_provider_timeout_after_retries(mocker):
    mocker.patch("requests.request", side_effect=requests.Timeout("timed out"))
    with pytest.raises(ProviderTimeout):
        abuseipdb.check_ip("198.51.100.7")
