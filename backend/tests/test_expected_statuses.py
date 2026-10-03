"""Regression tests for expected-status handling in provider call logging.

Two endpoints use 404 as a normal answer:

  * URLScan's result endpoint returns 404 while a scan is still running.
  * VirusTotal's file lookup returns 404 for a hash it has never seen,
    which means the file should be uploaded.

Both used to be logged as failed calls, which made the admin reliability
figures far too low. A URLScan scan that needed four polls logged three
failures and one success. A real fault (401, 500) must still be logged as
a failure.
"""

import json

import pytest

from api_clients import urlscan, virustotal
from utils.exceptions import ProviderError


class FakeResponse:
    def __init__(self, status_code, json_body=None):
        self.status_code = status_code
        self.ok = 200 <= status_code < 400
        self._json_body = json_body
        self.content = b"{}" if json_body is None else json.dumps(json_body).encode()

    def json(self):
        return self._json_body if self._json_body is not None else {}


@pytest.fixture(autouse=True)
def no_sleep(mocker):
    mocker.patch("api_clients._http.time.sleep")
    mocker.patch("api_clients.urlscan.time.sleep")


def logged_success_flags(mock_log):
    """(status_code, success) for every logged call, in order."""
    return [
        (call.kwargs.get("status_code"), call.args[1])
        for call in mock_log.call_args_list
    ]


# ---------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------


def test_virustotal_unknown_hash_404_is_logged_as_success(mocker):
    logged = mocker.patch("api_clients._http.log_api_call")
    mocker.patch("requests.request", return_value=FakeResponse(404))

    assert virustotal.get_file_report("a" * 64) is None
    assert logged_success_flags(logged) == [(404, True)]


def test_virustotal_401_is_still_logged_as_failure(mocker):
    logged = mocker.patch("api_clients._http.log_api_call")
    mocker.patch("requests.request", return_value=FakeResponse(401))

    with pytest.raises(ProviderError):
        virustotal.get_file_report("a" * 64)
    assert logged_success_flags(logged) == [(401, False)]


def test_virustotal_upload_404_is_not_treated_as_expected(mocker):
    """Only the hash lookup declares 404 as expected. A 404 on upload is a
    real fault and must still be logged as one."""
    logged = mocker.patch("api_clients._http.log_api_call")
    mocker.patch("requests.request", return_value=FakeResponse(404))

    with pytest.raises(ProviderError):
        virustotal.upload_file(b"bytes", "f.bin")
    assert logged_success_flags(logged) == [(404, False)]


# ---------------------------------------------------------------------
# URLScan
# ---------------------------------------------------------------------


def test_urlscan_not_ready_404_polls_are_logged_as_success(mocker):
    logged = mocker.patch("api_clients._http.log_api_call")
    mocker.patch(
        "requests.request",
        side_effect=[
            FakeResponse(200, {"uuid": "u1"}),                      # submit
            FakeResponse(404),                                       # not ready
            FakeResponse(404),                                       # not ready
            FakeResponse(200, {"verdicts": {"overall": {"malicious": False, "score": 0}}, "task": {}}),
        ],
    )

    result = urlscan.scan_url("https://example.com")
    assert result["malicious"] is False

    flags = logged_success_flags(logged)
    assert flags == [(200, True), (404, True), (404, True), (200, True)]
    # The whole scan worked, so nothing should count against reliability.
    assert all(success for _, success in flags)


def test_urlscan_submit_401_is_still_a_failure(mocker):
    logged = mocker.patch("api_clients._http.log_api_call")
    mocker.patch("requests.request", return_value=FakeResponse(401))

    with pytest.raises(ProviderError):
        urlscan.scan_url("https://example.com")
    assert logged_success_flags(logged) == [(401, False)]


def test_urlscan_server_error_on_result_is_still_a_failure(mocker):
    logged = mocker.patch("api_clients._http.log_api_call")
    mocker.patch(
        "requests.request",
        side_effect=[FakeResponse(200, {"uuid": "u1"})] + [FakeResponse(500)] * 6,
    )

    with pytest.raises(ProviderError):
        urlscan.scan_url("https://example.com")

    flags = logged_success_flags(logged)
    assert flags[0] == (200, True)
    assert any(status == 500 and not ok for status, ok in flags)


# ---------------------------------------------------------------------
# Providers that declare nothing keep the old strict behaviour
# ---------------------------------------------------------------------


def test_provider_without_expected_statuses_treats_404_as_failure(mocker):
    from api_clients import abuseipdb

    logged = mocker.patch("api_clients._http.log_api_call")
    mocker.patch("requests.request", return_value=FakeResponse(404))

    with pytest.raises(ProviderError):
        abuseipdb.check_ip("8.8.8.8")
    assert logged_success_flags(logged) == [(404, False)]
