"""Regression tests for credential redaction in provider call logging.

Safe Browsing takes its API key as a ?key= query parameter, so the
request URL is itself a secret. It used to be written as-is into
api_call_logs.endpoint on every call, and a provider error message can
contain the key too. Both are redacted now, and these tests make sure it
stays that way.
"""

import pytest
import requests

from api_clients import safe_browsing
from api_clients._http import redact_secrets
from utils.exceptions import ProviderError

SECRET = "AIzaSyFAKEKEYFORTESTINGONLY0000000000000"


def test_redacts_key_query_parameter():
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SECRET}"
    result = redact_secrets(url)
    assert SECRET not in result
    assert result.endswith("key=REDACTED")
    # The endpoint has to stay readable, or the log is no use.
    assert "safebrowsing.googleapis.com/v4/threatMatches:find" in result


@pytest.mark.parametrize("param", ["key", "apikey", "api_key", "token", "access_token", "API_KEY"])
def test_redacts_every_known_credential_parameter(param):
    assert SECRET not in redact_secrets(f"https://example.com/a?{param}={SECRET}")


def test_redacts_key_embedded_in_free_text():
    """requests' exception messages wrap the URL in a longer sentence, so
    the scrubber must work on text that is not parseable as a URL."""
    message = (
        "HTTPSConnectionPool(host='safebrowsing.googleapis.com', port=443): "
        f"Max retries exceeded with url: /v4/threatMatches:find?key={SECRET} "
        "(Caused by NewConnectionError('failed to establish a new connection'))"
    )
    result = redact_secrets(message)
    assert SECRET not in result
    assert "Max retries exceeded" in result


def test_leaves_non_secret_parameters_alone():
    url = "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90"
    assert redact_secrets(url) == url


def test_handles_empty_and_none_safely():
    assert redact_secrets("") == ""
    assert redact_secrets(None) is None


def test_safe_browsing_call_never_logs_the_key(mocker, monkeypatch):
    """End-to-end through the real client: whatever reaches log_api_call
    must not contain the configured key."""
    monkeypatch.setattr("config.SAFE_BROWSING_API_KEY", SECRET)
    logged = mocker.patch("api_clients._http.log_api_call")
    mocker.patch("api_clients._http.time.sleep")

    class FakeResponse:
        status_code = 200
        ok = True
        content = b"{}"

        def json(self):
            return {}

    mocker.patch("requests.request", return_value=FakeResponse())
    safe_browsing.check_urls(["https://example.com"])

    assert logged.called
    for call in logged.call_args_list:
        assert SECRET not in str(call), "API key leaked into api_call_logs"


def test_connection_error_message_is_redacted_before_logging(mocker, monkeypatch):
    monkeypatch.setattr("config.SAFE_BROWSING_API_KEY", SECRET)
    logged = mocker.patch("api_clients._http.log_api_call")
    mocker.patch(
        "requests.request",
        side_effect=requests.ConnectionError(
            f"Max retries exceeded with url: /v4/threatMatches:find?key={SECRET}"
        ),
    )

    with pytest.raises(ProviderError) as exc_info:
        safe_browsing.check_urls(["https://example.com"])

    # Neither the stored log nor the raised exception may carry the key.
    assert SECRET not in str(exc_info.value)
    for call in logged.call_args_list:
        assert SECRET not in str(call)
