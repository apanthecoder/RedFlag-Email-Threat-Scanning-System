"""HTTP code shared by the provider clients: explicit timeouts, retries
with exponential backoff (at most 2), and a log row for every attempt.

The clients (virustotal.py, safe_browsing.py, urlscan.py, abuseipdb.py)
call call_provider and read the response themselves. This module doesn't
know any provider's JSON format.
"""

from __future__ import annotations

import re
import time
from typing import Any

import requests

from database.models import log_api_call
from utils.exceptions import ProviderError, ProviderTimeout
from utils.logger import get_logger

logger = get_logger(__name__)

_RETRYABLE_STATUSES = {429, 500, 502, 503, 504}
_MAX_RETRIES = 2

# Query parameters that carry a credential. Safe Browsing puts its key in
# ?key=..., so the request URL is itself a secret and must never be stored
# or logged as it is.
#
# This is a regex instead of urlsplit because it has to clean plain text
# too: requests puts the full URL in the middle of its error messages.
_SECRET_PARAM_RE = re.compile(
    r"(?i)\b(key|apikey|api_key|token|access_token)=[^&\s'\"<>)\]]+"
)


def redact_secrets(text: str) -> str:
    """Replace credential query parameters with REDACTED.

    Works on a bare URL or on any text that contains one. Everything else
    is kept, so the log still shows which endpoint failed and why.
    """
    if not text:
        return text
    return _SECRET_PARAM_RE.sub(r"\1=REDACTED", text)


def _safe_json(response: requests.Response) -> Any:
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def call_provider(
    provider: str,
    method: str,
    url: str,
    *,
    timeout: float,
    scan_id: str | None = None,
    max_retries: int = _MAX_RETRIES,
    expected_statuses: frozenset[int] | set[int] = frozenset(),
    **kwargs: Any,
) -> requests.Response:
    """Make one provider call, retrying short-lived failures.

    Timeouts, 429s and 5xx responses are retried with exponential backoff,
    up to max_retries times. Other 4xx responses aren't: a 401 means the
    key is wrong and asking again won't help. Every attempt is written to
    api_call_logs.

    expected_statuses lists non-2xx codes that are a normal answer from
    this endpoint, so they're logged as successes. Two endpoints need it,
    or the admin reliability figures come out wrong:

      * URLScan's result endpoint returns 404 while the scan is still
        running.
      * VirusTotal's file lookup returns 404 for a hash it has never seen,
        which just means the file has to be uploaded.

    A 401 or 5xx still counts as a failure, so a bad key or an outage
    still shows up.
    """
    attempt = 0
    # Safe Browsing's key is in the query string, so redact the URL once
    # here and only ever log this copy.
    safe_url = redact_secrets(url)
    while True:
        start = time.monotonic()
        try:
            response = requests.request(method, url, timeout=timeout, **kwargs)
        except requests.Timeout as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            log_api_call(
                provider, False, scan_id=scan_id, endpoint=safe_url,
                duration_ms=duration_ms, error_message="timeout",
            )
            if attempt >= max_retries:
                raise ProviderTimeout(
                    f"{provider} timed out after {timeout}s"
                ) from exc
            attempt += 1
            time.sleep(2 ** attempt)
            continue
        except requests.RequestException as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            # requests usually puts the full URL in its error text, so
            # redact that as well.
            safe_error = redact_secrets(str(exc))
            log_api_call(
                provider, False, scan_id=scan_id, endpoint=safe_url,
                duration_ms=duration_ms, error_message=safe_error,
            )
            raise ProviderError(f"{provider} request failed: {safe_error}") from exc

        duration_ms = int((time.monotonic() - start) * 1000)

        if response.status_code in _RETRYABLE_STATUSES and attempt < max_retries:
            log_api_call(
                provider, False, scan_id=scan_id, endpoint=safe_url,
                status_code=response.status_code, duration_ms=duration_ms,
                error_message="retryable status, backing off",
            )
            attempt += 1
            time.sleep(2 ** attempt)
            continue

        succeeded = response.ok or response.status_code in expected_statuses
        log_api_call(
            provider, succeeded, scan_id=scan_id, endpoint=safe_url,
            status_code=response.status_code, duration_ms=duration_ms,
            raw_response=_safe_json(response),
        )
        return response
