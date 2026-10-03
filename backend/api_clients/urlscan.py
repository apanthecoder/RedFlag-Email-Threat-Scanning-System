"""URLScan.io v1 client. It loads a URL in a sandbox and reports how the
page behaves.

Free tier: 100 scans a day, 60 an hour, 2 a minute. That's tight, so the
caller caps how many URLs go to it and skips it when Safe Browsing has
already found a malicious link.

Unlike the other three providers it's asynchronous: submit, wait, then
poll for the result. This is the main reason a scan can take up to about
90 seconds.

Submissions use visibility "public", so scanned URLs can be seen by
anyone on urlscan.io. This is a known limitation, covered in the report.
"""

from __future__ import annotations

import time

import config
from api_clients._http import call_provider
from utils.exceptions import ProviderError, ProviderTimeout

BASE_URL = "https://urlscan.io/api/v1"

_INITIAL_WAIT_SECONDS = 10


def scan_url(url: str, scan_id: str | None = None) -> dict:
    """Submit a URL and poll until the result is ready.

    Raises ProviderTimeout if it isn't ready after URLSCAN_MAX_POLL_ATTEMPTS
    polls, URLSCAN_POLL_INTERVAL seconds apart. The caller then marks the
    URL UNAVAILABLE and scores without it.
    """
    submit_response = call_provider(
        "URLSCAN", "POST", f"{BASE_URL}/scan/",
        timeout=config.URLSCAN_POLL_TIMEOUT,
        headers={
            "API-Key": config.URLSCAN_API_KEY,
            "Content-Type": "application/json",
        },
        json={"url": url, "visibility": "public"},
        scan_id=scan_id,
    )
    if response_is_key_error(submit_response.status_code):
        raise ProviderError("URLScan API key rejected.")
    if not submit_response.ok:
        raise ProviderError(f"URLScan submission failed ({submit_response.status_code})")

    scan_uuid = submit_response.json().get("uuid")
    if not scan_uuid:
        raise ProviderError("URLScan did not return a scan UUID.")

    time.sleep(_INITIAL_WAIT_SECONDS)

    for _ in range(config.URLSCAN_MAX_POLL_ATTEMPTS):
        result_response = call_provider(
            "URLSCAN", "GET", f"{BASE_URL}/result/{scan_uuid}/",
            timeout=config.URLSCAN_POLL_TIMEOUT,
            headers={"API-Key": config.URLSCAN_API_KEY},
            scan_id=scan_id,
            # A 404 here means the scan is still running. It shouldn't
            # lower URLScan's success rate in the admin analytics.
            expected_statuses={404},
        )
        if result_response.status_code == 404:
            time.sleep(config.URLSCAN_POLL_INTERVAL)
            continue
        if not result_response.ok:
            raise ProviderError(f"URLScan result lookup failed ({result_response.status_code})")

        return _parse_result(result_response.json())

    raise ProviderTimeout(
        f"URLScan did not finish scanning {url} within the poll budget."
    )


def response_is_key_error(status_code: int) -> bool:
    return status_code in (401, 403)


def _parse_result(payload: dict) -> dict:
    verdict = payload.get("verdicts", {}).get("overall", {})
    return {
        "malicious": bool(verdict.get("malicious", False)),
        "score": verdict.get("score"),
        "screenshot_url": payload.get("task", {}).get("screenshotURL"),
    }
