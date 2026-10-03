"""Google Safe Browsing v4 client for known-bad URLs.

Free tier: 10,000 requests a day. threatMatches:find takes up to 500 URLs,
so one request covers every link in an email.
"""

from __future__ import annotations

import config
from api_clients._http import call_provider
from utils.exceptions import ProviderError

BASE_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def check_urls(urls: list[str], scan_id: str | None = None) -> dict[str, list[str]]:
    """Check up to 500 URLs in one call.

    Returns {url: [threat_type, ...]} for each URL that was flagged. A URL
    missing from the result is clean. For a batch with nothing flagged,
    Safe Browsing sends back an empty body; there's no "clean" field.
    """
    if not urls:
        return {}

    payload = {
        "client": {"clientId": "redflag", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls[:500]],
        },
    }

    response = call_provider(
        "SAFE_BROWSING", "POST",
        f"{BASE_URL}?key={config.SAFE_BROWSING_API_KEY}",
        timeout=config.SAFE_BROWSING_TIMEOUT,
        json=payload,
        scan_id=scan_id,
    )
    if response.status_code == 400:
        raise ProviderError(
            "Safe Browsing rejected the request (400). Check the API key and payload."
        )
    if not response.ok:
        raise ProviderError(f"Safe Browsing returned {response.status_code}")

    body = response.json() if response.content else {}
    results: dict[str, list[str]] = {}
    for match in body.get("matches", []):
        url = match.get("threat", {}).get("url")
        threat_type = match.get("threatType")
        if url and threat_type:
            results.setdefault(url, []).append(threat_type)
    return results
