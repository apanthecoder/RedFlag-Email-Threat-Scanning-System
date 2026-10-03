"""AbuseIPDB v2 client for sender IP reputation.

Free tier: 1,000 lookups a day. One call per email, for the earliest
public IP in the Received chain.
"""

from __future__ import annotations

import config
from api_clients._http import call_provider
from utils.exceptions import ProviderError

BASE_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip(ip: str, scan_id: str | None = None) -> dict:
    """Look up an IP's abuse confidence score, report count and country."""
    response = call_provider(
        "ABUSEIPDB", "GET", BASE_URL,
        timeout=config.ABUSEIPDB_TIMEOUT,
        headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        scan_id=scan_id,
    )
    if response.status_code == 401:
        raise ProviderError("AbuseIPDB API key rejected (401).")
    if not response.ok:
        raise ProviderError(f"AbuseIPDB returned {response.status_code}")

    data = response.json().get("data", {})
    return {
        "confidence_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "country_code": data.get("countryCode"),
        "is_whitelisted": bool(data.get("isWhitelisted", False)),
    }
