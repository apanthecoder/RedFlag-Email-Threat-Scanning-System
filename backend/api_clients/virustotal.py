"""VirusTotal v3 client for scanning attachments.

Free tier: 4 requests a minute and 500 a day, the tightest limit in the
system. Always look the hash up first and upload only when VirusTotal
returns 404. Each function makes a single call; caching and pacing are
the caller's job.
"""

from __future__ import annotations

import config
from api_clients._http import call_provider
from utils.exceptions import ProviderError

BASE_URL = "https://www.virustotal.com/api/v3"


def get_file_report(sha256: str, scan_id: str | None = None) -> dict | None:
    """Look a file up by hash. Returns None on a 404, meaning VirusTotal
    hasn't seen it, and the caller should use upload_file() next."""
    response = call_provider(
        "VIRUSTOTAL", "GET", f"{BASE_URL}/files/{sha256}",
        timeout=config.VIRUSTOTAL_TIMEOUT,
        headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
        scan_id=scan_id,
        # 404 means VirusTotal has never seen this hash, so the file needs
        # uploading. That's the normal path, not a failed call.
        expected_statuses={404},
    )
    if response.status_code == 404:
        return None
    if response.status_code == 401:
        raise ProviderError("VirusTotal API key rejected (401).")
    if not response.ok:
        raise ProviderError(f"VirusTotal returned {response.status_code}")
    return _parse_analysis_stats(response.json())


def upload_file(file_bytes: bytes, filename: str, scan_id: str | None = None) -> str:
    """Upload a file whose hash VirusTotal doesn't know yet.

    Returns an analysis id. Poll it with get_analysis() until the status
    is 'completed'.
    """
    response = call_provider(
        "VIRUSTOTAL", "POST", f"{BASE_URL}/files",
        timeout=config.VIRUSTOTAL_TIMEOUT,
        headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
        files={"file": (filename, file_bytes)},
        scan_id=scan_id,
    )
    if response.status_code == 401:
        raise ProviderError("VirusTotal API key rejected (401).")
    if not response.ok:
        raise ProviderError(f"VirusTotal upload failed ({response.status_code})")
    analysis_id = response.json().get("data", {}).get("id")
    if not analysis_id:
        raise ProviderError("VirusTotal upload did not return an analysis id.")
    return analysis_id


def get_analysis(analysis_id: str, scan_id: str | None = None) -> dict:
    """Poll an analysis started by upload_file().

    Returns {"status": "queued"} while pending, or {"status": "completed",
    ...stats} once VirusTotal has finished scanning the file.
    """
    response = call_provider(
        "VIRUSTOTAL", "GET", f"{BASE_URL}/analyses/{analysis_id}",
        timeout=config.VIRUSTOTAL_TIMEOUT,
        headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
        scan_id=scan_id,
    )
    if not response.ok:
        raise ProviderError(f"VirusTotal analysis lookup failed ({response.status_code})")

    payload = response.json()
    attrs = payload.get("data", {}).get("attributes", {})
    status = attrs.get("status", "queued")
    result: dict = {"status": status}
    if status == "completed":
        stats = attrs.get("stats", {})
        result.update({
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
        })
    return result


def _parse_analysis_stats(payload: dict) -> dict:
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    threat_label = attrs.get("popular_threat_classification", {}).get(
        "suggested_threat_label"
    )
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "harmless": stats.get("harmless", 0),
        "threat_label": threat_label,
    }
