"""The risk engine. Adds the signals up to a 0-100 score, puts the score
in a SAFE, SUSPICIOUS or DANGEROUS band, then applies the overrides, which
win whatever the score says.

The same signals and provider availability always give the same score,
band and override.
"""

from __future__ import annotations

import config

_BAND_ORDER = ["SAFE", "SUSPICIOUS", "DANGEROUS"]

_ALL_PROVIDERS = ("VIRUSTOTAL", "SAFE_BROWSING", "URLSCAN", "ABUSEIPDB")


def score_scan(
    header_signals: list[dict],
    url_signals: list[dict],
    attachment_signals: list[dict],
    provider_status: dict[str, str],
    attachment_results: list[dict],
    url_results: list[dict],
    header_result: dict | None,
) -> dict:
    """Combine every group's signals and provider outcomes into one verdict."""
    all_signals = [*header_signals, *url_signals, *attachment_signals]
    raw_score = sum(s["points"] for s in all_signals)
    risk_score = min(raw_score, 100)

    # A provider with no status (because its group crashed, say) counts as
    # UNAVAILABLE.
    full_status = {p: provider_status.get(p, "UNAVAILABLE") for p in _ALL_PROVIDERS}
    unavailable_providers = [p for p, s in full_status.items() if s == "UNAVAILABLE"]
    available_count = len(_ALL_PROVIDERS) - len(unavailable_providers)
    partial_scan = available_count < len(_ALL_PROVIDERS)

    risk_level = _band(risk_score)

    # With two or fewer providers answering, neither SAFE nor DANGEROUS can
    # be trusted, so the verdict is held at SUSPICIOUS for a person to
    # judge. The overrides below are direct detections and still win.
    if available_count <= 2:
        risk_level = "SUSPICIOUS"

    override_applied = _first_override(attachment_results, url_results, header_result)
    if override_applied in ("VT_MALICIOUS_THRESHOLD", "SAFE_BROWSING_MALICIOUS_THRESHOLD"):
        risk_level = "DANGEROUS"
    elif override_applied in ("ABUSEIPDB_HIGH_CONFIDENCE", "EXECUTABLE_ATTACHMENT"):
        risk_level = _floor(risk_level, "SUSPICIOUS")

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "partial_scan": partial_scan,
        "unavailable_providers": unavailable_providers,
        "override_applied": override_applied,
        "signals": all_signals,
    }


def _band(score: int) -> str:
    if score <= config.RISK_BAND_SAFE_MAX:
        return "SAFE"
    if score <= config.RISK_BAND_SUSPICIOUS_MAX:
        return "SUSPICIOUS"
    return "DANGEROUS"


def _floor(level: str, minimum: str) -> str:
    if _BAND_ORDER.index(level) < _BAND_ORDER.index(minimum):
        return minimum
    return level


def _first_override(
    attachment_results: list[dict],
    url_results: list[dict],
    header_result: dict | None,
) -> str | None:
    """Check the overrides in priority order and return the first that
    applies. It's saved with the scan so the advice can refer to it."""
    if any((a.get("vt_malicious_count") or 0) >= 5 for a in attachment_results):
        return "VT_MALICIOUS_THRESHOLD"

    if any(u.get("safe_browsing_status") in ("MALWARE", "SOCIAL_ENGINEERING") for u in url_results):
        return "SAFE_BROWSING_MALICIOUS_THRESHOLD"

    confidence = (header_result or {}).get("abuseipdb_confidence")
    if confidence is not None and confidence >= 90:
        return "ABUSEIPDB_HIGH_CONFIDENCE"

    if any(a.get("is_executable") for a in attachment_results):
        return "EXECUTABLE_ATTACHMENT"

    return None
