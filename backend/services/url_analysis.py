"""URL analysis. Safe Browsing checks every link in one batched call.
URLScan is submit-and-poll, one URL at a time, with a cap per scan, and is
skipped when Safe Browsing has already found a malicious link. The offline
checks from eml_parser (shortener, display mismatch, punycode, raw IP
host) become signals here as well.
"""

from __future__ import annotations

import time

import config
from api_clients import safe_browsing, urlscan
from services.signals import make_signal
from utils.exceptions import ProviderError, ProviderTimeout
from utils.logger import get_logger

logger = get_logger(__name__)

W = config.RISK_WEIGHTS

_MALICIOUS_THREAT_TYPES = {"MALWARE", "SOCIAL_ENGINEERING"}
_UNWANTED_THREAT_TYPES = {"UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"}


def analyze_urls(urls: list[dict], scan_id: str | None = None) -> dict:
    """urls is the urls list from services.eml_parser.parse_eml().

    Returns {"url_results": [...], "signals": [...], "provider_status": {...}}.
    """
    if not urls:
        # No links means nothing to check, not a provider failure.
        return {
            "url_results": [],
            "signals": [],
            "provider_status": {"SAFE_BROWSING": "AVAILABLE", "URLSCAN": "AVAILABLE"},
        }

    signals = []
    enriched = [dict(u) for u in urls]
    provider_status = {"SAFE_BROWSING": "UNAVAILABLE", "URLSCAN": "AVAILABLE"}

    sb_results: dict[str, list[str]] = {}
    try:
        sb_results = safe_browsing.check_urls([u["url"] for u in enriched], scan_id=scan_id)
        provider_status["SAFE_BROWSING"] = "AVAILABLE"
    except (ProviderError, ProviderTimeout) as exc:
        logger.warning("Safe Browsing unavailable: %s", exc)
        provider_status["SAFE_BROWSING"] = "UNAVAILABLE"

    safe_browsing_found_malicious = False

    for entry in enriched:
        threats = set(sb_results.get(entry["url"], []))
        if threats & _MALICIOUS_THREAT_TYPES:
            threat_type = next(iter(threats & _MALICIOUS_THREAT_TYPES))
            entry["safe_browsing_status"] = threat_type
            safe_browsing_found_malicious = True
            signals.append(make_signal(
                "url", "SAFE_BROWSING_MALWARE_SOCIAL", W["SAFE_BROWSING_MALWARE_SOCIAL"],
                f"Google Safe Browsing identified this link as {threat_type.replace('_', ' ').lower()}.",
                {"url": entry["url"], "threat_type": threat_type}, severity="CRITICAL",
            ))
        elif threats & _UNWANTED_THREAT_TYPES:
            threat_type = next(iter(threats & _UNWANTED_THREAT_TYPES))
            entry["safe_browsing_status"] = threat_type
            signals.append(make_signal(
                "url", "SAFE_BROWSING_UNWANTED_HARMFUL", W["SAFE_BROWSING_UNWANTED_HARMFUL"],
                f"Google Safe Browsing flagged this link as {threat_type.replace('_', ' ').lower()}.",
                {"url": entry["url"], "threat_type": threat_type}, severity="MEDIUM",
            ))
        elif provider_status["SAFE_BROWSING"] == "AVAILABLE":
            entry["safe_browsing_status"] = "CLEAN"
        else:
            entry["safe_browsing_status"] = "UNAVAILABLE"

        if entry.get("display_mismatch"):
            signals.append(make_signal(
                "url", "DISPLAY_MISMATCH", W["DISPLAY_MISMATCH"],
                "This link's visible text names a different site than where it "
                "actually leads. This is a common impersonation technique.",
                {"url": entry["url"], "anchor_text": entry.get("anchor_text")},
                severity="HIGH",
            ))
        if entry.get("is_shortener"):
            signals.append(make_signal(
                "url", "SHORTENER", W["SHORTENER"],
                "This link uses a URL-shortening service, which hides the real "
                "destination until it's clicked.",
                {"url": entry["url"]}, severity="LOW",
            ))
        if entry.get("is_raw_ip_host"):
            signals.append(make_signal(
                "url", "RAW_IP_HOST", W["RAW_IP_HOST"],
                "This link points to a raw numeric address instead of a named "
                "website, which legitimate businesses rarely do.",
                {"url": entry["url"]}, severity="MEDIUM",
            ))
        if entry.get("is_punycode"):
            signals.append(make_signal(
                "url", "PUNYCODE", W["PUNYCODE"],
                "This link's domain uses characters disguised to look like a "
                "different, trusted domain name.",
                {"url": entry["url"]}, severity="HIGH",
            ))

        entry.setdefault("urlscan_verdict", "UNAVAILABLE")
        entry.setdefault("urlscan_score", None)
        entry.setdefault("urlscan_screenshot_url", None)

    if not safe_browsing_found_malicious:
        _run_urlscan(enriched[: config.MAX_URLSCAN_CALLS_PER_SCAN], signals, provider_status, scan_id)
    # Otherwise URLScan is skipped on purpose: Safe Browsing already found
    # a malicious link. Its status stays AVAILABLE because nothing failed.

    return {"url_results": enriched, "signals": signals, "provider_status": provider_status}


def _run_urlscan(candidates: list[dict], signals: list[dict], provider_status: dict, scan_id: str | None) -> None:
    if not candidates:
        return

    attempted = False
    any_success = False
    deadline = time.monotonic() + config.URLSCAN_TIME_BUDGET_SECONDS

    for entry in candidates:
        if time.monotonic() > deadline:
            # Out of time. The rest keep their UNAVAILABLE default.
            logger.info("URLScan time budget spent; skipping %s", entry["url"])
            break
        attempted = True
        try:
            result = urlscan.scan_url(entry["url"], scan_id=scan_id)
            any_success = True
            entry["urlscan_verdict"] = "MALICIOUS" if result["malicious"] else "CLEAN"
            entry["urlscan_score"] = result["score"]
            entry["urlscan_screenshot_url"] = result["screenshot_url"]

            if result["malicious"]:
                signals.append(make_signal(
                    "url", "URLSCAN_MALICIOUS", W["URLSCAN_MALICIOUS"],
                    "URLScan.io's live sandbox test found this link behaves "
                    "maliciously.",
                    {"url": entry["url"], "score": result["score"]}, severity="CRITICAL",
                ))
            elif result["score"] is not None and result["score"] > 50:
                signals.append(make_signal(
                    "url", "URLSCAN_HIGH_SCORE_UNFLAGGED", W["URLSCAN_HIGH_SCORE_UNFLAGGED"],
                    "URLScan.io's live sandbox test gave this link an elevated "
                    "risk score, though it stopped short of calling it malicious.",
                    {"url": entry["url"], "score": result["score"]}, severity="MEDIUM",
                ))
        except (ProviderError, ProviderTimeout) as exc:
            logger.warning("URLScan unavailable for %s: %s", entry["url"], exc)
            entry["urlscan_verdict"] = "UNAVAILABLE"

    if attempted and not any_success:
        provider_status["URLSCAN"] = "UNAVAILABLE"
