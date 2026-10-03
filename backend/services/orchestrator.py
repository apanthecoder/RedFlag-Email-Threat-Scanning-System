"""Runs the three analysis groups (headers, URLs, attachments) in parallel
and passes their output to the risk engine. If one group crashes, the
other two still count and the scan still gets a report.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from services.attachment_analysis import scan_attachments
from services.header_analysis import analyze_headers
from services.risk_scoring import score_scan
from services.url_analysis import analyze_urls
from utils.logger import get_logger

logger = get_logger(__name__)


def run_pipeline(parsed: dict, scan_id: str | None = None) -> dict:
    """parsed is the dict returned by services.eml_parser.parse_eml().

    Returns header_result, url_results, attachment_results and verdict,
    which routes/scan.py saves with database.models.save_full_scan_result().
    Each provider call has its own timeout, so no group can hang forever.
    """
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {
            pool.submit(analyze_headers, parsed["headers"], scan_id): "headers",
            pool.submit(analyze_urls, parsed["urls"], scan_id): "urls",
            pool.submit(scan_attachments, parsed["attachments"], scan_id): "attachments",
        }
        results: dict[str, dict] = {}
        for future in as_completed(futures):
            group_name = futures[future]
            try:
                results[group_name] = future.result()
            except Exception as exc:
                logger.error("Analysis group '%s' failed entirely: %s", group_name, exc)
                results[group_name] = {"signals": [], "provider_status": {}}

    header_out = results.get("headers", {})
    url_out = results.get("urls", {})
    attachment_out = results.get("attachments", {})

    provider_status: dict[str, str] = {}
    provider_status.update(header_out.get("provider_status", {}))
    provider_status.update(url_out.get("provider_status", {}))
    provider_status.update(attachment_out.get("provider_status", {}))

    header_result = header_out.get("header_result")
    url_results = url_out.get("url_results", [])
    attachment_results = attachment_out.get("attachment_results", [])

    verdict = score_scan(
        header_signals=header_out.get("signals", []),
        url_signals=url_out.get("signals", []),
        attachment_signals=attachment_out.get("signals", []),
        provider_status=provider_status,
        attachment_results=attachment_results,
        url_results=url_results,
        header_result=header_result,
    )

    return {
        "header_result": header_result,
        "url_results": url_results,
        "attachment_results": attachment_results,
        "verdict": verdict,
    }
