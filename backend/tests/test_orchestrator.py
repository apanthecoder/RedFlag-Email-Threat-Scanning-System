"""Tests for services/orchestrator.py: the three analysis groups run in
parallel and one group crashing outright must never abort the others.
"""

from services.orchestrator import run_pipeline

PARSED = {
    "headers": {"from": "a@b.com", "spf_result": "NONE", "dkim_result": "NONE", "dmarc_result": "NONE"},
    "urls": [],
    "attachments": [],
}


def test_pipeline_combines_all_three_groups(mocker):
    mocker.patch(
        "services.orchestrator.analyze_headers",
        return_value={"header_result": {"from_address": "a@b.com"}, "signals": [], "provider_status": {"ABUSEIPDB": "AVAILABLE"}},
    )
    mocker.patch(
        "services.orchestrator.analyze_urls",
        return_value={"url_results": [], "signals": [], "provider_status": {"SAFE_BROWSING": "AVAILABLE", "URLSCAN": "AVAILABLE"}},
    )
    mocker.patch(
        "services.orchestrator.scan_attachments",
        return_value={"attachment_results": [], "signals": [], "provider_status": {"VIRUSTOTAL": "AVAILABLE"}},
    )

    result = run_pipeline(PARSED)

    assert result["header_result"] == {"from_address": "a@b.com"}
    assert result["verdict"]["risk_level"] == "SAFE"
    assert result["verdict"]["partial_scan"] is False
    assert result["verdict"]["unavailable_providers"] == []


def test_one_group_crashing_does_not_abort_the_others(mocker):
    mocker.patch("services.orchestrator.analyze_headers", side_effect=RuntimeError("boom"))
    mocker.patch(
        "services.orchestrator.analyze_urls",
        return_value={"url_results": [], "signals": [], "provider_status": {"SAFE_BROWSING": "AVAILABLE", "URLSCAN": "AVAILABLE"}},
    )
    mocker.patch(
        "services.orchestrator.scan_attachments",
        return_value={"attachment_results": [], "signals": [], "provider_status": {"VIRUSTOTAL": "AVAILABLE"}},
    )

    result = run_pipeline(PARSED)

    # The crashed group contributes no signals and its provider is marked
    # unavailable, but the scan still produces a full verdict.
    assert result["header_result"] is None
    assert "ABUSEIPDB" in result["verdict"]["unavailable_providers"]
    assert result["verdict"]["partial_scan"] is True
    assert result["verdict"]["risk_level"] in ("SAFE", "SUSPICIOUS", "DANGEROUS")


def test_all_groups_crashing_still_returns_a_verdict(mocker):
    mocker.patch("services.orchestrator.analyze_headers", side_effect=RuntimeError("boom"))
    mocker.patch("services.orchestrator.analyze_urls", side_effect=RuntimeError("boom"))
    mocker.patch("services.orchestrator.scan_attachments", side_effect=RuntimeError("boom"))

    result = run_pipeline(PARSED)

    assert result["verdict"]["risk_level"] == "SUSPICIOUS"  # 0 providers available -> never SAFE
    assert set(result["verdict"]["unavailable_providers"]) == {
        "VIRUSTOTAL", "SAFE_BROWSING", "URLSCAN", "ABUSEIPDB",
    }
