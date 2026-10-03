"""Unit tests for the risk engine: bands, overrides, and the partial-scan
cap. All inputs are plain dicts, with no providers or database.
"""

from services.risk_scoring import score_scan

FULL_STATUS = {"VIRUSTOTAL": "AVAILABLE", "SAFE_BROWSING": "AVAILABLE", "URLSCAN": "AVAILABLE", "ABUSEIPDB": "AVAILABLE"}


def _score(points, provider_status=None, attachment_results=None, url_results=None, header_result=None):
    signals = [{"category": "test", "signal": "TEST_SIGNAL", "points": points, "severity": "MEDIUM", "explanation": "x", "evidence": {}}] if points else []
    return score_scan(
        header_signals=signals,
        url_signals=[],
        attachment_signals=[],
        provider_status=provider_status or FULL_STATUS,
        attachment_results=attachment_results or [],
        url_results=url_results or [],
        header_result=header_result,
    )


def test_no_signals_is_safe():
    result = _score(0)
    assert result["risk_score"] == 0
    assert result["risk_level"] == "SAFE"
    assert result["override_applied"] is None
    assert result["partial_scan"] is False
    assert result["unavailable_providers"] == []


def test_band_boundary_safe_max():
    assert _score(24)["risk_level"] == "SAFE"


def test_band_boundary_suspicious_start():
    assert _score(25)["risk_level"] == "SUSPICIOUS"


def test_band_boundary_suspicious_max():
    assert _score(59)["risk_level"] == "SUSPICIOUS"


def test_band_boundary_dangerous_start():
    assert _score(60)["risk_level"] == "DANGEROUS"


def test_score_caps_at_100():
    result = _score(500)
    assert result["risk_score"] == 100
    assert result["risk_level"] == "DANGEROUS"


def test_vt_override_forces_dangerous_even_with_low_score():
    result = _score(0, attachment_results=[{"vt_malicious_count": 7, "is_executable": False}])
    assert result["risk_level"] == "DANGEROUS"
    assert result["override_applied"] == "VT_MALICIOUS_THRESHOLD"


def test_safe_browsing_override_forces_dangerous():
    result = _score(0, url_results=[{"safe_browsing_status": "SOCIAL_ENGINEERING"}])
    assert result["risk_level"] == "DANGEROUS"
    assert result["override_applied"] == "SAFE_BROWSING_MALICIOUS_THRESHOLD"


def test_abuseipdb_override_floors_suspicious_not_below():
    result = _score(0, header_result={"abuseipdb_confidence": 95})
    assert result["risk_level"] == "SUSPICIOUS"
    assert result["override_applied"] == "ABUSEIPDB_HIGH_CONFIDENCE"


def test_abuseipdb_override_does_not_downgrade_dangerous():
    result = _score(70, header_result={"abuseipdb_confidence": 95})
    assert result["risk_level"] == "DANGEROUS"


def test_executable_override_floors_suspicious():
    result = _score(0, attachment_results=[{"vt_malicious_count": 0, "is_executable": True}])
    assert result["risk_level"] == "SUSPICIOUS"
    assert result["override_applied"] == "EXECUTABLE_ATTACHMENT"


def test_partial_scan_flagged_with_one_provider_down():
    status = {**FULL_STATUS, "URLSCAN": "UNAVAILABLE"}
    result = _score(10, provider_status=status)
    assert result["partial_scan"] is True
    assert result["unavailable_providers"] == ["URLSCAN"]
    # Three of four still answered, so it scores normally with no cap.
    assert result["risk_level"] == "SAFE"


def test_two_or_fewer_providers_caps_at_suspicious_even_if_score_is_low():
    status = {"VIRUSTOTAL": "UNAVAILABLE", "SAFE_BROWSING": "UNAVAILABLE", "URLSCAN": "AVAILABLE", "ABUSEIPDB": "AVAILABLE"}
    result = _score(0, provider_status=status)
    assert result["risk_level"] == "SUSPICIOUS"
    assert result["partial_scan"] is True


def test_two_or_fewer_providers_caps_dangerous_score_down_to_suspicious():
    status = {"VIRUSTOTAL": "UNAVAILABLE", "SAFE_BROWSING": "UNAVAILABLE", "URLSCAN": "AVAILABLE", "ABUSEIPDB": "AVAILABLE"}
    result = _score(80, provider_status=status)
    assert result["risk_level"] == "SUSPICIOUS"


def test_conclusive_override_still_wins_despite_partial_scan_cap():
    status = {"VIRUSTOTAL": "AVAILABLE", "SAFE_BROWSING": "UNAVAILABLE", "URLSCAN": "UNAVAILABLE", "ABUSEIPDB": "UNAVAILABLE"}
    result = _score(0, provider_status=status, attachment_results=[{"vt_malicious_count": 10, "is_executable": True}])
    assert result["risk_level"] == "DANGEROUS"
    assert result["override_applied"] == "VT_MALICIOUS_THRESHOLD"


def test_signals_are_all_present_in_output():
    result = _score(10)
    assert len(result["signals"]) == 1
    assert result["signals"][0]["signal"] == "TEST_SIGNAL"
