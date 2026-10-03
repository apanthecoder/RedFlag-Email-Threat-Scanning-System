"""Offline tests for services/eml_parser.py against the fixtures in
docs/test-samples/. No network access and no external API: parsing has to
be testable offline.

One test per parser-level signal, named after the sample it reads, so a
failure names both the signal and the fixture.
"""

import os

import pytest

from services.eml_parser import (
    _display_name_spoof,
    _extract_domain,
    _is_display_mismatch,
    parse_eml,
)
from utils.exceptions import ParsingError

SAMPLES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "docs", "test-samples",
)

EXPECTED_SAMPLES = {
    "01_clean_no_links.eml",
    "02_clean_with_link.eml",
    "03_no_auth_headers.eml",
    "04_auth_fail_all.eml",
    "05_reply_to_mismatch.eml",
    "06_display_name_spoof.eml",
    "07_link_display_mismatch.eml",
    "08_link_shortener.eml",
    "09_link_raw_ip.eml",
    "10_link_punycode.eml",
    "11_attachment_extension_mismatch.eml",
    "12_attachment_executable.eml",
    "13_attachment_password_zip.eml",
    "14_attachment_password_7z.eml",
    "15_multi_signal_phishing.eml",
    "16_eicar_malware.eml.b64",
    "17_safe_browsing_phishing.eml",
    "18_malformed.eml",
    "19_no_received_headers.eml",
}


def sample_path(name: str) -> str:
    return os.path.join(SAMPLES_DIR, name)


# ---------------------------------------------------------------------
# Clean baselines
# ---------------------------------------------------------------------


def test_clean_no_links_has_no_urls():
    result = parse_eml(sample_path("01_clean_no_links.eml"))
    assert result["urls"] == []
    assert result["attachments"] == []
    assert "Klang" in result["body_text"]
    assert result["headers"]["spf_result"] == "PASS"
    assert result["headers"]["dkim_result"] == "PASS"
    assert result["headers"]["dmarc_result"] == "PASS"
    assert result["headers"]["sender_ip"] == "93.184.216.34"
    assert result["headers"]["sender_ip_status"] == "AVAILABLE"


def test_clean_with_link_extracts_legit_url_without_signals():
    result = parse_eml(sample_path("02_clean_with_link.eml"))
    urls = result["urls"]
    assert len(urls) == 1
    assert urls[0]["url"] == "https://example.com/shared/week6"
    assert urls[0]["is_shortener"] is False
    assert urls[0]["display_mismatch"] is False
    assert urls[0]["is_punycode"] is False
    assert urls[0]["is_raw_ip_host"] is False


# ---------------------------------------------------------------------
# Header signals
# ---------------------------------------------------------------------


def test_missing_authentication_results_reads_as_none():
    headers = parse_eml(sample_path("03_no_auth_headers.eml"))["headers"]
    assert headers["spf_result"] == "NONE"
    assert headers["dkim_result"] == "NONE"
    assert headers["dmarc_result"] == "NONE"


def test_all_three_authentication_failures_detected():
    headers = parse_eml(sample_path("04_auth_fail_all.eml"))["headers"]
    assert headers["spf_result"] == "FAIL"
    assert headers["dkim_result"] == "FAIL"
    assert headers["dmarc_result"] == "FAIL"


def test_reply_to_on_another_domain_flagged():
    headers = parse_eml(sample_path("05_reply_to_mismatch.eml"))["headers"]
    assert headers["reply_to_mismatch"] is True
    assert headers["display_name_spoof"] is False


def test_brand_in_display_name_flagged():
    headers = parse_eml(sample_path("06_display_name_spoof.eml"))["headers"]
    assert headers["display_name_spoof"] is True
    assert headers["reply_to_mismatch"] is False


def test_no_received_headers_marks_sender_ip_unavailable():
    headers = parse_eml(sample_path("19_no_received_headers.eml"))["headers"]
    assert headers["sender_ip"] is None
    assert headers["sender_ip_status"] == "UNAVAILABLE"
    assert headers["received"] == []


# ---------------------------------------------------------------------
# URL signals
# ---------------------------------------------------------------------


def test_link_text_naming_another_site_flagged():
    urls = parse_eml(sample_path("07_link_display_mismatch.eml"))["urls"]
    assert len(urls) == 1
    assert urls[0]["display_mismatch"] is True


def test_shortened_url_flagged():
    urls = parse_eml(sample_path("08_link_shortener.eml"))["urls"]
    assert len(urls) == 1
    assert urls[0]["is_shortener"] is True


def test_raw_ip_host_flagged():
    urls = parse_eml(sample_path("09_link_raw_ip.eml"))["urls"]
    assert len(urls) == 1
    assert urls[0]["is_raw_ip_host"] is True


def test_punycode_host_flagged():
    urls = parse_eml(sample_path("10_link_punycode.eml"))["urls"]
    assert len(urls) == 1
    assert urls[0]["is_punycode"] is True


# ---------------------------------------------------------------------
# Attachment signals
# ---------------------------------------------------------------------


def test_extension_magic_byte_mismatch_detected():
    attachments = parse_eml(sample_path("11_attachment_extension_mismatch.eml"))["attachments"]
    assert len(attachments) == 1
    attachment = attachments[0]
    assert attachment["filename"] == "Invoice_2026_0143.pdf"
    assert attachment["detected_file_type"] == "exe"
    assert attachment["extension_mismatch"] is True
    assert len(attachment["sha256"]) == 64
    assert len(attachment["md5"]) == 32


def test_executable_attachment_detected():
    attachments = parse_eml(sample_path("12_attachment_executable.eml"))["attachments"]
    assert len(attachments) == 1
    assert attachments[0]["filename"].endswith(".exe")
    assert attachments[0]["is_executable"] is True
    # Named .exe and actually an executable, so this is not a disguise.
    assert attachments[0]["extension_mismatch"] is False


def test_password_protected_zip_attachment_detected():
    attachments = parse_eml(sample_path("13_attachment_password_zip.eml"))["attachments"]
    assert len(attachments) == 1
    assert attachments[0]["is_password_protected"] is True


def test_password_protected_7z_attachment_detected():
    attachments = parse_eml(sample_path("14_attachment_password_7z.eml"))["attachments"]
    assert len(attachments) == 1
    assert attachments[0]["is_password_protected"] is True


# ---------------------------------------------------------------------
# Combinations and rejection
# ---------------------------------------------------------------------


def test_multi_signal_phishing_raises_every_intended_header_and_url_signal():
    result = parse_eml(sample_path("15_multi_signal_phishing.eml"))
    headers = result["headers"]
    assert headers["spf_result"] == "FAIL"
    assert headers["dkim_result"] == "FAIL"
    assert headers["dmarc_result"] == "FAIL"
    assert headers["reply_to_mismatch"] is True
    assert headers["display_name_spoof"] is True
    assert len(result["urls"]) == 1
    assert result["urls"][0]["display_mismatch"] is True


def test_malformed_file_is_rejected():
    with pytest.raises(ParsingError):
        parse_eml(sample_path("18_malformed.eml"))


def test_all_samples_present():
    actual = set(os.listdir(SAMPLES_DIR))
    assert EXPECTED_SAMPLES.issubset(actual)


# --- Regression tests for lookalike links and spoofed From headers --------



@pytest.mark.parametrize("anchor, hostname", [
    ("paypal.com", "paypal.com.evil.example"),
    ("paypal.com", "evil-paypal.com"),
    ("bank.com", "mybank.com"),
])
def test_lookalike_link_is_a_display_mismatch(anchor, hostname):
    assert _is_display_mismatch(anchor, hostname) is True


@pytest.mark.parametrize("anchor, hostname", [
    ("paypal.com", "paypal.com"),
    ("www.paypal.com", "paypal.com"),
    ("paypal.com", "www.paypal.com"),
    ("paypal.com", "login.paypal.com"),
])
def test_same_site_link_is_not_a_display_mismatch(anchor, hostname):
    assert _is_display_mismatch(anchor, hostname) is False


def test_domain_comes_from_the_real_address_not_the_display_name():
    header = '"support@paypal.com" <billing@evil.example>'
    assert _extract_domain(header) == "evil.example"
    assert _display_name_spoof(header) is True
