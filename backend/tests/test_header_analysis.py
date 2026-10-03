"""Regression test: analyze_headers' output goes straight into
database.models (from_address/to_address/date_header columns) and the
frontend's TechnicalDetails component, so its keys have to use those
names, not eml_parser's from/to/date.
"""

from services.header_analysis import analyze_headers

HEADERS = {
    "from": "sender@example.com",
    "to": "clerk@example.com",
    "date": "Mon, 10 Aug 2026 00:00:00 +0000",
    "reply_to": None,
    "return_path": None,
    "message_id": "<test@example.com>",
    "spf_result": "PASS",
    "dkim_result": "PASS",
    "dmarc_result": "PASS",
    "reply_to_mismatch": False,
    "display_name_spoof": False,
    "sender_ip": None,
    "sender_ip_status": "UNAVAILABLE",
}


def test_header_result_uses_database_field_names():
    result = analyze_headers(HEADERS)["header_result"]
    assert result["from_address"] == "sender@example.com"
    assert result["to_address"] == "clerk@example.com"
    assert result["date_header"] == "Mon, 10 Aug 2026 00:00:00 +0000"
