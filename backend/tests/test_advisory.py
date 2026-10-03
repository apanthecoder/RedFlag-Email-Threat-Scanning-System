"""Tests for services/advisory.py: rule triggers, urgency ordering, and
the "every scan gets a panel" guarantee, including SAFE.
"""

from services.advisory import build_advisory

SAFE_VERDICT = {"risk_level": "SAFE", "signals": []}
SUSPICIOUS_VERDICT = {"risk_level": "SUSPICIOUS", "signals": []}
DANGEROUS_VERDICT = {"risk_level": "DANGEROUS", "signals": []}


def _triggers(steps):
    return [s["triggered_by"] for s in steps]


def test_safe_verdict_with_no_signals_still_gets_one_step():
    steps = build_advisory(SAFE_VERDICT, None, [], [])
    assert len(steps) == 1
    assert steps[0]["triggered_by"] == "SAFE_VERDICT"
    assert steps[0]["severity"] == "INFO"
    assert steps[0]["step_order"] == 1


def test_malicious_attachment_produces_stop_and_containment_steps_in_order():
    attachments = [{"filename": "invoice.pdf.exe", "vt_status": "MALICIOUS", "is_executable": True}]
    steps = build_advisory(DANGEROUS_VERDICT, None, [], attachments)
    triggers = _triggers(steps)

    assert "MALICIOUS_ATTACHMENT" in triggers
    assert "MALICIOUS_ATTACHMENT_ALREADY_OPENED" in triggers
    # "Don't open" steps come before containment steps.
    assert triggers.index("MALICIOUS_ATTACHMENT") < triggers.index("MALICIOUS_ATTACHMENT_ALREADY_OPENED")
    # Step orders are sequential starting at 1.
    assert [s["step_order"] for s in steps] == list(range(1, len(steps) + 1))


def test_executable_but_not_confirmed_malicious_gets_warning_not_critical():
    attachments = [{"filename": "setup.exe", "vt_status": "CLEAN", "is_executable": True}]
    steps = build_advisory(SUSPICIOUS_VERDICT, None, [], attachments)
    exec_step = next(s for s in steps if s["triggered_by"] == "EXECUTABLE_ATTACHMENT")
    assert exec_step["severity"] == "WARNING"
    # Not also flagged as MALICIOUS_ATTACHMENT since vt_status isn't MALICIOUS.
    assert "MALICIOUS_ATTACHMENT" not in _triggers(steps)


def test_malicious_url_produces_stop_and_containment_steps():
    urls = [{"url": "http://evil.example", "safe_browsing_status": "SOCIAL_ENGINEERING"}]
    steps = build_advisory(DANGEROUS_VERDICT, None, urls, [])
    triggers = _triggers(steps)
    assert "MALICIOUS_URL" in triggers
    assert "MALICIOUS_URL_ALREADY_CLICKED" in triggers
    assert triggers.index("MALICIOUS_URL") < triggers.index("MALICIOUS_URL_ALREADY_CLICKED")


def test_display_mismatch_url_triggers_step():
    urls = [{"url": "http://evil.example", "display_mismatch": True}]
    steps = build_advisory(SUSPICIOUS_VERDICT, None, urls, [])
    assert "DISPLAY_MISMATCH" in _triggers(steps)


def test_auth_failure_triggers_step():
    header_result = {"spf_result": "FAIL", "dkim_result": "PASS", "dmarc_result": "PASS"}
    steps = build_advisory(SUSPICIOUS_VERDICT, header_result, [], [])
    assert "AUTH_FAIL" in _triggers(steps)


def test_no_auth_failure_does_not_trigger_step():
    header_result = {"spf_result": "PASS", "dkim_result": "PASS", "dmarc_result": "PASS"}
    steps = build_advisory(SAFE_VERDICT, header_result, [], [])
    assert "AUTH_FAIL" not in _triggers(steps)


def test_high_abuse_ip_triggers_step():
    header_result = {"abuseipdb_confidence": 92}
    steps = build_advisory(SUSPICIOUS_VERDICT, header_result, [], [])
    assert "HIGH_ABUSE_IP" in _triggers(steps)


def test_low_abuse_confidence_does_not_trigger_step():
    header_result = {"abuseipdb_confidence": 20}
    steps = build_advisory(SAFE_VERDICT, header_result, [], [])
    assert "HIGH_ABUSE_IP" not in _triggers(steps)


def test_display_name_spoof_triggers_step():
    header_result = {"display_name_spoof": True}
    steps = build_advisory(SUSPICIOUS_VERDICT, header_result, [], [])
    assert "DISPLAY_NAME_SPOOF" in _triggers(steps)


def test_dangerous_verdict_adds_report_to_it_step_last_among_escalation():
    steps = build_advisory(DANGEROUS_VERDICT, None, [], [])
    assert steps[-1]["triggered_by"] == "DANGEROUS_VERDICT"
    assert steps[-1]["severity"] == "CRITICAL"


def test_suspicious_verdict_adds_verify_step():
    steps = build_advisory(SUSPICIOUS_VERDICT, None, [], [])
    assert steps[-1]["triggered_by"] == "SUSPICIOUS_VERDICT"
    assert steps[-1]["severity"] == "WARNING"


def test_every_step_has_one_action_and_required_fields():
    header_result = {"spf_result": "FAIL", "abuseipdb_confidence": 90, "display_name_spoof": True}
    attachments = [{"filename": "bad.exe", "vt_status": "MALICIOUS", "is_executable": True}]
    urls = [{"url": "http://evil.example", "safe_browsing_status": "MALWARE", "display_mismatch": True}]
    steps = build_advisory(DANGEROUS_VERDICT, header_result, urls, attachments)

    assert len(steps) > 1
    for step in steps:
        assert set(step.keys()) == {"step_order", "step_title", "step_detail", "severity", "triggered_by"}
        assert step["severity"] in ("INFO", "WARNING", "CRITICAL")
        assert step["step_title"]
        assert step["step_detail"]

    # Sequential ordering across the whole combined set too.
    assert [s["step_order"] for s in steps] == list(range(1, len(steps) + 1))


def test_full_urgency_ordering_stop_before_containment_before_escalation():
    header_result = {"spf_result": "FAIL"}
    attachments = [{"filename": "bad.exe", "vt_status": "MALICIOUS", "is_executable": True}]
    urls = [{"url": "http://evil.example", "safe_browsing_status": "MALWARE"}]
    steps = build_advisory(DANGEROUS_VERDICT, header_result, urls, attachments)
    triggers = _triggers(steps)

    stop_idx = triggers.index("MALICIOUS_ATTACHMENT")
    containment_idx = triggers.index("MALICIOUS_ATTACHMENT_ALREADY_OPENED")
    verification_idx = triggers.index("AUTH_FAIL")
    escalation_idx = triggers.index("DANGEROUS_VERDICT")

    assert stop_idx < containment_idx < verification_idx < escalation_idx
