"""Builds the security advice for a scan from fixed rules, with no
language model involved. It takes the verdict and the header, URL and
attachment results, and returns ordered steps. The steps are saved to
advisory_outputs, so an old report keeps the advice it was given even if
these rules change later.

Steps are ordered by urgency: what not to do, then containment, then
checking the sender, then the overall verdict. Each step is one action,
written for someone with no security background, and none of them say
the email is definitely safe.

The "already opened" and "already clicked" steps are always generated
next to their prevention step. The frontend decides which to show from
the user's answer to its one question, going by the triggered_by names
that end in _ALREADY_OPENED and _ALREADY_CLICKED.
"""

from __future__ import annotations

# advisory_outputs.severity only allows these three values (see schema.sql)
_INFO = "INFO"
_WARNING = "WARNING"
_CRITICAL = "CRITICAL"


def build_advisory(
    verdict: dict,
    header_result: dict | None,
    url_results: list[dict],
    attachment_results: list[dict],
) -> list[dict]:
    """Returns ordered steps as {step_order, step_title, step_detail,
    severity, triggered_by}. Every scan gets at least one step. A SAFE
    result gets one too, because an empty panel looks like an error."""
    steps: list[dict] = []
    order = _Counter()

    malicious_attachments = [a for a in attachment_results if a.get("vt_status") == "MALICIOUS"]
    executable_attachments = [a for a in attachment_results if a.get("is_executable")]
    malicious_urls = [
        u for u in url_results
        if u.get("safe_browsing_status") in ("MALWARE", "SOCIAL_ENGINEERING")
        or u.get("urlscan_verdict") == "MALICIOUS"
    ]
    display_mismatch_urls = [u for u in url_results if u.get("display_mismatch")]
    auth_failed = bool(header_result) and any(
        header_result.get(f"{proto}_result") == "FAIL" for proto in ("spf", "dkim", "dmarc")
    )
    high_abuse_ip = bool(header_result) and (header_result.get("abuseipdb_confidence") or 0) >= 75
    display_name_spoof = bool(header_result) and header_result.get("display_name_spoof")

    # --- Don't open, don't click --------------------------------------

    if malicious_attachments:
        names = ", ".join(a["filename"] for a in malicious_attachments)
        steps.append(_step(
            order.next(), "Do not open the attachment",
            f"{names} was identified as malicious. Opening it could install "
            f"software that steals passwords or files from this computer. "
            f"Delete it from your Downloads folder if you already saved it.",
            _CRITICAL, "MALICIOUS_ATTACHMENT",
        ))
    elif executable_attachments:
        names = ", ".join(a["filename"] for a in executable_attachments)
        steps.append(_step(
            order.next(), "Do not run the attached program file",
            f"{names} is a program file (an executable). Legitimate invoices "
            f"and quotations are never sent as executables, so do not run it.",
            _WARNING, "EXECUTABLE_ATTACHMENT",
        ))

    if malicious_urls:
        steps.append(_step(
            order.next(), "Do not click any link in this email",
            "One or more links in this email were identified as malicious. "
            "Clicking them could take you to a fake login page or install "
            "malware on this computer.",
            _CRITICAL, "MALICIOUS_URL",
        ))

    # --- Containment (shown conditionally by the frontend) --------------

    if malicious_attachments:
        steps.append(_step(
            order.next(), "If you already opened the attachment, disconnect now",
            "Disconnect this computer from Wi-Fi or the network cable, run a "
            "full antivirus scan, and contact your IT contact before "
            "reconnecting.",
            _CRITICAL, "MALICIOUS_ATTACHMENT_ALREADY_OPENED",
        ))

    if malicious_urls:
        steps.append(_step(
            order.next(), "If you already clicked the link, change your passwords",
            "From a different device, change the password for any account "
            "you entered details into, and turn on two-factor authentication "
            "if it isn't already on.",
            _CRITICAL, "MALICIOUS_URL_ALREADY_CLICKED",
        ))

    # --- Check the sender -------------------------------------------------

    if display_mismatch_urls:
        steps.append(_step(
            order.next(), "Treat mismatched links with suspicion",
            "This email contains a link whose visible text names one website "
            "but actually leads somewhere else. This is a common impersonation "
            "technique.",
            _WARNING, "DISPLAY_MISMATCH",
        ))

    if auth_failed:
        steps.append(_step(
            order.next(), "Verify the sender before acting on this email",
            "This email did not fully pass SPF, DKIM or DMARC, the checks that "
            "confirm an email really came from the address it claims. The "
            "sender's address may be forged. Verify by phoning a number you "
            "already have on file, not one written in this email.",
            _WARNING, "AUTH_FAIL",
        ))

    if high_abuse_ip:
        confidence = header_result.get("abuseipdb_confidence")
        steps.append(_step(
            order.next(), "Be aware of this email's origin",
            f"This email came from a server with a history of abuse reports "
            f"({confidence}% abuse confidence score on AbuseIPDB).",
            _WARNING, "HIGH_ABUSE_IP",
        ))

    if display_name_spoof:
        steps.append(_step(
            order.next(), "Confirm requests through a known contact channel",
            "The sender's display name doesn't match its actual address. This "
            "is a common way of impersonating a trusted supplier or colleague. "
            "Confirm any request through your existing contact details "
            "before acting on it.",
            _WARNING, "DISPLAY_NAME_SPOOF",
        ))

    # --- Overall verdict --------------------------------------------------

    risk_level = verdict.get("risk_level")
    if risk_level == "DANGEROUS":
        steps.append(_step(
            order.next(), "Report this email to your IT contact",
            "This email shows strong signs of phishing or malware. Report it "
            "to your IT contact and do not forward it to colleagues.",
            _CRITICAL, "DANGEROUS_VERDICT",
        ))
    elif risk_level == "SUSPICIOUS":
        steps.append(_step(
            order.next(), "Verify before acting on this email",
            "This email has some suspicious signals, but nothing conclusive. "
            "Do not act on any requests in it, such as payments, credentials "
            "or downloads, until you've verified the sender independently.",
            _WARNING, "SUSPICIOUS_VERDICT",
        ))
    else:
        steps.append(_step(
            order.next(), "No threats detected in this scan",
            "This scan did not find any known indicators of phishing or "
            "malware. This is not a guarantee the email is safe, so stay "
            "cautious with unexpected payment or credential requests, and "
            "report anything that feels off.",
            _INFO, "SAFE_VERDICT",
        ))

    return steps


def _step(step_order: int, title: str, detail: str, severity: str, triggered_by: str) -> dict:
    return {
        "step_order": step_order,
        "step_title": title,
        "step_detail": detail,
        "severity": severity,
        "triggered_by": triggered_by,
    }


class _Counter:
    def __init__(self):
        self._n = 0

    def next(self) -> int:
        self._n += 1
        return self._n
