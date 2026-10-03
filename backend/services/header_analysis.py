"""Header analysis: SPF/DKIM/DMARC, Reply-To and display-name spoofing,
and one live call to AbuseIPDB for the sender IP that eml_parser found.
"""

from __future__ import annotations

import config
from api_clients import abuseipdb
from services.signals import make_signal
from utils.exceptions import ProviderError, ProviderTimeout
from utils.logger import get_logger

logger = get_logger(__name__)

W = config.RISK_WEIGHTS


def analyze_headers(headers: dict, scan_id: str | None = None) -> dict:
    """headers is the headers dict from services.eml_parser.parse_eml().

    Returns {"header_result": dict, "signals": [...], "provider_status": {"ABUSEIPDB": ...}}.
    """
    signals = []
    # eml_parser's keys (from/to/date) differ from the database columns
    # (from_address/to_address/date_header). Map them here, because this
    # dict is what gets saved and what the frontend shows as header_result.
    result = {
        **headers,
        "from_address": headers.get("from"),
        "to_address": headers.get("to"),
        "date_header": headers.get("date"),
    }
    provider_status = {"ABUSEIPDB": "UNAVAILABLE"}

    spf = headers.get("spf_result", "NONE")
    dkim = headers.get("dkim_result", "NONE")
    dmarc = headers.get("dmarc_result", "NONE")

    if spf == "FAIL":
        signals.append(make_signal(
            "headers", "SPF_FAIL", W["SPF_FAIL"],
            "The sender's domain did not pass SPF, a check that confirms an "
            "email really came from a server the domain owner authorised.",
            {"spf_result": spf}, severity="HIGH",
        ))
    if dkim == "FAIL":
        signals.append(make_signal(
            "headers", "DKIM_FAIL", W["DKIM_FAIL"],
            "The email's DKIM signature did not verify, meaning its content "
            "or sender may have been altered or forged in transit.",
            {"dkim_result": dkim}, severity="HIGH",
        ))
    if dmarc == "FAIL":
        signals.append(make_signal(
            "headers", "DMARC_FAIL", W["DMARC_FAIL"],
            "The email failed DMARC, the policy check that ties SPF and DKIM "
            "together. This is a strong sign the sending address is not genuine.",
            {"dmarc_result": dmarc}, severity="HIGH",
        ))
    if spf == "NONE" and dkim == "NONE" and dmarc == "NONE":
        signals.append(make_signal(
            "headers", "ALL_AUTH_ABSENT", W["ALL_AUTH_ABSENT"],
            "No SPF, DKIM or DMARC results were present to check at all. "
            "This alone doesn't mean the email is fake, but it removes a "
            "layer of verification.",
            {}, severity="LOW",
        ))

    if headers.get("reply_to_mismatch"):
        signals.append(make_signal(
            "headers", "REPLY_TO_MISMATCH", W["REPLY_TO_MISMATCH"],
            "Replies to this email would go to a different domain than the "
            "one it claims to be from. This is a common redirection trick.",
            {"from": headers.get("from"), "reply_to": headers.get("reply_to")},
            severity="HIGH",
        ))
    if headers.get("display_name_spoof"):
        signals.append(make_signal(
            "headers", "DISPLAY_NAME_SPOOF", W["DISPLAY_NAME_SPOOF"],
            "The sender's display name doesn't match its actual address. For "
            "example, a name that looks like a known brand sent from an "
            "unrelated domain.",
            {"from": headers.get("from")}, severity="HIGH",
        ))

    sender_ip = headers.get("sender_ip")
    if sender_ip and headers.get("sender_ip_status") == "AVAILABLE":
        try:
            abuse = abuseipdb.check_ip(sender_ip, scan_id=scan_id)
            provider_status["ABUSEIPDB"] = "AVAILABLE"
            result["abuseipdb_confidence"] = abuse["confidence_score"]
            result["abuseipdb_reports"] = abuse["total_reports"]
            result["abuseipdb_country"] = abuse["country_code"]

            confidence = abuse["confidence_score"]
            evidence = {
                "ip": sender_ip,
                "confidence_score": confidence,
                "total_reports": abuse["total_reports"],
                "country_code": abuse["country_code"],
            }
            if confidence >= 75:
                signals.append(make_signal(
                    "headers", "ABUSEIPDB_75_100", W["ABUSEIPDB_75_100"],
                    f"This email came from a server with a {confidence}% abuse "
                    f"confidence score on AbuseIPDB, based on "
                    f"{abuse['total_reports']} reports from other users.",
                    evidence, severity="CRITICAL",
                ))
            elif confidence >= 40:
                signals.append(make_signal(
                    "headers", "ABUSEIPDB_40_74", W["ABUSEIPDB_40_74"],
                    f"The sending server has a moderate abuse history on "
                    f"AbuseIPDB ({confidence}% confidence score).",
                    evidence, severity="MEDIUM",
                ))
            elif confidence >= 15:
                signals.append(make_signal(
                    "headers", "ABUSEIPDB_15_39", W["ABUSEIPDB_15_39"],
                    f"The sending server has a small number of abuse reports "
                    f"on AbuseIPDB ({confidence}% confidence score).",
                    evidence, severity="LOW",
                ))
        except (ProviderError, ProviderTimeout) as exc:
            logger.warning("AbuseIPDB unavailable for %s: %s", sender_ip, exc)
            provider_status["ABUSEIPDB"] = "UNAVAILABLE"
    else:
        # No public sender IP, so there was nothing to look up. That isn't
        # a provider failure and shouldn't mark the scan as partial.
        provider_status["ABUSEIPDB"] = "AVAILABLE"

    return {"header_result": result, "signals": signals, "provider_status": provider_status}
