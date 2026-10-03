"""Attachment analysis: VirusTotal (hash lookup first, upload only when
the hash is unknown) plus the extension and executable checks eml_parser
already ran.

VirusTotal's free tier (4 requests a minute, 500 a day) is the tightest
limit in the system. Don't scan attachments in parallel: one attachment
can already cost a lookup, an upload and VIRUSTOTAL_ANALYSIS_MAX_POLLS
polls.
"""

from __future__ import annotations

import time

import config
from api_clients import virustotal
from services.signals import make_signal
from utils.exceptions import ProviderError, ProviderTimeout
from utils.logger import get_logger

logger = get_logger(__name__)

W = config.RISK_WEIGHTS


def scan_attachments(attachments: list[dict], scan_id: str | None = None) -> dict:
    """attachments is the list from eml_parser.parse_eml(). Each entry has
    a payload_bytes key, used for the upload and never saved.

    Returns {"attachment_results": [...], "signals": [...], "provider_status": {"VIRUSTOTAL": ...}}.
    """
    if not attachments:
        return {
            "attachment_results": [],
            "signals": [],
            "provider_status": {"VIRUSTOTAL": "AVAILABLE"},
        }

    signals = []
    enriched = []
    attempted = False
    any_success = False
    upload_deadline = time.monotonic() + config.VIRUSTOTAL_UPLOAD_TIME_BUDGET_SECONDS

    for attachment in attachments:
        entry = {k: v for k, v in attachment.items() if k != "payload_bytes"}
        attempted = True

        try:
            report = _get_or_submit_report(
                attachment, scan_id, allow_upload=time.monotonic() < upload_deadline
            )
            if report is None:
                entry["vt_status"] = "UNAVAILABLE"
            else:
                any_success = True
                _apply_vt_report(entry, report, signals)
        except (ProviderError, ProviderTimeout) as exc:
            logger.warning("VirusTotal unavailable for %s: %s", attachment["filename"], exc)
            entry["vt_status"] = "UNAVAILABLE"

        if entry.get("extension_mismatch"):
            signals.append(make_signal(
                "attachment", "EXTENSION_MISMATCH", W["EXTENSION_MISMATCH"],
                f"{entry['filename']}'s actual file type doesn't match its "
                f"extension. This is a common way to disguise an executable as "
                f"a harmless document.",
                {"filename": entry["filename"], "detected_type": entry.get("detected_file_type")},
                severity="HIGH",
            ))
        if entry.get("is_executable"):
            signals.append(make_signal(
                "attachment", "EXECUTABLE_TYPE", W["EXECUTABLE_TYPE"],
                f"{entry['filename']} is a program file. Legitimate invoices "
                f"and quotations are never sent as executables.",
                {"filename": entry["filename"]}, severity="HIGH",
            ))
        if entry.get("is_password_protected"):
            signals.append(make_signal(
                "attachment", "PASSWORD_PROTECTED_ARCHIVE", W["PASSWORD_PROTECTED_ARCHIVE"],
                f"{entry['filename']} is a password-protected archive. "
                f"Attackers often use this to hide malware from antivirus "
                f"scanning, since the scanner can't look inside without "
                f"the password.",
                {"filename": entry["filename"]}, severity="MEDIUM",
            ))
        if entry.get("has_macros"):
            signals.append(make_signal(
                "attachment", "MACRO_ENABLED_DOCUMENT", W["MACRO_ENABLED_DOCUMENT"],
                f"{entry['filename']} contains macros, which is embedded code "
                f"that can run automatically when the file is opened. This is one "
                f"of the most common ways malware is delivered through "
                f"Office documents.",
                {"filename": entry["filename"]}, severity="MEDIUM",
            ))

        enriched.append(entry)

    provider_status = {"VIRUSTOTAL": "AVAILABLE" if any_success or not attempted else "UNAVAILABLE"}
    return {"attachment_results": enriched, "signals": signals, "provider_status": provider_status}


def _get_or_submit_report(
    attachment: dict, scan_id: str | None, allow_upload: bool = True
) -> dict | None:
    """Look the hash up first, and upload only if VirusTotal has never seen
    it. Returns None when there is no result: the upload was skipped
    because the time budget ran out, or the analysis did not finish in
    time. The caller marks the attachment UNAVAILABLE in both cases."""
    report = virustotal.get_file_report(attachment["sha256"], scan_id=scan_id)
    if report is not None or not allow_upload:
        return report

    analysis_id = virustotal.upload_file(
        attachment.get("payload_bytes", b""), attachment["filename"], scan_id=scan_id
    )

    for poll in range(config.VIRUSTOTAL_ANALYSIS_MAX_POLLS):
        analysis = virustotal.get_analysis(analysis_id, scan_id=scan_id)
        if analysis["status"] == "completed":
            return analysis
        # No point waiting after the last poll; the answer is already no.
        if poll < config.VIRUSTOTAL_ANALYSIS_MAX_POLLS - 1:
            time.sleep(config.VIRUSTOTAL_ANALYSIS_POLL_INTERVAL)

    return None


def _apply_vt_report(entry: dict, report: dict, signals: list[dict]) -> None:
    malicious = report.get("malicious", 0)
    suspicious = report.get("suspicious", 0)
    total = malicious + suspicious + report.get("undetected", 0) + report.get("harmless", 0)

    entry["vt_malicious_count"] = malicious
    entry["vt_suspicious_count"] = suspicious
    entry["vt_total_engines"] = total
    entry["vt_threat_label"] = report.get("threat_label")

    evidence = {"filename": entry["filename"], "malicious": malicious, "total": total}

    if malicious >= 5:
        entry["vt_status"] = "MALICIOUS"
        signals.append(make_signal(
            "attachment", "VT_MALICIOUS_HIGH", W["VT_MALICIOUS_HIGH"],
            f"{malicious} of {total} antivirus engines identified "
            f"{entry['filename']} as malicious"
            + (f" ({report['threat_label']})." if report.get("threat_label") else "."),
            evidence, severity="CRITICAL",
        ))
    elif malicious >= 1:
        entry["vt_status"] = "MALICIOUS"
        signals.append(make_signal(
            "attachment", "VT_MALICIOUS_LOW", W["VT_MALICIOUS_LOW"],
            f"{malicious} of {total} antivirus engines identified "
            f"{entry['filename']} as malicious.",
            evidence, severity="HIGH",
        ))
    elif suspicious > 0:
        entry["vt_status"] = "SUSPICIOUS"
        signals.append(make_signal(
            "attachment", "VT_SUSPICIOUS_ONLY", W["VT_SUSPICIOUS_ONLY"],
            f"{suspicious} of {total} antivirus engines flagged "
            f"{entry['filename']} as suspicious, without a majority calling "
            f"it outright malicious.",
            evidence, severity="MEDIUM",
        ))
    else:
        entry["vt_status"] = "CLEAN"
