"""Generate the .eml test samples in docs/test-samples/.

Usage:
    python -m scripts.generate_test_samples

Writes to docs/test-samples/ in the repo root. Safe to re-run: every file
is rebuilt from scratch, so this script is the source of the fixtures and
nobody has to hand-edit them.

The samples are grouped by the signal each one should raise (see
config.RISK_WEIGHTS). Samples 01-15 and 18-19 only need the parser, so
they score the same with or without internet access. Samples 16 and 17
need a live provider to answer. docs/test-samples/README.md has the full
table and the two signals that can't be produced as a fixture.
"""

from __future__ import annotations

import base64
import io
import os
import zipfile
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import py7zr

OUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "docs", "test-samples",
)

EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# A minimal DOS/PE stub: enough for the magic-byte check to report "exe",
# and not a runnable program.
MZ_STUB = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 48

# Google's public Safe Browsing test page. Whether the v4 API flags it is
# up to Google and can change, so check sample 17 on the day instead of
# counting on it.
SAFE_BROWSING_TEST_URL = "http://testsafebrowsing.appspot.com/s/phishing.html"

PASS_AUTH = "spf=pass smtp.mailfrom=supplier-example.com; dkim=pass header.d=supplier-example.com; dmarc=pass"
FAIL_AUTH = "spf=fail smtp.mailfrom=supplier-example.com; dkim=fail; dmarc=fail"

RECEIVED_CHAIN = [
    "from mail.internal.corp (mail.internal.corp [10.0.0.5]) "
    "by mx.recipientmail.com with ESMTP id abc123; " + formatdate(),
    # 93.184.216.34 was example.com's address for years. It's a real public
    # IP. The 203.0.113.0/24 documentation range won't do here, because the
    # parser skips it as non-public.
    "from mx-relay.sender.com (mx-relay.sender.com [93.184.216.34]) "
    "by mail.internal.corp with ESMTP id def456; " + formatdate(),
]

NO_ORIGIN_RECEIVED_CHAIN = [
    "from mail.internal.corp (mail.internal.corp [10.0.0.5]) "
    "by mx.recipientmail.com with ESMTP id abc123; " + formatdate(),
]


# ---------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------


def _base_message(
    subject: str,
    from_addr: str,
    to_addr: str = "clerk@qrsolution.com.my",
    received: list[str] | None = RECEIVED_CHAIN,
    auth_results: str | None = PASS_AUTH,
    reply_to: str | None = None,
) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Date"] = formatdate()
    msg["Message-ID"] = make_msgid()
    if reply_to:
        msg["Reply-To"] = reply_to
    if auth_results:
        msg["Authentication-Results"] = auth_results
    for header in (received or []):
        msg["Received"] = header  # each call adds one more Received header
    return msg


def _html_link_message(msg: EmailMessage, intro: str, anchor_text: str, href: str) -> EmailMessage:
    """Attach a plain-text part and an HTML part carrying one link, so the
    parser's HTML path (anchor text vs href) is the one exercised."""
    msg.set_content(f"{intro}\n\n{href}\n")
    msg.add_alternative(
        f"<html><body><p>{intro}</p>"
        f'<p><a href="{href}">{anchor_text}</a></p></body></html>',
        subtype="html",
    )
    return msg


def _encrypted_zip(filename: str = "invoice.pdf", content: bytes = b"%PDF-1.4 placeholder") -> bytes:
    """A real ZIP with the standard PKZIP encryption bit (bit 0) set in both
    the local file header and the central directory record. stdlib zipfile
    can read encrypted entries but not write them, so the bit is flipped in
    the raw bytes after a normal write. eml_parser only ever reads the flag,
    never the (would-be encrypted) content; this is the same construction
    the unit tests use."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr(filename, content)
    raw = bytearray(buffer.getvalue())

    idx = raw.find(b"PK\x03\x04")
    raw[idx + 6] |= 0x1  # general purpose bit flag, 2 bytes at offset 6
    idx = raw.find(b"PK\x01\x02")
    raw[idx + 8] |= 0x1  # general purpose bit flag, 2 bytes at offset 8 here
    return bytes(raw)


def _encrypted_7z(password: str = "invoice2026") -> bytes:
    buffer = io.BytesIO()
    with py7zr.SevenZipFile(buffer, "w", password=password) as archive:
        archive.writestr(b"%PDF-1.4 placeholder", "invoice.pdf")
    return buffer.getvalue()


# ---------------------------------------------------------------------
# Samples: clean baselines
# ---------------------------------------------------------------------


def sample_01_clean_no_links() -> EmailMessage:
    """Expected SAFE, score 0. Every signal absent."""
    msg = _base_message(
        subject="Quotation approved: QR-2026-0143",
        from_addr="Siti Rahman <siti@supplier-example.com>",
    )
    msg.set_content(
        "Hi,\n\nThe quotation for the Klang warehouse job is approved. "
        "Works can start on Monday as planned.\n\nRegards,\nSiti\n"
    )
    return msg


def sample_02_clean_with_link() -> EmailMessage:
    """Expected SAFE, score 0. A plain, matching link raises nothing.

    The link points at example.com because urlscan.io refuses to visit
    blocklisted domains (Google's among them) and domains that do not
    resolve, answering 400 either way. example.com is registered, resolves,
    and is accepted, so this is the one sample where the live sandbox check
    actually runs and comes back CLEAN.
    """
    msg = _base_message(
        subject="Site photos for week 6",
        from_addr="Azman <azman@supplier-example.com>",
    )
    return _html_link_message(
        msg,
        "The site photos for week 6 are in the shared folder.",
        "https://example.com/shared/week6",
        "https://example.com/shared/week6",
    )


# ---------------------------------------------------------------------
# Samples: header signals
# ---------------------------------------------------------------------


def sample_03_no_auth_headers() -> EmailMessage:
    """ALL_AUTH_ABSENT (+10). Expected SAFE: absent checks are a small
    deduction, not an accusation."""
    msg = _base_message(
        subject="Delivery order 8891",
        from_addr="Store <store@supplier-example.com>",
        auth_results=None,
    )
    msg.set_content("Delivery order 8891 has been dispatched.\n")
    return msg


def sample_04_auth_fail_all() -> EmailMessage:
    """SPF_FAIL (+20), DKIM_FAIL (+20), DMARC_FAIL (+25) = 65.
    Expected DANGEROUS on arithmetic alone."""
    msg = _base_message(
        subject="Updated payment instructions",
        from_addr="Accounts <accounts@supplier-example.com>",
        auth_results=FAIL_AUTH,
    )
    msg.set_content(
        "Please note our bank details have changed. Use the new account "
        "for all outstanding invoices.\n"
    )
    return msg


def sample_05_reply_to_mismatch() -> EmailMessage:
    """REPLY_TO_MISMATCH (+20). Expected SAFE by score, but the finding is
    listed; replies would leave the sender's domain."""
    msg = _base_message(
        subject="Re: Invoice INV-2026-0088",
        from_addr="Accounts <accounts@supplier-example.com>",
        reply_to="accounts.payable@gmail-secure.example",
    )
    msg.set_content("Please confirm receipt of the attached statement.\n")
    return msg


def sample_06_display_name_spoof() -> EmailMessage:
    """DISPLAY_NAME_SPOOF (+25). Expected SUSPICIOUS. The display name
    carries a brand the real address has nothing to do with."""
    msg = _base_message(
        subject="Your PayPal account needs attention",
        from_addr='"PayPal Service" <no-reply@billing-notice.example>',
    )
    msg.set_content(
        "We could not confirm a recent payment on your account. "
        "Please review it at your earliest convenience.\n"
    )
    return msg


# ---------------------------------------------------------------------
# Samples: URL signals
# ---------------------------------------------------------------------


def sample_07_link_display_mismatch() -> EmailMessage:
    """DISPLAY_MISMATCH (+25). Expected SUSPICIOUS. Also the sample the
    end-to-end test forces a Safe Browsing hit against."""
    msg = _base_message(
        subject="Action required: verify your account",
        from_addr="Notices <notices@supplier-example.com>",
    )
    return _html_link_message(
        msg,
        "Your account needs to be verified before Friday.",
        "https://www.maybank2u.com.my/login",
        "http://secure-verify.example/session/maybank2u",
    )


def sample_08_link_shortener() -> EmailMessage:
    """SHORTENER (+10). Expected SAFE by score; the destination is hidden
    until clicked, which is the point of the finding."""
    msg = _base_message(
        subject="Invoice payment link",
        from_addr="Billing <billing@supplier-example.com>",
    )
    return _html_link_message(
        msg,
        "You can settle the invoice using the link below.",
        "Pay invoice",
        "https://bit.ly/3xInv0ice",
    )


def sample_09_link_raw_ip() -> EmailMessage:
    """RAW_IP_HOST (+20). Expected SAFE by score. Legitimate businesses
    rarely link to a bare IP address."""
    msg = _base_message(
        subject="Document ready for download",
        from_addr="Docs <docs@supplier-example.com>",
    )
    return _html_link_message(
        msg,
        "Your document is ready.",
        "Download document",
        "http://93.184.216.34/invoice/download",
    )


def sample_10_link_punycode() -> EmailMessage:
    """PUNYCODE (+25). Expected SUSPICIOUS. xn--pypal-4ve.com renders as a
    lookalike of a well-known brand."""
    msg = _base_message(
        subject="Confirm your details",
        from_addr="Support <support@supplier-example.com>",
    )
    return _html_link_message(
        msg,
        "Please confirm your details to keep your account active.",
        "Confirm now",
        "https://xn--pypal-4ve.com/verify",
    )


# ---------------------------------------------------------------------
# Samples: attachment signals
# ---------------------------------------------------------------------


def sample_11_attachment_extension_mismatch() -> EmailMessage:
    """EXTENSION_MISMATCH (+35). Expected SUSPICIOUS. Named .pdf, but its
    magic bytes say it is an executable."""
    msg = _base_message(
        subject="Invoice attached",
        from_addr="Billing <billing@supplier-example.com>",
    )
    msg.set_content("The invoice is attached.\n")
    msg.add_attachment(
        MZ_STUB, maintype="application", subtype="pdf", filename="Invoice_2026_0143.pdf"
    )
    return msg


def sample_12_attachment_executable() -> EmailMessage:
    """EXECUTABLE_TYPE (+30) and the EXECUTABLE_ATTACHMENT override, which
    holds the verdict at SUSPICIOUS even on a low score."""
    msg = _base_message(
        subject="Please install the updated viewer",
        from_addr="IT Support <it@supplier-example.com>",
    )
    msg.set_content("Run the attached tool to open the new invoice format.\n")
    msg.add_attachment(
        MZ_STUB,
        maintype="application",
        subtype="octet-stream",
        filename="Invoice_Viewer_Setup.exe",
    )
    return msg


def sample_13_attachment_password_zip() -> EmailMessage:
    """PASSWORD_PROTECTED_ARCHIVE (+20) via the ZIP encryption flag."""
    msg = _base_message(
        subject="Statement (password in separate message)",
        from_addr="Accounts <accounts@supplier-example.com>",
    )
    msg.set_content("The password follows in a separate email.\n")
    msg.add_attachment(
        _encrypted_zip(), maintype="application", subtype="zip", filename="Statement.zip"
    )
    return msg


def sample_14_attachment_password_7z() -> EmailMessage:
    """PASSWORD_PROTECTED_ARCHIVE (+20) via py7zr, a genuinely encrypted
    7z archive."""
    msg = _base_message(
        subject="Contract documents",
        from_addr="Legal <legal@supplier-example.com>",
    )
    msg.set_content("Contract documents attached, password as agreed.\n")
    msg.add_attachment(
        _encrypted_7z(), maintype="application", subtype="x-7z-compressed", filename="Contract.7z"
    )
    return msg


# ---------------------------------------------------------------------
# Samples: combinations and provider-dependent cases
# ---------------------------------------------------------------------


def sample_15_multi_signal_phishing() -> EmailMessage:
    """A realistic invoice-fraud message stacking six offline signals:
    SPF_FAIL, DKIM_FAIL, DMARC_FAIL, REPLY_TO_MISMATCH, DISPLAY_NAME_SPOOF
    and DISPLAY_MISMATCH. Expected DANGEROUS with no provider needed; the
    best sample for a screenshot of a full report."""
    msg = _base_message(
        subject="URGENT: overdue invoice INV-2026-0177",
        from_addr='"Microsoft Billing" <ar@invoice-settlement.example>',
        auth_results=FAIL_AUTH,
        reply_to="remittance@payments-desk.example",
    )
    return _html_link_message(
        msg,
        "Our records show invoice INV-2026-0177 is overdue. Settle it today "
        "to avoid suspension of works.",
        "https://portal.microsoft.com/invoice",
        "http://invoice-settlement.example/pay/0177",
    )


def sample_16_eicar_malware() -> EmailMessage:
    """VT_MALICIOUS_HIGH (+60) and the VT_MALICIOUS_THRESHOLD override,
    plus EXECUTABLE_TYPE (+30) and the three auth failures. Expected
    DANGEROUS, score 100; needs VirusTotal reachable.

    Written base64-wrapped (see write_base64): a plain .eml carrying EICAR
    cannot survive on disk on a machine with real-time antivirus."""
    msg = _base_message(
        subject="Urgent: overdue invoice attached",
        from_addr='"Accounts Payable" <billing@supplier-example.com>',
        auth_results=FAIL_AUTH,
        reply_to="payments@another-domain.example",
    )
    msg.set_content("Please settle the attached invoice today.\n")
    msg.add_attachment(
        EICAR.encode("ascii"),
        maintype="application",
        subtype="octet-stream",
        filename="invoice.pdf.exe",
    )
    return msg


def sample_17_safe_browsing_phishing() -> EmailMessage:
    """SAFE_BROWSING_MALWARE_SOCIAL (+55) and its override; needs Google
    Safe Browsing reachable, and needs Google to still be listing its own
    test page. Verify the verdict on the day rather than assuming it."""
    msg = _base_message(
        subject="Mailbox storage full",
        from_addr="Mail Admin <admin@supplier-example.com>",
    )
    return _html_link_message(
        msg,
        "Your mailbox is full. Re-validate your account to keep receiving mail.",
        "Re-validate mailbox",
        SAFE_BROWSING_TEST_URL,
    )


def sample_19_no_received_headers() -> EmailMessage:
    """No public sender IP, so AbuseIPDB is skipped rather than failed.
    Exercises sender_ip_status = UNAVAILABLE."""
    msg = _base_message(
        subject="Saved message with no delivery chain",
        from_addr="Sender <sender@supplier-example.com>",
        received=None,
        auth_results=None,
    )
    msg.set_content("This message has no Received headers, as if saved directly to disk.\n")
    return msg


# ---------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------


def write(msg: EmailMessage, filename: str) -> None:
    path = os.path.join(OUT_DIR, filename)
    with open(path, "wb") as f:
        f.write(bytes(msg))
    print(f"wrote {path}")


def write_base64(msg: EmailMessage, filename: str) -> None:
    """Write a base64-wrapped copy of an EICAR-bearing email.

    A plain .eml containing EICAR cannot survive on disk on a machine with
    real-time antivirus: Windows Defender detects the signature inside the
    MIME part on write, deletes the attachment and substitutes a notice, so
    the committed fixture silently stops being an EICAR test. Wrapping the
    whole message in one more layer of base64 makes it opaque to that scan,
    so the fixture survives in the repository intact.

    This mirrors how eicar.org itself distributes the test file: as
    eicar_com.zip and eicarcom2.zip rather than only as a bare eicar.com.
    Decode it with scripts/materialise_eicar.py when you need the real
    message.
    """
    path = os.path.join(OUT_DIR, filename)
    encoded = base64.b64encode(bytes(msg))
    with open(path, "wb") as f:
        f.write(b"# Base64-wrapped EICAR test email. See docs/test-samples/README.md\n")
        f.write(b"# Decode with: python -m scripts.materialise_eicar\n")
        for i in range(0, len(encoded), 76):
            f.write(encoded[i:i + 76] + b"\n")
    print(f"wrote {path}")


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)

    write(sample_01_clean_no_links(), "01_clean_no_links.eml")
    write(sample_02_clean_with_link(), "02_clean_with_link.eml")
    write(sample_03_no_auth_headers(), "03_no_auth_headers.eml")
    write(sample_04_auth_fail_all(), "04_auth_fail_all.eml")
    write(sample_05_reply_to_mismatch(), "05_reply_to_mismatch.eml")
    write(sample_06_display_name_spoof(), "06_display_name_spoof.eml")
    write(sample_07_link_display_mismatch(), "07_link_display_mismatch.eml")
    write(sample_08_link_shortener(), "08_link_shortener.eml")
    write(sample_09_link_raw_ip(), "09_link_raw_ip.eml")
    write(sample_10_link_punycode(), "10_link_punycode.eml")
    write(sample_11_attachment_extension_mismatch(), "11_attachment_extension_mismatch.eml")
    write(sample_12_attachment_executable(), "12_attachment_executable.eml")
    write(sample_13_attachment_password_zip(), "13_attachment_password_zip.eml")
    write(sample_14_attachment_password_7z(), "14_attachment_password_7z.eml")
    write(sample_15_multi_signal_phishing(), "15_multi_signal_phishing.eml")

    # 16 is written base64-wrapped, not as a plain .eml, so local antivirus
    # can't strip it.
    write_base64(sample_16_eicar_malware(), "16_eicar_malware.eml.b64")

    write(sample_17_safe_browsing_phishing(), "17_safe_browsing_phishing.eml")

    # 18: a malformed file that should be rejected. It's binary garbage
    # with a .eml extension, not an email at all.
    malformed_path = os.path.join(OUT_DIR, "18_malformed.eml")
    with open(malformed_path, "wb") as f:
        f.write(b"\x00\x01\x02NOT AN EMAIL FILE\xff\xfe" * 10)
    print(f"wrote {malformed_path}")

    write(sample_19_no_received_headers(), "19_no_received_headers.eml")


if __name__ == "__main__":
    main()
