"""Offline .eml parsing: headers, authentication results, sender IP, URLs
and attachments. No external API calls.

Attachments are never opened or run, URLs are never followed, and HTML
bodies are never rendered. This module only reads bytes.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import re
import zipfile
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

import py7zr
from bs4 import BeautifulSoup
from oletools.olevba import VBA_Parser

import config
from utils.exceptions import ParsingError
from utils.logger import get_logger

logger = get_logger(__name__)

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
# Punctuation that ends a sentence rather than a URL, as in
# "see https://example.com/page." or "(https://example.com)".
_URL_TRAILING_PUNCT = ".,;:!?)]}'\""
_DOMAIN_LIKE_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE
)
_BRAND_KEYWORDS = (
    "paypal", "microsoft", "apple", "amazon", "docusign", "dhl", "fedex",
    "bank", "netflix", "google", "office365", "outlook",
)

_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),  # docx, xlsx, pptx, zip all share this signature
    (b"MZ", "exe"),
]

_EXTENSION_TYPE_GROUPS: dict[str, str] = {
    ".pdf": "pdf",
    ".docx": "zip", ".xlsx": "zip", ".pptx": "zip", ".zip": "zip",
    ".exe": "exe", ".scr": "exe", ".dll": "exe",
}

# Old OLE2 formats (.doc/.xls/.ppt) and macro-enabled OOXML
# (.docm/.xlsm/.pptm/...) can carry VBA macros. Plain .docx/.xlsx/.pptx
# can't.
_MACRO_CAPABLE_EXTENSIONS = {
    ".doc", ".xls", ".ppt",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
}


_INVALID_EML_MESSAGE = (
    "That file isn't a valid .eml email file. In Outlook, Gmail or Yahoo, "
    "save the message as .eml and try again."
)


def parse_eml(path: str) -> dict:
    """Parse a .eml file from disk.

    Uploads don't go through this, since they never touch the disk. It's
    for the test fixtures in docs/test-samples/ and command-line use.
    """
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as exc:
        raise ParsingError(_INVALID_EML_MESSAGE, code="PARSING_ERROR") from exc
    return parse_eml_bytes(raw)


def parse_eml_bytes(raw: bytes) -> dict:
    """Parse raw .eml bytes into headers, urls, attachments and body_text.

    This takes bytes, not a path, on purpose. Uploads used to be saved to
    disk first, and on a machine with real-time antivirus that failed
    twice over. The antivirus locked the file as soon as it saw a known
    signature, so reading it failed and the email was reported as
    malformed. Then deleting it failed too and the file was left behind.
    Keeping the upload in memory means there is no file at all.

    Raises ParsingError if the bytes can't be parsed as an email.
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        raise ParsingError(_INVALID_EML_MESSAGE, code="PARSING_ERROR") from exc

    # BytesParser is lenient and rarely raises on garbage. It returns a
    # message with no headers and a list of defects instead, so check for
    # that here and reject the file.
    if not msg.keys() or msg.defects:
        raise ParsingError(_INVALID_EML_MESSAGE, code="PARSING_ERROR")

    headers = _extract_headers(msg)
    body_text, html_parts, text_parts = _extract_bodies(msg)
    urls = _extract_urls(html_parts, text_parts)
    attachments = _extract_attachments(msg)

    return {
        "headers": headers,
        "urls": urls,
        "attachments": attachments,
        "body_text": body_text,
    }


# ---------------------------------------------------------------------
# Headers and authentication
# ---------------------------------------------------------------------


def _extract_headers(msg: Message) -> dict:
    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To")
    received_headers = msg.get_all("Received", [])

    auth = _extract_auth_results(msg)
    sender_ip, sender_ip_status = _extract_sender_ip(received_headers)

    return {
        "from": from_header,
        "to": msg.get("To"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "reply_to": reply_to,
        "return_path": msg.get("Return-Path"),
        "message_id": msg.get("Message-ID"),
        "received": [str(h) for h in received_headers],
        "spf_result": auth["spf_result"],
        "dkim_result": auth["dkim_result"],
        "dmarc_result": auth["dmarc_result"],
        "reply_to_mismatch": _reply_to_mismatch(from_header, reply_to),
        "display_name_spoof": _display_name_spoof(from_header),
        "sender_ip": sender_ip,
        "sender_ip_status": sender_ip_status,
    }


# Header result words mapped to the values schema.sql allows for each
# column. Anything not listed becomes NONE: temperror, permerror, policy,
# and Outlook's bestguesspass, which means the domain publishes no DMARC
# record, so no DMARC check actually ran.
_AUTH_RESULT_MAP: dict[str, dict[str, str]] = {
    "spf_result": {"PASS": "PASS", "FAIL": "FAIL", "HARDFAIL": "FAIL",
                   "SOFTFAIL": "SOFTFAIL", "NEUTRAL": "NEUTRAL"},
    "dkim_result": {"PASS": "PASS", "FAIL": "FAIL", "HARDFAIL": "FAIL", "SOFTFAIL": "FAIL"},
    "dmarc_result": {"PASS": "PASS", "FAIL": "FAIL", "HARDFAIL": "FAIL", "SOFTFAIL": "FAIL"},
}


def _normalise_auth_result(key: str, word: str) -> str:
    return _AUTH_RESULT_MAP[key].get(word.upper(), "NONE")


def _extract_auth_results(msg: Message) -> dict:
    """Use Authentication-Results if present, then Received-SPF, else NONE."""
    result = {"spf_result": "NONE", "dkim_result": "NONE", "dmarc_result": "NONE"}

    auth_header = msg.get("Authentication-Results")
    if auth_header:
        for key, field in (("spf_result", "spf"), ("dkim_result", "dkim"), ("dmarc_result", "dmarc")):
            m = re.search(rf"{field}=(\w+)", auth_header, re.IGNORECASE)
            if m:
                result[key] = _normalise_auth_result(key, m.group(1))
        return result

    received_spf = msg.get("Received-SPF")
    if received_spf:
        m = re.match(r"^\s*(\w+)", received_spf)
        if m:
            result["spf_result"] = _normalise_auth_result("spf_result", m.group(1))

    return result


def _reply_to_mismatch(from_header: str, reply_to: str | None) -> bool:
    if not reply_to:
        return False
    from_domain = _extract_domain(from_header)
    reply_domain = _extract_domain(reply_to)
    if not from_domain or not reply_domain:
        return False
    return from_domain.lower() != reply_domain.lower()


def _display_name_spoof(from_header: str) -> bool:
    """True when the display name carries a brand, or an address of its
    own, that the real From address does not match."""
    if not from_header:
        return False

    display_name, actual_address = parseaddr(from_header)
    display_name = display_name.strip()
    actual_domain = _extract_domain(from_header) or ""

    if not display_name:
        return False

    # An address written into the display name that isn't the real one.
    embedded = re.search(r"[\w.+-]+@[\w.-]+", display_name)
    if embedded and embedded.group(0).lower() != actual_address.lower():
        return True

    lowered = display_name.lower()
    for brand in _BRAND_KEYWORDS:
        if brand in lowered and brand not in actual_domain.lower():
            return True

    return False


def _extract_domain(address_header: str) -> str | None:
    """Domain of the real address in a header such as From or Reply-To.

    parseaddr reads the address inside the angle brackets, so an address
    typed into the display name ("support@paypal.com" <x@evil.example>)
    is not mistaken for the sender's.
    """
    _, address = parseaddr(address_header or "")
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower() or None


def _extract_sender_ip(received_headers: list) -> tuple[str | None, str]:
    """The earliest hop is the origin. Each server adds its Received header
    at the top, so the earliest one is last in the list."""
    if not received_headers:
        return None, "UNAVAILABLE"

    for header in reversed(received_headers):
        for match in re.finditer(r"\[([0-9a-fA-F:.]+)\]|\(([0-9a-fA-F:.]+)\)", str(header)):
            candidate = match.group(1) or match.group(2)
            try:
                ip_obj = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            # is_global also rules out ranges that are not "private" but are
            # still not a real sender, such as carrier-grade NAT (100.64/10).
            if not ip_obj.is_global:
                continue
            return str(ip_obj), "AVAILABLE"

    return None, "UNAVAILABLE"


# ---------------------------------------------------------------------
# Body and URLs
# ---------------------------------------------------------------------


def _extract_bodies(msg: Message) -> tuple[str, list[str], list[str]]:
    """Return (plain-text body, HTML parts, text parts). HTML is parsed for
    links and text only, never rendered."""
    html_parts: list[str] = []
    text_parts: list[str] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        if content_type == "text/html":
            try:
                html_parts.append(part.get_content())
            except Exception:
                logger.warning("Could not decode an HTML part; skipping")
        elif content_type == "text/plain":
            try:
                text_parts.append(part.get_content())
            except Exception:
                logger.warning("Could not decode a text part; skipping")

    body_segments = list(text_parts)
    for html in html_parts:
        soup = BeautifulSoup(html, "html.parser")
        body_segments.append(soup.get_text(separator=" ", strip=True))

    return "\n".join(body_segments), html_parts, text_parts


def _extract_urls(html_parts: list[str], text_parts: list[str]) -> list[dict]:
    found: dict[str, dict] = {}

    for html in html_parts:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.lower().startswith(("mailto:", "tel:")):
                continue
            if not href.lower().startswith(("http://", "https://")):
                continue
            anchor_text = a.get_text(strip=True)
            found.setdefault(href, {"url": href, "anchor_text": anchor_text or None})

    for text in text_parts:
        for match in _URL_RE.finditer(text):
            url = match.group(0).rstrip(_URL_TRAILING_PUNCT)
            found.setdefault(url, {"url": url, "anchor_text": None})

    urls = list(found.values())[: config.MAX_URLS]

    for entry in urls:
        entry.update(_classify_url(entry["url"], entry.get("anchor_text")))

    return urls


def _classify_url(url: str, anchor_text: str | None) -> dict:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    is_shortener = hostname in config.URL_SHORTENERS
    is_punycode = hostname.startswith("xn--") or ".xn--" in hostname
    is_raw_ip_host = _is_ip_literal(hostname)
    display_mismatch = _is_display_mismatch(anchor_text, hostname)

    return {
        "is_shortener": is_shortener,
        "is_punycode": is_punycode,
        "is_raw_ip_host": is_raw_ip_host,
        "display_mismatch": display_mismatch,
    }


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_display_mismatch(anchor_text: str | None, actual_hostname: str) -> bool:
    if not anchor_text or not actual_hostname:
        return False
    domain_match = _DOMAIN_LIKE_RE.search(anchor_text)
    if not domain_match:
        return False
    anchor_domain = _strip_www(domain_match.group(0).lower())
    actual = _strip_www(actual_hostname.lower())
    # Same domain, or one is a subdomain of the other. This has to compare
    # whole labels: a plain substring test lets "paypal.com" match
    # "paypal.com.evil.example" and "evil-paypal.com", which are exactly
    # the lookalikes this check exists to catch.
    return not (
        actual == anchor_domain
        or actual.endswith("." + anchor_domain)
        or anchor_domain.endswith("." + actual)
    )


def _strip_www(hostname: str) -> str:
    return hostname[4:] if hostname.startswith("www.") else hostname


# ---------------------------------------------------------------------
# Attachments
# ---------------------------------------------------------------------


def _extract_attachments(msg: Message) -> list[dict]:
    attachments = []
    total_size = 0

    for part in msg.iter_attachments():
        if len(attachments) >= config.MAX_ATTACHMENTS:
            break

        filename = part.get_filename() or "unnamed"
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            logger.warning("Could not decode attachment payload for %s", filename)
            payload = b""

        size = len(payload)
        if total_size + size > config.MAX_ATTACHMENTS_TOTAL_SIZE_BYTES:
            logger.warning("Attachment cap reached; skipping remaining attachments")
            break
        total_size += size

        declared_mime_type = part.get_content_type()
        detected_type = _detect_magic_type(payload)
        extension = _get_extension(filename)
        extension_mismatch = _is_extension_mismatch(extension, detected_type)
        is_executable = extension in config.EXECUTABLE_EXTENSIONS
        is_password_protected = _is_password_protected_archive(payload, extension)
        has_macros = _has_vba_macros(payload, extension)

        attachments.append({
            "filename": filename,
            "declared_mime_type": declared_mime_type,
            "detected_file_type": detected_type,
            "extension_mismatch": extension_mismatch,
            "is_executable": is_executable,
            "is_password_protected": is_password_protected,
            "has_macros": has_macros,
            "size_bytes": size,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "md5": hashlib.md5(payload).hexdigest(),
            # Only kept so the file can be uploaded to VirusTotal if its
            # hash is unknown (services/attachment_analysis.py). It's never
            # saved: database.models reads the named keys above and skips
            # this one. Remove it before logging a dict like this.
            "payload_bytes": payload,
        })

    return attachments


def _detect_magic_type(payload: bytes) -> str:
    for signature, type_name in _MAGIC_SIGNATURES:
        if payload.startswith(signature):
            return type_name
    return "unknown"


def _get_extension(filename: str) -> str:
    idx = filename.rfind(".")
    return filename[idx:].lower() if idx != -1 else ""


def _is_password_protected_archive(payload: bytes, extension: str) -> bool:
    """Reads the archive's own encryption flag. It never tries to open or
    crack the archive. ZIP uses the standard library and 7z uses py7zr.
    RAR isn't supported because rarfile needs an external unrar program.
    A RAR attachment is still hashed and sent to VirusTotal; it just can't
    raise this signal."""
    if extension == ".zip":
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                return any(info.flag_bits & 0x1 for info in archive.infolist())
        except (zipfile.BadZipFile, OSError, EOFError):
            return False
    if extension == ".7z":
        try:
            with py7zr.SevenZipFile(io.BytesIO(payload)) as archive:
                return archive.needs_password()
        except Exception:
            # py7zr has its own exceptions for broken or unreadable
            # archives. Any of them just means we can't tell.
            return False
    return False


def _has_vba_macros(payload: bytes, extension: str) -> bool:
    """Looks for VBA macros in OLE2 and macro-enabled OOXML documents using
    oletools. It reads the file's structure and never runs anything."""
    if extension not in _MACRO_CAPABLE_EXTENSIONS:
        return False
    parser = None
    try:
        parser = VBA_Parser(filename=f"attachment{extension}", data=payload)
        return bool(parser.detect_vba_macros())
    except Exception:
        logger.warning("Could not inspect %s for macros", extension)
        return False
    finally:
        if parser is not None:
            try:
                parser.close()
            except Exception:
                pass


def _is_extension_mismatch(extension: str, detected_type: str) -> bool:
    if detected_type == "unknown":
        return False
    expected_group = _EXTENSION_TYPE_GROUPS.get(extension)
    if expected_group is None:
        return False
    return expected_group != detected_type
