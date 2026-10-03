"""Tests for the two archive and document signals: password-protected
archive detection (ZIP via stdlib zipfile, 7z via py7zr) and VBA macro
detection (oletools).

The archive tests use real encrypted archives, not mocks. py7zr can
write a password-protected 7z directly. For ZIP, the standard library can
read encrypted entries but not write them, so the test flips the PKZIP
encryption bit in a normal archive's headers.

Macro detection is mocked at oletools.olevba.VBA_Parser. Building a valid
OLE2 vbaProject.bin by hand would be a project in itself, and the mock
still shows that eml_parser passes oletools' answer through.
"""

import io
import zipfile

import py7zr
import pytest

from services.eml_parser import _has_vba_macros, _is_password_protected_archive


def _build_encrypted_zip(filename: str = "secret.txt", content: bytes = b"top secret") -> bytes:
    """A real ZIP with the standard PKZIP general-purpose encryption bit
    (bit 0) set in both the local file header and the central directory
    record. zipfile can't write encrypted entries, so the bit is flipped
    directly in the raw bytes after a normal write; the payload itself
    is left as plaintext, since _is_password_protected_archive only ever
    reads the flag, never the (would-be encrypted) content."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr(filename, content)
    raw = bytearray(buffer.getvalue())

    local_sig = b"PK\x03\x04"
    central_sig = b"PK\x01\x02"
    idx = raw.find(local_sig)
    assert idx != -1
    flag_offset = idx + 6  # general purpose bit flag is 2 bytes at offset 6
    raw[flag_offset] |= 0x1

    idx = raw.find(central_sig)
    assert idx != -1
    flag_offset = idx + 8  # general purpose bit flag is 2 bytes at offset 8 here
    raw[flag_offset] |= 0x1

    return bytes(raw)


def _build_plain_zip(filename: str = "readme.txt", content: bytes = b"hello") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr(filename, content)
    return buffer.getvalue()


def _build_encrypted_7z(password: str = "hunter2") -> bytes:
    buffer = io.BytesIO()
    with py7zr.SevenZipFile(buffer, "w", password=password) as archive:
        archive.writestr(b"top secret", "secret.txt")
    return buffer.getvalue()


def _build_plain_7z() -> bytes:
    buffer = io.BytesIO()
    with py7zr.SevenZipFile(buffer, "w") as archive:
        archive.writestr(b"hello", "readme.txt")
    return buffer.getvalue()


# ---------------------------------------------------------------------
# Password-protected archives
# ---------------------------------------------------------------------


def test_detects_real_password_protected_zip():
    payload = _build_encrypted_zip()
    assert _is_password_protected_archive(payload, ".zip") is True


def test_does_not_flag_a_plain_zip():
    payload = _build_plain_zip()
    assert _is_password_protected_archive(payload, ".zip") is False


def test_detects_real_password_protected_7z():
    payload = _build_encrypted_7z()
    assert _is_password_protected_archive(payload, ".7z") is True


def test_does_not_flag_a_plain_7z():
    payload = _build_plain_7z()
    assert _is_password_protected_archive(payload, ".7z") is False


def test_malformed_zip_does_not_crash():
    assert _is_password_protected_archive(b"not a real zip file", ".zip") is False


def test_malformed_7z_does_not_crash():
    assert _is_password_protected_archive(b"not a real 7z file", ".7z") is False


def test_non_archive_extension_is_never_flagged():
    payload = _build_encrypted_zip()
    # Even encrypted-zip bytes shouldn't be checked if the extension
    # doesn't claim to be an archive at all.
    assert _is_password_protected_archive(payload, ".pdf") is False


def test_rar_is_not_supported_but_does_not_crash():
    """RAR was deliberately out of scope (needs an external unrar/unar
    binary, not just a pip package); confirm it degrades safely rather
    than raising."""
    assert _is_password_protected_archive(b"Rar!\x1a\x07\x01\x00fake", ".rar") is False


# ---------------------------------------------------------------------
# Macro-enabled documents
# ---------------------------------------------------------------------


def test_macro_detection_reports_true_when_oletools_finds_macros(mocker):
    mock_parser = mocker.MagicMock()
    mock_parser.detect_vba_macros.return_value = True
    mocker.patch("services.eml_parser.VBA_Parser", return_value=mock_parser)

    assert _has_vba_macros(b"fake docm bytes", ".docm") is True
    mock_parser.close.assert_called_once()


def test_macro_detection_reports_false_when_oletools_finds_none(mocker):
    mock_parser = mocker.MagicMock()
    mock_parser.detect_vba_macros.return_value = False
    mocker.patch("services.eml_parser.VBA_Parser", return_value=mock_parser)

    assert _has_vba_macros(b"fake docx-shaped bytes", ".docm") is False


def test_macro_detection_skipped_for_non_macro_capable_extensions(mocker):
    mock_vba_parser_class = mocker.patch("services.eml_parser.VBA_Parser")
    assert _has_vba_macros(b"whatever", ".pdf") is False
    mock_vba_parser_class.assert_not_called()


def test_macro_detection_does_not_crash_on_unparseable_bytes(mocker):
    mocker.patch("services.eml_parser.VBA_Parser", side_effect=RuntimeError("corrupt file"))
    assert _has_vba_macros(b"garbage", ".doc") is False


@pytest.mark.parametrize("extension", [".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm"])
def test_all_macro_capable_extensions_are_checked(mocker, extension):
    mock_parser = mocker.MagicMock()
    mock_parser.detect_vba_macros.return_value = True
    mocker.patch("services.eml_parser.VBA_Parser", return_value=mock_parser)
    assert _has_vba_macros(b"fake bytes", extension) is True


def test_docx_without_m_is_never_macro_capable(mocker):
    """.docx (no macros by OOXML definition, unlike .docm) should never
    even reach oletools."""
    mock_vba_parser_class = mocker.patch("services.eml_parser.VBA_Parser")
    assert _has_vba_macros(b"whatever", ".docx") is False
    mock_vba_parser_class.assert_not_called()
