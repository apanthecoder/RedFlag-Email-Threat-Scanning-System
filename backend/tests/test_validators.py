"""Tests for utils/validators.py upload validation."""

import io

import pytest
from werkzeug.datastructures import FileStorage

import config
from utils.exceptions import ValidationError
from utils.validators import validate_eml_upload


def make_file(filename: str, content: bytes) -> FileStorage:
    return FileStorage(stream=io.BytesIO(content), filename=filename)


def test_no_file_rejected():
    with pytest.raises(ValidationError) as exc_info:
        validate_eml_upload(None)
    assert exc_info.value.code == "NO_FILE"


def test_wrong_extension_rejected():
    f = make_file("invoice.pdf", b"not an email")
    with pytest.raises(ValidationError) as exc_info:
        validate_eml_upload(f)
    assert exc_info.value.code == "INVALID_FILE_TYPE"


def test_empty_file_rejected():
    f = make_file("email.eml", b"")
    with pytest.raises(ValidationError) as exc_info:
        validate_eml_upload(f)
    assert exc_info.value.code == "EMPTY_FILE"


def test_oversized_file_rejected():
    f = make_file("email.eml", b"x" * (config.MAX_UPLOAD_SIZE_BYTES + 1))
    with pytest.raises(ValidationError) as exc_info:
        validate_eml_upload(f)
    assert exc_info.value.code == "FILE_TOO_LARGE"


def test_valid_eml_accepted():
    f = make_file("email.eml", b"Subject: test\n\nbody")
    filename = validate_eml_upload(f)
    assert filename == "email.eml"


def test_filename_is_sanitised():
    f = make_file("../../etc/passwd.eml", b"Subject: test\n\nbody")
    filename = validate_eml_upload(f)
    assert "/" not in filename
    assert ".." not in filename


def test_non_ascii_filename_accepted():
    # secure_filename strips non-ASCII characters, which used to turn
    # "發票.eml" into "eml" and fail the extension check.
    f = make_file("發票.eml", b"From: a@example.com\n\nhello")
    assert validate_eml_upload(f).endswith(".eml")
