"""Upload validation. Runs before any parsing touches the file."""

from __future__ import annotations

import os

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

import config
from utils.exceptions import ValidationError


def validate_eml_upload(file: FileStorage | None) -> str:
    """Validate an uploaded .eml file and return its sanitised filename.

    Raises ValidationError on failure. The frontend shows the message to
    the user as-is, so it's written in plain language.
    """
    if file is None or file.filename == "":
        raise ValidationError(
            "No file was uploaded. Choose a .eml file and try again.",
            code="NO_FILE",
        )

    # Check the extension on the name as uploaded. secure_filename drops
    # every non-ASCII character, so "發票.eml" would come back as "eml" and
    # fail the check even though it is a perfectly good file.
    _, ext = os.path.splitext(file.filename)
    if ext.lower() != config.ALLOWED_EXTENSION:
        raise ValidationError(
            "That file isn't a valid .eml email file. In Outlook, Gmail or "
            "Yahoo, save the message as .eml and try again.",
            code="INVALID_FILE_TYPE",
        )

    filename = secure_filename(file.filename)
    if not filename.lower().endswith(config.ALLOWED_EXTENSION):
        filename = "email.eml"

    # FileStorage has no size until it's read, so measure the stream.
    file.stream.seek(0, os.SEEK_END)
    size = file.stream.tell()
    file.stream.seek(0)

    if size == 0:
        raise ValidationError(
            "That file is empty. Choose a valid .eml file and try again.",
            code="EMPTY_FILE",
        )

    if size > config.MAX_UPLOAD_SIZE_BYTES:
        size_mb = size / (1024 * 1024)
        limit_mb = config.MAX_UPLOAD_SIZE_BYTES / (1024 * 1024)
        raise ValidationError(
            f"That file is {size_mb:.1f} MB. The limit is {limit_mb:.0f} MB.",
            code="FILE_TOO_LARGE",
        )

    return filename
