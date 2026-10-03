"""Scan endpoints: upload, status polling, the full report and per-session
history. The routes only validate input, start or read a scan and shape
the response. Parsing and analysis live in services/.
"""

from __future__ import annotations

import threading
from email.utils import parseaddr

from flask import Blueprint, jsonify, make_response, request

import config
from database import models
from services.advisory import build_advisory
from services.eml_parser import parse_eml_bytes
from services.orchestrator import run_pipeline
from utils.exceptions import ParsingError
from utils.logger import get_logger
from utils.validators import validate_eml_upload

scan_bp = Blueprint("scan", __name__)
logger = get_logger(__name__)

SESSION_COOKIE_NAME = "rf_session"


def _envelope(success: bool, data=None, error=None):
    return {"success": success, "data": data, "error": error}


def _get_or_create_session_id() -> tuple[str, bool]:
    """Returns (session_id, is_new). A cookie for a session the database
    doesn't know, for example after a wipe, gets a new session."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id and models.get_session(session_id):
        models.touch_session(session_id)
        return session_id, False
    return models.create_session(), True


def _set_session_cookie(response, session_id: str) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        httponly=True,
        samesite="Lax",
        secure=config.FLASK_ENV != "development",
        max_age=60 * 60 * 24 * 30,
    )


def _extract_email_address(from_header: str | None) -> str | None:
    # parseaddr takes the address in the angle brackets. A regex that grabs
    # the first thing shaped like an address would return the fake one in
    # a spoofed header like '"support@paypal.com" <x@evil.example>'.
    if not from_header:
        return None
    _, address = parseaddr(from_header)
    return address if "@" in address else None


@scan_bp.post("/scan")
def create_scan():
    filename = validate_eml_upload(request.files.get("file"))
    session_id, is_new_session = _get_or_create_session_id()

    # The upload stays in memory and never touches the disk (the reason is
    # in services/eml_parser.py, parse_eml_bytes). validate_eml_upload and
    # MAX_CONTENT_LENGTH both cap it at 10 MB.
    upload = request.files["file"]
    upload.stream.seek(0)
    raw_email = upload.stream.read()

    scan_id = models.create_scan(session_id, original_filename=filename)

    thread = threading.Thread(
        target=_run_pipeline_job, args=(scan_id, raw_email), daemon=True
    )
    thread.start()

    response = make_response(
        jsonify(_envelope(True, data={"scan_id": scan_id})), 202
    )
    if is_new_session:
        _set_session_cookie(response, session_id)
    return response


def _run_pipeline_job(scan_id: str, raw_email: bytes) -> None:
    """Runs in a background thread.

    The email only exists in memory and is dropped when this returns.
    Nothing is written to backend/uploads/, so there's no cleanup step that
    could fail and leave a malicious file behind.
    """
    try:
        models.update_scan_status(scan_id, "PARSING")
        parsed = parse_eml_bytes(raw_email)

        sender_address = _extract_email_address(parsed["headers"].get("from"))
        models.update_scan_metadata(scan_id, parsed["headers"].get("subject"), sender_address)

        models.update_scan_status(scan_id, "ANALYZING_HEADERS")
        result = run_pipeline(parsed, scan_id=scan_id)

        models.update_scan_status(scan_id, "SCORING")
        advisory_steps = build_advisory(
            result["verdict"], result["header_result"],
            result["url_results"], result["attachment_results"],
        )
        models.save_full_scan_result(
            scan_id=scan_id,
            header_result=result["header_result"],
            url_results=result["url_results"],
            attachment_results=result["attachment_results"],
            advisory_steps=advisory_steps,
            verdict=result["verdict"],
        )
    except ParsingError as exc:
        logger.warning("Scan %s failed to parse: %s", scan_id, exc)
        models.update_scan_status(scan_id, "FAILED", error_message=exc.message)
    except Exception:
        logger.exception("Scan %s failed unexpectedly", scan_id)
        models.update_scan_status(
            scan_id, "FAILED",
            error_message="Something went wrong while scanning this email.",
        )


@scan_bp.get("/scan/<scan_id>")
def get_scan_report(scan_id: str):
    scan = models.get_scan(scan_id)
    if scan is None:
        return jsonify(_envelope(
            False, error={"code": "NOT_FOUND", "message": "No scan found with that ID."}
        )), 404

    data = {
        "scan": scan,
        "header_result": models.get_header_result(scan_id),
        "url_results": models.get_url_results(scan_id),
        "attachment_results": models.get_attachment_results(scan_id),
        "advisory": models.get_advisory_outputs(scan_id),
    }
    return jsonify(_envelope(True, data=data)), 200


@scan_bp.get("/scan/<scan_id>/status")
def get_scan_status(scan_id: str):
    scan = models.get_scan(scan_id)
    if scan is None:
        return jsonify(_envelope(
            False, error={"code": "NOT_FOUND", "message": "No scan found with that ID."}
        )), 404
    return jsonify(_envelope(True, data={
        "status": scan["status"],
        "error_message": scan.get("error_message"),
    })), 200


@scan_bp.get("/history")
def get_history():
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return jsonify(_envelope(True, data=[])), 200
    return jsonify(_envelope(True, data=models.get_scans_for_session(session_id))), 200
