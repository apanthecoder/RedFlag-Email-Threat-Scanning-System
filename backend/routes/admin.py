"""Admin endpoints: login, logout, session check, analytics from
api_call_logs, and the monthly PDF report. Everything except login and
logout sits behind the require_admin decorator.
"""

from __future__ import annotations

from datetime import date, datetime

from flask import Blueprint, jsonify, make_response, request, session

from database import models
from services.report_generator import build_monthly_report
from utils.auth import require_admin, verify_password
from utils.exceptions import ValidationError
from utils.logger import get_logger
from utils.rate_limit import RateLimiter

admin_bp = Blueprint("admin", __name__)
logger = get_logger(__name__)

# 5 attempts per 5 minutes per client IP.
_login_limiter = RateLimiter(max_attempts=5, window_seconds=300)


def _envelope(success: bool, data=None, error=None):
    return {"success": success, "data": data, "error": error}


def _client_ip() -> str:
    # ProxyFix (app.py) has already set remote_addr from the proxy's header.
    # Don't read X-Forwarded-For directly: a caller can put anything in it
    # and get around the login limiter.
    return request.remote_addr or "unknown"


@admin_bp.post("/admin/login")
def login():
    ip = _client_ip()
    if not _login_limiter.is_allowed(ip):
        return jsonify(_envelope(False, error={
            "code": "RATE_LIMITED",
            "message": "Too many login attempts. Try again in a few minutes.",
        })), 429

    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    _login_limiter.record_attempt(ip)

    admin = models.get_admin_by_username(username) if username else None
    if not admin or not verify_password(password, admin["password_hash"]):
        logger.warning("Failed admin login attempt for username=%r from %s", username, ip)
        return jsonify(_envelope(False, error={
            "code": "INVALID_CREDENTIALS",
            "message": "Incorrect username or password.",
        })), 401

    session.clear()
    session["is_admin"] = True
    session["admin_id"] = admin["id"]
    session["admin_username"] = admin["username"]
    models.record_admin_login(admin["id"])

    return jsonify(_envelope(True, data={"username": admin["username"]})), 200


@admin_bp.post("/admin/logout")
def logout():
    session.clear()
    return jsonify(_envelope(True, data={"logged_out": True})), 200


@admin_bp.get("/admin/me")
@require_admin
def me():
    return jsonify(_envelope(True, data={"username": session.get("admin_username")})), 200


@admin_bp.get("/admin/analytics")
@require_admin
def get_analytics():
    data = {
        "provider_calls": models.get_api_call_analytics(),
        "scan_stats": models.get_scan_stats(),
    }
    return jsonify(_envelope(True, data=data)), 200


@admin_bp.get("/admin/report")
@require_admin
def get_monthly_report():
    """Return a generated PDF summarising one month of scanning activity.

    Query parameter `month` is YYYY-MM and defaults to the current month.
    """
    year, month = _parse_month()
    data = models.get_monthly_report_data(year, month)
    pdf_bytes = build_monthly_report(data, generated_by=session.get("admin_username"))

    filename = f"redflag-report-{year:04d}-{month:02d}.pdf"
    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Content-Length"] = str(len(pdf_bytes))
    return response


def _parse_month() -> tuple[int, int]:
    """Validate the `month` query parameter, defaulting to the current month."""
    raw = (request.args.get("month") or "").strip()
    if not raw:
        today = date.today()
        return today.year, today.month
    try:
        parsed = datetime.strptime(raw, "%Y-%m")
    except ValueError as exc:
        raise ValidationError(
            "month must be in YYYY-MM format, for example 2026-08.",
            code="INVALID_MONTH",
        ) from exc
    return parsed.year, parsed.month
