"""Tests for the admin monthly PDF report: the aggregation query, the PDF
builder, and the protected endpoint that ties them together.
"""

import itertools

import bcrypt
import pytest

import config
from database import models
from database.db import init_db
from services.report_generator import build_monthly_report

ADMIN_USERNAME = "reportadmin"
ADMIN_PASSWORD = "report-admin-password"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "test_report.db"))
    init_db()
    models.create_admin_user(
        ADMIN_USERNAME,
        bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt()).decode(),
    )

    import app as app_module
    flask_app = app_module.create_app()
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


_login_counter = itertools.count()


def login(client):
    """Each call uses a distinct client IP, because the login rate limiter
    is module-level state shared across the whole test session (the same
    convention as tests/test_admin_route.py)."""
    return client.post(
        "/api/admin/login",
        json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        headers={"X-Forwarded-For": f"10.9.0.{next(_login_counter) % 250 + 1}"},
    )


def seed_scan(risk_level, created_at, override=None, status="COMPLETE"):
    """Insert a scan directly with a controlled created_at timestamp."""
    from database.db import get_connection

    session_id = models.create_session()
    scan_id = models.create_scan(session_id, original_filename="x.eml")
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE scans SET risk_level = ?, risk_score = 50, status = ?,
                   override_applied = ?, created_at = ?
            WHERE scan_id = ?
            """,
            (risk_level, status, override, created_at, scan_id),
        )
        conn.commit()
    return scan_id


# ---------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------


def test_monthly_data_counts_only_the_requested_month(client):
    seed_scan("SAFE", "2026-08-05 10:00:00.000000")
    seed_scan("DANGEROUS", "2026-08-20 11:00:00.000000")
    seed_scan("SAFE", "2026-09-01 09:00:00.000000")  # different month

    data = models.get_monthly_report_data(2026, 8)
    assert data["period"] == "2026-08"
    assert data["totals"]["total_scans"] == 2
    assert data["by_risk_level"] == {"SAFE": 1, "DANGEROUS": 1}


def test_monthly_data_is_empty_for_a_month_with_no_activity(client):
    data = models.get_monthly_report_data(2020, 1)
    assert data["totals"]["total_scans"] == 0
    assert data["by_risk_level"] == {}


def test_monthly_data_counts_overrides(client):
    seed_scan("DANGEROUS", "2026-08-05 10:00:00.000000", override="VT_MALICIOUS_THRESHOLD")
    seed_scan("DANGEROUS", "2026-08-06 10:00:00.000000", override="VT_MALICIOUS_THRESHOLD")
    seed_scan("SAFE", "2026-08-07 10:00:00.000000")

    data = models.get_monthly_report_data(2026, 8)
    assert data["overrides"] == [{"override_applied": "VT_MALICIOUS_THRESHOLD", "c": 2}]


# ---------------------------------------------------------------------
# PDF generation
# ---------------------------------------------------------------------


def test_builder_produces_a_real_pdf():
    data = {
        "period": "2026-08",
        "totals": {"total_scans": 3, "completed": 3, "failed": 0, "partial": 1},
        "by_risk_level": {"SAFE": 1, "SUSPICIOUS": 1, "DANGEROUS": 1},
        "provider_calls": [
            {"provider": "VIRUSTOTAL", "total_calls": 10, "successful_calls": 9, "avg_duration_ms": 412.5}
        ],
        "overrides": [{"override_applied": "VT_MALICIOUS_THRESHOLD", "c": 1}],
        "attachments": {"total": 2, "malicious": 1, "executables": 1, "macro_documents": 0, "password_protected": 0},
        "urls": {"total": 4, "flagged_by_safe_browsing": 1, "display_mismatches": 2, "shorteners": 1},
    }
    pdf = build_monthly_report(data, generated_by="admin")
    assert pdf.startswith(b"%PDF-"), "output is not a PDF"
    assert len(pdf) > 1000


def test_builder_handles_a_month_with_no_scans():
    """An empty month must still produce a valid PDF, not raise."""
    data = {
        "period": "2020-01",
        "totals": {"total_scans": 0, "completed": 0, "failed": 0, "partial": 0},
        "by_risk_level": {},
        "provider_calls": [],
        "overrides": [],
        "attachments": {},
        "urls": {},
    }
    pdf = build_monthly_report(data)
    assert pdf.startswith(b"%PDF-")


def test_builder_survives_missing_keys():
    """Defensive: a partial aggregate dict must not crash the generator."""
    pdf = build_monthly_report({"period": "2026-08", "totals": {"total_scans": 1}})
    assert pdf.startswith(b"%PDF-")


# ---------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------


def test_report_endpoint_requires_admin(client):
    response = client.get("/api/admin/report")
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "UNAUTHENTICATED"


def test_report_endpoint_returns_a_pdf_attachment(client):
    login(client)
    seed_scan("DANGEROUS", "2026-08-05 10:00:00.000000")

    response = client.get("/api/admin/report?month=2026-08")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/pdf"
    assert 'filename="redflag-report-2026-08.pdf"' in response.headers["Content-Disposition"]
    assert response.data.startswith(b"%PDF-")


def test_report_endpoint_defaults_to_current_month(client):
    login(client)
    response = client.get("/api/admin/report")
    assert response.status_code == 200
    assert response.data.startswith(b"%PDF-")


@pytest.mark.parametrize("bad", ["not-a-month", "2026-13", "2026", "08-2026", "2026-0"])
def test_report_endpoint_rejects_a_malformed_month(client, bad):
    login(client)
    response = client.get(f"/api/admin/report?month={bad}")
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "INVALID_MONTH"


def test_report_endpoint_works_for_an_empty_month(client):
    login(client)
    response = client.get("/api/admin/report?month=2019-05")
    assert response.status_code == 200
    assert response.data.startswith(b"%PDF-")
