"""Insert and fetch functions for every table in schema.sql.

Routes and services call these and never write SQL themselves. Every query
uses ? placeholders. Never build one with an f-string.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from database.db import get_connection, transaction, row_to_dict, rows_to_dicts
from utils.logger import get_logger

logger = get_logger(__name__)


def _json_or_none(value: Any) -> str | None:
    return json.dumps(value) if value is not None else None


def _parse_json_fields(row: dict | None, fields: tuple[str, ...]) -> dict | None:
    """SQLite has no JSON type, so these columns hold json.dumps() strings.
    Turn them back into Python objects for the API."""
    if row is None:
        return None
    for field in fields:
        raw = row.get(field)
        if raw is not None:
            try:
                row[field] = json.loads(raw)
            except (TypeError, ValueError):
                pass
    return row


def _parse_json_fields_many(rows: list[dict], fields: tuple[str, ...]) -> list[dict]:
    return [_parse_json_fields(row, fields) for row in rows]


def _now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")


# The values the CHECK constraints in schema.sql allow for the three
# header_results auth columns. eml_parser already maps header words onto
# these; this is a last check so an unexpected value is saved as NONE
# instead of failing the whole scan.
_ALLOWED_AUTH_RESULTS = {
    "spf_result": {"PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE"},
    "dkim_result": {"PASS", "FAIL", "NONE"},
    "dmarc_result": {"PASS", "FAIL", "NONE"},
}


def _auth_result(data: dict, key: str) -> str:
    value = data.get(key, "NONE")
    if value in _ALLOWED_AUTH_RESULTS[key]:
        return value
    logger.warning("Unexpected %s value %r saved as NONE", key, value)
    return "NONE"


# ---------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------


def create_session(session_id: str | None = None) -> str:
    session_id = session_id or str(uuid.uuid4())
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO sessions (session_id) VALUES (?)",
            (session_id,),
        )
        conn.commit()
    return session_id


def touch_session(session_id: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET last_seen_at = ? WHERE session_id = ?",
            (_now(), session_id),
        )
        conn.commit()


def get_session(session_id: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
    return row_to_dict(row)


# ---------------------------------------------------------------------
# admin_users
# ---------------------------------------------------------------------


def create_admin_user(username: str, password_hash: str) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO admin_users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
        return cursor.lastrowid


def get_admin_by_username(username: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM admin_users WHERE username = ?", (username,)
        ).fetchone()
    return row_to_dict(row)


def record_admin_login(admin_id: int) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE admin_users SET last_login_at = ? WHERE id = ?",
            (_now(), admin_id),
        )
        conn.commit()


# ---------------------------------------------------------------------
# scans
# ---------------------------------------------------------------------


def create_scan(
    session_id: str,
    original_filename: str | None = None,
    scan_id: str | None = None,
) -> str:
    scan_id = scan_id or str(uuid.uuid4())
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO scans (scan_id, session_id, status, original_filename)
            VALUES (?, ?, 'PENDING', ?)
            """,
            (scan_id, session_id, original_filename),
        )
        conn.commit()
    return scan_id


def update_scan_status(scan_id: str, status: str, error_message: str | None = None) -> None:
    completed_at = _now() if status in ("COMPLETE", "FAILED") else None
    with get_connection() as conn:
        if completed_at:
            conn.execute(
                """
                UPDATE scans
                SET status = ?, error_message = ?, updated_at = ?, completed_at = ?
                WHERE scan_id = ?
                """,
                (status, error_message, _now(), completed_at, scan_id),
            )
        else:
            conn.execute(
                """
                UPDATE scans
                SET status = ?, error_message = ?, updated_at = ?
                WHERE scan_id = ?
                """,
                (status, error_message, _now(), scan_id),
            )
        conn.commit()


def update_scan_metadata(scan_id: str, email_subject: str | None, sender_address: str | None) -> None:
    subject = email_subject[:200] if email_subject else None
    with get_connection() as conn:
        conn.execute(
            "UPDATE scans SET email_subject = ?, sender_address = ?, updated_at = ? WHERE scan_id = ?",
            (subject, sender_address, _now(), scan_id),
        )
        conn.commit()


def save_scan_verdict(
    scan_id: str,
    risk_score: int,
    risk_level: str,
    partial_scan: bool,
    unavailable_providers: list[str],
    override_applied: str | None,
    signals: list[dict],
) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE scans
            SET risk_score = ?, risk_level = ?, partial_scan = ?,
                unavailable_providers = ?, override_applied = ?,
                signals = ?, status = 'COMPLETE', completed_at = ?, updated_at = ?
            WHERE scan_id = ?
            """,
            (
                risk_score,
                risk_level,
                int(partial_scan),
                _json_or_none(unavailable_providers),
                override_applied,
                _json_or_none(signals),
                _now(),
                _now(),
                scan_id,
            ),
        )
        conn.commit()


def get_scan(scan_id: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    return _parse_json_fields(row_to_dict(row), ("unavailable_providers", "signals"))


def get_scans_for_session(session_id: str, limit: int = 50) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT * FROM scans
            WHERE session_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (session_id, limit),
        ).fetchall()
    return _parse_json_fields_many(rows_to_dicts(rows), ("unavailable_providers", "signals"))


# ---------------------------------------------------------------------
# header_results
# ---------------------------------------------------------------------


def save_header_result(scan_id: str, data: dict) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO header_results (
                scan_id, from_address, to_address, reply_to, return_path,
                message_id, date_header, spf_result, dkim_result, dmarc_result,
                reply_to_mismatch, display_name_spoof, sender_ip, sender_ip_status,
                abuseipdb_confidence, abuseipdb_reports, abuseipdb_country, raw_headers
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                data.get("from_address"),
                data.get("to_address"),
                data.get("reply_to"),
                data.get("return_path"),
                data.get("message_id"),
                data.get("date_header"),
                _auth_result(data, "spf_result"),
                _auth_result(data, "dkim_result"),
                _auth_result(data, "dmarc_result"),
                int(data.get("reply_to_mismatch", False)),
                int(data.get("display_name_spoof", False)),
                data.get("sender_ip"),
                data.get("sender_ip_status", "UNAVAILABLE"),
                data.get("abuseipdb_confidence"),
                data.get("abuseipdb_reports"),
                data.get("abuseipdb_country"),
                _json_or_none(data.get("raw_headers")),
            ),
        )
        conn.commit()


def get_header_result(scan_id: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM header_results WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    return _parse_json_fields(row_to_dict(row), ("raw_headers",))


# ---------------------------------------------------------------------
# url_results
# ---------------------------------------------------------------------


def save_url_results(scan_id: str, urls: list[dict]) -> None:
    if not urls:
        return
    with get_connection() as conn:
        conn.executemany(
            """
            INSERT INTO url_results (
                scan_id, url, anchor_text, is_shortener, display_mismatch,
                is_punycode, is_raw_ip_host, safe_browsing_status,
                urlscan_verdict, urlscan_score, urlscan_screenshot_url, raw_response
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id,
                    u["url"],
                    u.get("anchor_text"),
                    int(u.get("is_shortener", False)),
                    int(u.get("display_mismatch", False)),
                    int(u.get("is_punycode", False)),
                    int(u.get("is_raw_ip_host", False)),
                    u.get("safe_browsing_status", "UNAVAILABLE"),
                    u.get("urlscan_verdict", "UNAVAILABLE"),
                    u.get("urlscan_score"),
                    u.get("urlscan_screenshot_url"),
                    _json_or_none(u.get("raw_response")),
                )
                for u in urls
            ],
        )
        conn.commit()


def get_url_results(scan_id: str) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM url_results WHERE scan_id = ?", (scan_id,)
        ).fetchall()
    return _parse_json_fields_many(rows_to_dicts(rows), ("raw_response",))


# ---------------------------------------------------------------------
# attachment_results
# ---------------------------------------------------------------------


def save_attachment_results(scan_id: str, attachments: list[dict]) -> None:
    if not attachments:
        return
    with get_connection() as conn:
        conn.executemany(
            """
            INSERT INTO attachment_results (
                scan_id, filename, declared_mime_type, detected_file_type,
                extension_mismatch, is_executable, is_password_protected, has_macros,
                size_bytes, sha256, md5,
                vt_status, vt_malicious_count, vt_suspicious_count,
                vt_total_engines, vt_threat_label, raw_response
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id,
                    a["filename"],
                    a.get("declared_mime_type"),
                    a.get("detected_file_type"),
                    int(a.get("extension_mismatch", False)),
                    int(a.get("is_executable", False)),
                    int(a.get("is_password_protected", False)),
                    int(a.get("has_macros", False)),
                    a["size_bytes"],
                    a["sha256"],
                    a["md5"],
                    a.get("vt_status", "UNAVAILABLE"),
                    a.get("vt_malicious_count"),
                    a.get("vt_suspicious_count"),
                    a.get("vt_total_engines"),
                    a.get("vt_threat_label"),
                    _json_or_none(a.get("raw_response")),
                )
                for a in attachments
            ],
        )
        conn.commit()


def get_attachment_results(scan_id: str) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM attachment_results WHERE scan_id = ?", (scan_id,)
        ).fetchall()
    return _parse_json_fields_many(rows_to_dicts(rows), ("raw_response",))


def find_attachment_by_hash(sha256: str) -> dict | None:
    """Latest result for this hash from the last 24 hours. Not wired in
    yet; meant for reusing a VirusTotal result instead of uploading again."""
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT * FROM attachment_results
            WHERE sha256 = ? AND created_at > DATETIME('now', '-24 hours')
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (sha256,),
        ).fetchone()
    return row_to_dict(row)


# ---------------------------------------------------------------------
# advisory_outputs
# ---------------------------------------------------------------------


def save_advisory_outputs(scan_id: str, steps: list[dict]) -> None:
    if not steps:
        return
    with get_connection() as conn:
        conn.executemany(
            """
            INSERT INTO advisory_outputs (
                scan_id, step_order, step_title, step_detail, severity, triggered_by
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id,
                    s["step_order"],
                    s["step_title"],
                    s["step_detail"],
                    s["severity"],
                    s["triggered_by"],
                )
                for s in steps
            ],
        )
        conn.commit()


def get_advisory_outputs(scan_id: str) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT * FROM advisory_outputs
            WHERE scan_id = ?
            ORDER BY step_order ASC
            """,
            (scan_id,),
        ).fetchall()
    return rows_to_dicts(rows)


# ---------------------------------------------------------------------
# api_call_logs
# ---------------------------------------------------------------------


def log_api_call(
    provider: str,
    success: bool,
    scan_id: str | None = None,
    endpoint: str | None = None,
    status_code: int | None = None,
    duration_ms: int | None = None,
    error_message: str | None = None,
    raw_response: Any = None,
) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO api_call_logs (
                scan_id, provider, endpoint, status_code, duration_ms,
                success, error_message, raw_response
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                provider,
                endpoint,
                status_code,
                duration_ms,
                int(success),
                error_message,
                _json_or_none(raw_response),
            ),
        )
        conn.commit()


def get_api_call_logs(limit: int = 100, offset: int = 0) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT * FROM api_call_logs
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    return rows_to_dicts(rows)


def get_api_call_analytics() -> list[dict]:
    """Per-provider call counts and success rates for the admin dashboard.

    successful_calls includes the 404s that URLScan and VirusTotal return
    as a normal answer (see api_clients/_http.py). expected_not_found
    counts those on their own so they're still visible.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                provider,
                COUNT(*)     AS total_calls,
                SUM(success) AS successful_calls,
                SUM(CASE WHEN status_code = 404 THEN 1 ELSE 0 END) AS expected_not_found,
                AVG(duration_ms) AS avg_duration_ms
            FROM api_call_logs
            GROUP BY provider
            """
        ).fetchall()
    return rows_to_dicts(rows)


def get_monthly_report_data(year: int, month: int) -> dict:
    """Everything the monthly PDF report needs, for one month.

    created_at is stored as 'YYYY-MM-DD HH:MM:SS.ffffff', so matching the
    'YYYY-MM' prefix picks out the month without parsing any dates, and
    idx_scans_created still gets used.
    """
    prefix = f"{year:04d}-{month:02d}"
    like = prefix + "%"

    with get_connection() as conn:
        totals = conn.execute(
            """
            SELECT
                COUNT(*)                                        AS total_scans,
                SUM(CASE WHEN status = 'COMPLETE' THEN 1 ELSE 0 END) AS completed,
                SUM(CASE WHEN status = 'FAILED'   THEN 1 ELSE 0 END) AS failed,
                SUM(CASE WHEN partial_scan = 1    THEN 1 ELSE 0 END) AS partial
            FROM scans WHERE created_at LIKE ?
            """,
            (like,),
        ).fetchone()

        by_level = conn.execute(
            """
            SELECT risk_level, COUNT(*) AS c FROM scans
            WHERE created_at LIKE ? AND risk_level IS NOT NULL
            GROUP BY risk_level
            """,
            (like,),
        ).fetchall()

        providers = conn.execute(
            """
            SELECT provider,
                   COUNT(*)          AS total_calls,
                   SUM(success)      AS successful_calls,
                   SUM(CASE WHEN status_code = 404 THEN 1 ELSE 0 END) AS expected_not_found,
                   AVG(duration_ms)  AS avg_duration_ms
            FROM api_call_logs WHERE created_at LIKE ?
            GROUP BY provider
            """,
            (like,),
        ).fetchall()

        overrides = conn.execute(
            """
            SELECT override_applied, COUNT(*) AS c FROM scans
            WHERE created_at LIKE ? AND override_applied IS NOT NULL
            GROUP BY override_applied ORDER BY c DESC
            """,
            (like,),
        ).fetchall()

        attachments = conn.execute(
            """
            SELECT
                COUNT(*)                                              AS total,
                SUM(CASE WHEN a.vt_status = 'MALICIOUS' THEN 1 ELSE 0 END) AS malicious,
                SUM(a.is_executable)         AS executables,
                SUM(a.has_macros)            AS macro_documents,
                SUM(a.is_password_protected) AS password_protected
            FROM attachment_results a
            JOIN scans s ON s.scan_id = a.scan_id
            WHERE s.created_at LIKE ?
            """,
            (like,),
        ).fetchone()

        urls = conn.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN u.safe_browsing_status IN ('MALWARE', 'SOCIAL_ENGINEERING')
                         THEN 1 ELSE 0 END) AS flagged_by_safe_browsing,
                SUM(u.display_mismatch) AS display_mismatches,
                SUM(u.is_shortener)     AS shorteners
            FROM url_results u
            JOIN scans s ON s.scan_id = u.scan_id
            WHERE s.created_at LIKE ?
            """,
            (like,),
        ).fetchone()

    return {
        "period": prefix,
        "totals": dict(totals) if totals else {},
        "by_risk_level": {r["risk_level"]: r["c"] for r in by_level},
        "provider_calls": rows_to_dicts(providers),
        "overrides": rows_to_dicts(overrides),
        "attachments": dict(attachments) if attachments else {},
        "urls": dict(urls) if urls else {},
    }


def get_scan_stats() -> dict:
    """Aggregate counts for the admin analytics dashboard."""
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
        by_level_rows = conn.execute(
            """
            SELECT risk_level, COUNT(*) AS c FROM scans
            WHERE risk_level IS NOT NULL
            GROUP BY risk_level
            """
        ).fetchall()
        partial = conn.execute(
            "SELECT COUNT(*) AS c FROM scans WHERE partial_scan = 1"
        ).fetchone()["c"]
    return {
        "total_scans": total,
        "by_risk_level": {row["risk_level"]: row["c"] for row in by_level_rows},
        "partial_scans": partial,
    }


# ---------------------------------------------------------------------
# Full-scan write, in one transaction
# ---------------------------------------------------------------------


def save_full_scan_result(
    scan_id: str,
    header_result: dict | None,
    url_results: list[dict],
    attachment_results: list[dict],
    advisory_steps: list[dict],
    verdict: dict,
) -> None:
    """Save a finished scan to every table it touches, in one transaction.

    Either scans, header_results, url_results, attachment_results and
    advisory_outputs are all written, or none of them are.
    """
    with transaction() as cursor:
        if header_result:
            cursor.execute(
                """
                INSERT INTO header_results (
                    scan_id, from_address, to_address, reply_to, return_path,
                    message_id, date_header, spf_result, dkim_result, dmarc_result,
                    reply_to_mismatch, display_name_spoof, sender_ip, sender_ip_status,
                    abuseipdb_confidence, abuseipdb_reports, abuseipdb_country, raw_headers
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    header_result.get("from_address"),
                    header_result.get("to_address"),
                    header_result.get("reply_to"),
                    header_result.get("return_path"),
                    header_result.get("message_id"),
                    header_result.get("date_header"),
                    _auth_result(header_result, "spf_result"),
                    _auth_result(header_result, "dkim_result"),
                    _auth_result(header_result, "dmarc_result"),
                    int(header_result.get("reply_to_mismatch", False)),
                    int(header_result.get("display_name_spoof", False)),
                    header_result.get("sender_ip"),
                    header_result.get("sender_ip_status", "UNAVAILABLE"),
                    header_result.get("abuseipdb_confidence"),
                    header_result.get("abuseipdb_reports"),
                    header_result.get("abuseipdb_country"),
                    _json_or_none(header_result.get("raw_headers")),
                ),
            )

        if url_results:
            cursor.executemany(
                """
                INSERT INTO url_results (
                    scan_id, url, anchor_text, is_shortener, display_mismatch,
                    is_punycode, is_raw_ip_host, safe_browsing_status,
                    urlscan_verdict, urlscan_score, urlscan_screenshot_url, raw_response
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        u["url"],
                        u.get("anchor_text"),
                        int(u.get("is_shortener", False)),
                        int(u.get("display_mismatch", False)),
                        int(u.get("is_punycode", False)),
                        int(u.get("is_raw_ip_host", False)),
                        u.get("safe_browsing_status", "UNAVAILABLE"),
                        u.get("urlscan_verdict", "UNAVAILABLE"),
                        u.get("urlscan_score"),
                        u.get("urlscan_screenshot_url"),
                        _json_or_none(u.get("raw_response")),
                    )
                    for u in url_results
                ],
            )

        if attachment_results:
            cursor.executemany(
                """
                INSERT INTO attachment_results (
                    scan_id, filename, declared_mime_type, detected_file_type,
                    extension_mismatch, is_executable, is_password_protected, has_macros,
                    size_bytes, sha256, md5,
                    vt_status, vt_malicious_count, vt_suspicious_count,
                    vt_total_engines, vt_threat_label, raw_response
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        a["filename"],
                        a.get("declared_mime_type"),
                        a.get("detected_file_type"),
                        int(a.get("extension_mismatch", False)),
                        int(a.get("is_executable", False)),
                        int(a.get("is_password_protected", False)),
                        int(a.get("has_macros", False)),
                        a["size_bytes"],
                        a["sha256"],
                        a["md5"],
                        a.get("vt_status", "UNAVAILABLE"),
                        a.get("vt_malicious_count"),
                        a.get("vt_suspicious_count"),
                        a.get("vt_total_engines"),
                        a.get("vt_threat_label"),
                        _json_or_none(a.get("raw_response")),
                    )
                    for a in attachment_results
                ],
            )

        if advisory_steps:
            cursor.executemany(
                """
                INSERT INTO advisory_outputs (
                    scan_id, step_order, step_title, step_detail, severity, triggered_by
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        s["step_order"],
                        s["step_title"],
                        s["step_detail"],
                        s["severity"],
                        s["triggered_by"],
                    )
                    for s in advisory_steps
                ],
            )

        cursor.execute(
            """
            UPDATE scans
            SET risk_score = ?, risk_level = ?, partial_scan = ?,
                unavailable_providers = ?, override_applied = ?,
                signals = ?, status = 'COMPLETE', completed_at = ?, updated_at = ?
            WHERE scan_id = ?
            """,
            (
                verdict["risk_score"],
                verdict["risk_level"],
                int(verdict.get("partial_scan", False)),
                _json_or_none(verdict.get("unavailable_providers", [])),
                verdict.get("override_applied"),
                _json_or_none(verdict.get("signals", [])),
                _now(),
                _now(),
                scan_id,
            ),
        )
