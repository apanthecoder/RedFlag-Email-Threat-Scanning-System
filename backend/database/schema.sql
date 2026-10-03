-- RedFlag database schema (SQLite)
--
-- Applied automatically at startup by database.db.init_db(). By hand:
--   sqlite3 backend/database/redflag.db < schema.sql
--
-- Only this file, database/db.py and database/models.py contain SQL.
-- Everything else goes through models.py.
--
-- SQLite has no ENUM or JSON type. Enums are TEXT with a CHECK constraint,
-- and JSON columns are TEXT holding a json.dumps() string that Python
-- reads back.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------
-- sessions: the anonymous UUID cookie each visitor gets on their first
-- request. History is filtered by it. Visitors don't log in.
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT     NOT NULL PRIMARY KEY,
    created_at   TEXT     NOT NULL DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
    last_seen_at TEXT     NOT NULL DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'))
);

-- ---------------------------------------------------------------------
-- admin_users: the only accounts in the system. Passwords are bcrypt
-- hashes. Login rate limiting happens in Flask.
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS admin_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
    last_login_at TEXT    NULL
);

-- ---------------------------------------------------------------------
-- scans: one row per uploaded .eml. email_subject is cut to 200
-- characters when saved (privacy note in AGENTS.md). The .eml itself is
-- never written to disk or stored here.
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS scans (
    scan_id               TEXT    NOT NULL PRIMARY KEY,
    session_id            TEXT    NOT NULL,
    status                TEXT    NOT NULL DEFAULT 'PENDING'
                              CHECK (status IN (
                                  'PENDING', 'PARSING', 'ANALYZING_HEADERS',
                                  'CHECKING_URLS', 'SCANNING_ATTACHMENTS',
                                  'SCORING', 'COMPLETE', 'FAILED'
                              )),
    original_filename     TEXT    NULL,
    email_subject         TEXT    NULL CHECK (LENGTH(email_subject) <= 200),
    sender_address        TEXT    NULL,
    risk_score            INTEGER NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_level            TEXT    NULL CHECK (risk_level IN ('SAFE', 'SUSPICIOUS', 'DANGEROUS')),
    partial_scan          INTEGER NOT NULL DEFAULT 0 CHECK (partial_scan IN (0, 1)),
    unavailable_providers TEXT    NULL,  -- JSON array
    override_applied      TEXT    NULL,
    signals                TEXT    NULL, -- JSON array
    error_message          TEXT    NULL,
    created_at             TEXT    NOT NULL DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
    updated_at             TEXT    NOT NULL DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
    completed_at           TEXT    NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scans_session ON scans(session_id);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);

-- ---------------------------------------------------------------------
-- header_results: one row per scan, with the sender authentication and
-- spoofing checks taken from the email headers.
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS header_results (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id              TEXT    NOT NULL,
    from_address         TEXT    NULL,
    to_address           TEXT    NULL,
    reply_to             TEXT    NULL,
    return_path          TEXT    NULL,
    message_id           TEXT    NULL,
    date_header          TEXT    NULL,
    spf_result           TEXT    NOT NULL DEFAULT 'NONE'
                              CHECK (spf_result IN ('PASS', 'FAIL', 'SOFTFAIL', 'NEUTRAL', 'NONE')),
    dkim_result          TEXT    NOT NULL DEFAULT 'NONE'
                              CHECK (dkim_result IN ('PASS', 'FAIL', 'NONE')),
    dmarc_result         TEXT    NOT NULL DEFAULT 'NONE'
                              CHECK (dmarc_result IN ('PASS', 'FAIL', 'NONE')),
    reply_to_mismatch    INTEGER NOT NULL DEFAULT 0 CHECK (reply_to_mismatch IN (0, 1)),
    display_name_spoof   INTEGER NOT NULL DEFAULT 0 CHECK (display_name_spoof IN (0, 1)),
    sender_ip            TEXT    NULL,
    sender_ip_status     TEXT    NOT NULL DEFAULT 'UNAVAILABLE'
                              CHECK (sender_ip_status IN ('AVAILABLE', 'UNAVAILABLE')),
    abuseipdb_confidence INTEGER NULL,
    abuseipdb_reports    INTEGER NULL,
    abuseipdb_country    TEXT    NULL,
    raw_headers          TEXT    NULL, -- JSON object
    created_at           TEXT    NOT NULL DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_header_results_scan ON header_results(scan_id);

-- ---------------------------------------------------------------------
-- url_results: one row per URL found in the email body (50 at most).
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS url_results (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id                TEXT    NOT NULL,
    url                    TEXT    NOT NULL,
    anchor_text            TEXT    NULL,
    is_shortener           INTEGER NOT NULL DEFAULT 0 CHECK (is_shortener IN (0, 1)),
    display_mismatch       INTEGER NOT NULL DEFAULT 0 CHECK (display_mismatch IN (0, 1)),
    is_punycode            INTEGER NOT NULL DEFAULT 0 CHECK (is_punycode IN (0, 1)),
    is_raw_ip_host         INTEGER NOT NULL DEFAULT 0 CHECK (is_raw_ip_host IN (0, 1)),
    safe_browsing_status   TEXT    NOT NULL DEFAULT 'UNAVAILABLE'
                              CHECK (safe_browsing_status IN (
                                  'CLEAN', 'MALWARE', 'SOCIAL_ENGINEERING',
                                  'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION',
                                  'UNAVAILABLE'
                              )),
    urlscan_verdict        TEXT    NOT NULL DEFAULT 'UNAVAILABLE'
                              CHECK (urlscan_verdict IN ('CLEAN', 'MALICIOUS', 'UNAVAILABLE')),
    urlscan_score          INTEGER NULL,
    urlscan_screenshot_url TEXT    NULL,
    raw_response           TEXT    NULL, -- JSON object
    created_at             TEXT    NOT NULL DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_url_results_scan ON url_results(scan_id);

-- ---------------------------------------------------------------------
-- attachment_results: one row per attachment (10 at most, 25 MB total).
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS attachment_results (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id              TEXT    NOT NULL,
    filename             TEXT    NOT NULL,
    declared_mime_type   TEXT    NULL,
    detected_file_type   TEXT    NULL,
    extension_mismatch   INTEGER NOT NULL DEFAULT 0 CHECK (extension_mismatch IN (0, 1)),
    is_executable        INTEGER NOT NULL DEFAULT 0 CHECK (is_executable IN (0, 1)),
    is_password_protected INTEGER NOT NULL DEFAULT 0 CHECK (is_password_protected IN (0, 1)),
    has_macros           INTEGER NOT NULL DEFAULT 0 CHECK (has_macros IN (0, 1)),
    size_bytes           INTEGER NOT NULL,
    sha256               TEXT    NOT NULL,
    md5                  TEXT    NOT NULL,
    vt_status            TEXT    NOT NULL DEFAULT 'UNAVAILABLE'
                              CHECK (vt_status IN ('CLEAN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN', 'UNAVAILABLE')),
    vt_malicious_count   INTEGER NULL,
    vt_suspicious_count  INTEGER NULL,
    vt_total_engines     INTEGER NULL,
    vt_threat_label      TEXT    NULL,
    raw_response         TEXT    NULL, -- JSON object
    created_at           TEXT    NOT NULL DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_attachment_results_scan ON attachment_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_attachment_results_sha256 ON attachment_results(sha256);

-- ---------------------------------------------------------------------
-- advisory_outputs: saved so an old report still shows the advice it was
-- given, even if the rules change later.
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS advisory_outputs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT    NOT NULL,
    step_order   INTEGER NOT NULL,
    step_title   TEXT    NOT NULL,
    step_detail  TEXT    NOT NULL,
    severity     TEXT    NOT NULL CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),
    triggered_by TEXT    NOT NULL,
    created_at   TEXT    NOT NULL DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_advisory_outputs_scan ON advisory_outputs(scan_id);

-- ---------------------------------------------------------------------
-- api_call_logs: every call to a provider, for the admin analytics and to
-- show where a verdict came from. Never store keys here.
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS api_call_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       TEXT    NULL,
    provider      TEXT    NOT NULL CHECK (provider IN ('VIRUSTOTAL', 'SAFE_BROWSING', 'URLSCAN', 'ABUSEIPDB')),
    endpoint      TEXT    NULL,
    status_code   INTEGER NULL,
    duration_ms   INTEGER NULL,
    success       INTEGER NOT NULL CHECK (success IN (0, 1)),
    error_message TEXT    NULL,
    raw_response  TEXT    NULL, -- JSON object
    created_at    TEXT    NOT NULL DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_api_call_logs_provider ON api_call_logs(provider);
CREATE INDEX IF NOT EXISTS idx_api_call_logs_created ON api_call_logs(created_at);

-- There used to be a system_logs table here so an admin could read the
-- application log in the browser. Nothing ever wrote to it (the logger
-- only writes to a file and the console), so the admin view was always
-- empty. The table, its model functions, endpoint and UI panel were
-- removed. Application logs go to backend/logs/redflag.log, and every
-- provider call is still recorded in api_call_logs above.
