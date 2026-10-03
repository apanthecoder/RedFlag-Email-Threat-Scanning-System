"""Central configuration for RedFlag backend.

Reads the environment once (via python-dotenv) and exposes typed
constants. Nothing else should call os.getenv.
"""

from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

load_dotenv()


def _env(name: str, default: str | None = None) -> str | None:
    """os.getenv, except that a blank value counts as unset.

    .env.example lists the optional keys as NAME= with nothing after them,
    meaning "use the default". Plain os.getenv returns "" for those, which
    once turned a blank DB_PATH into a throwaway temporary database.
    """
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


# --- Flask / server -------------------------------------------------------

FLASK_ENV: str = _env("FLASK_ENV", "development")
# The fallback is only for local development. It signs the admin session
# cookie, so a server running on it would accept forged admin logins;
# validate_secret_key() stops that from happening outside development.
_DEV_SECRET_KEY = "dev-secret-key-change-me"
SECRET_KEY: str = _env("SECRET_KEY", _DEV_SECRET_KEY)
FRONTEND_ORIGIN: str = _env("FRONTEND_ORIGIN", "http://localhost:5173")

# --- Database --------------------------------------------------------------

# SQLite file, relative to backend/ unless overridden with an absolute path.
DB_PATH: str = _env(
    "DB_PATH", os.path.join(os.path.dirname(__file__), "database", "redflag.db")
)

# --- Threat intelligence API keys ------------------------------------------

VIRUSTOTAL_API_KEY: str | None = _env("VIRUSTOTAL_API_KEY")
SAFE_BROWSING_API_KEY: str | None = _env("SAFE_BROWSING_API_KEY")
URLSCAN_API_KEY: str | None = _env("URLSCAN_API_KEY")
ABUSEIPDB_API_KEY: str | None = _env("ABUSEIPDB_API_KEY")

# --- Admin bootstrap -------------------------------------------------------

# The free hosting tier starts from an empty disk after every restart, and
# the admin account goes with it. If these are set, the account is created
# again at startup. Locally they stay unset and you run
# python -m database.seed_admin instead.
ADMIN_USERNAME: str | None = _env("ADMIN_USERNAME")
ADMIN_PASSWORD: str | None = _env("ADMIN_PASSWORD")

# --- Built frontend --------------------------------------------------------

# Flask serves the built React app so the site and the API share one
# address. The session cookies are SameSite=Lax, which browsers don't send
# across sites, so hosting them separately would break admin login and
# scan history.
FRONTEND_DIST: str = _env(
    "FRONTEND_DIST",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist"),
)

_REQUIRED_KEYS = {
    "VIRUSTOTAL_API_KEY": VIRUSTOTAL_API_KEY,
    "SAFE_BROWSING_API_KEY": SAFE_BROWSING_API_KEY,
    "URLSCAN_API_KEY": URLSCAN_API_KEY,
    "ABUSEIPDB_API_KEY": ABUSEIPDB_API_KEY,
}

# --- Upload limits -----------------------------------------------------

MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSION: str = ".eml"
UPLOAD_DIR: str = os.path.join(os.path.dirname(__file__), "uploads")
MAX_ATTACHMENTS: int = 10
MAX_ATTACHMENTS_TOTAL_SIZE_BYTES: int = 25 * 1024 * 1024
MAX_URLS: int = 50

# --- Provider timeouts (seconds) -------------------------------------------

VIRUSTOTAL_TIMEOUT: int = 15
SAFE_BROWSING_TIMEOUT: int = 15
ABUSEIPDB_TIMEOUT: int = 10
URLSCAN_POLL_TIMEOUT: int = 20
URLSCAN_MAX_POLL_ATTEMPTS: int = 12
URLSCAN_POLL_INTERVAL: int = 5

# --- Risk scoring thresholds -------------------------------------------

RISK_BAND_SAFE_MAX: int = 24
RISK_BAND_SUSPICIOUS_MAX: int = 59
RISK_BAND_DANGEROUS_MAX: int = 100

# Every point in a score traces back to one named signal in this table.
RISK_WEIGHTS: dict[str, int] = {
    # attachments
    "VT_MALICIOUS_HIGH": 60,        # 5+ engines flagged malicious
    "VT_MALICIOUS_LOW": 40,         # 1-4 engines flagged malicious
    "VT_SUSPICIOUS_ONLY": 15,
    "EXTENSION_MISMATCH": 35,
    "EXECUTABLE_TYPE": 30,
    "PASSWORD_PROTECTED_ARCHIVE": 20,  # ZIP/7z only; see eml_parser._is_password_protected_archive
    "MACRO_ENABLED_DOCUMENT": 15,
    # urls
    "SAFE_BROWSING_MALWARE_SOCIAL": 55,
    "SAFE_BROWSING_UNWANTED_HARMFUL": 30,
    "URLSCAN_MALICIOUS": 40,
    "URLSCAN_HIGH_SCORE_UNFLAGGED": 15,
    "DISPLAY_MISMATCH": 25,
    "SHORTENER": 10,
    "RAW_IP_HOST": 20,
    "PUNYCODE": 25,
    # sender IP
    "ABUSEIPDB_75_100": 45,
    "ABUSEIPDB_40_74": 25,
    "ABUSEIPDB_15_39": 10,
    # headers
    "SPF_FAIL": 20,
    "DKIM_FAIL": 20,
    "DMARC_FAIL": 25,
    "ALL_AUTH_ABSENT": 10,
    "REPLY_TO_MISMATCH": 20,
    "DISPLAY_NAME_SPOOF": 25,
}

# URLScan's quota is small (100/day, 60/hour, 2/minute), so only this many
# URLs per scan go to it, and none at all if Safe Browsing already found a
# malicious link.
MAX_URLSCAN_CALLS_PER_SCAN: int = 5

# Time budgets for the two slow providers. The frontend gives up polling
# after 2 minutes, so a scan has to finish well inside that. Once a budget
# is spent, no new URLScan submission or VirusTotal upload is started; the
# ones that were skipped are marked UNAVAILABLE. One URLScan call can take
# up to ~70s by itself, so the budget is checked before each call, not
# during it.
URLSCAN_TIME_BUDGET_SECONDS: int = 40
VIRUSTOTAL_UPLOAD_TIME_BUDGET_SECONDS: int = 40

# Polling for a file just uploaded to VirusTotal. Kept short because the
# free tier allows 4 requests a minute and a whole scan should finish in
# about 90 seconds.
VIRUSTOTAL_ANALYSIS_MAX_POLLS: int = 4
VIRUSTOTAL_ANALYSIS_POLL_INTERVAL: int = 15

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly",
}

EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".js", ".vbs", ".jar"}


def validate_secret_key() -> None:
    """Exit outside development if SECRET_KEY was never set."""
    if FLASK_ENV != "development" and SECRET_KEY == _DEV_SECRET_KEY:
        sys.stderr.write(
            "RedFlag refuses to start: SECRET_KEY is not set. Set it to a long "
            "random string, e.g. the output of: "
            "python -c 'import secrets; print(secrets.token_hex(32))'\n"
        )
        sys.exit(1)


def validate_provider_keys(strict: bool = True) -> list[str]:
    """Return the names of any missing provider keys.

    Outside development, with strict=True, a missing key stops the process
    so the app can't start half-configured.
    """
    missing = [name for name, value in _REQUIRED_KEYS.items() if not value]
    if missing and strict and FLASK_ENV != "development":
        sys.stderr.write(
            "RedFlag refuses to start: missing required API keys: "
            f"{', '.join(missing)}\n"
        )
        sys.exit(1)
    return missing
