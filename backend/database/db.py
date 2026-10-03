"""SQLite connection helpers. Apart from schema.sql, this is the only
module that deals with connections. Everything else goes through
models.py.

SQLite doesn't need a connection pool. Opening a connection is cheap and
the database file serialises writes, so each helper opens a short-lived
connection with foreign keys on and a busy timeout.
"""

from __future__ import annotations

import contextlib
import sqlite3
from typing import Iterator

import config
from utils.logger import get_logger

logger = get_logger(__name__)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextlib.contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """Yield a connection; always closes it on exit."""
    conn = _connect()
    try:
        yield conn
    finally:
        conn.close()


@contextlib.contextmanager
def transaction() -> Iterator[sqlite3.Cursor]:
    """Yield a cursor inside a transaction. Commits at the end, or rolls
    back if anything raises.

    Use it for writes that span tables, like a finished scan, which writes
    to scans, header_results, url_results, attachment_results and
    advisory_outputs. Either all of it is saved or none of it is.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()


def init_db() -> None:
    """Apply schema.sql. Safe to repeat: every statement is CREATE ... IF NOT EXISTS."""
    import os

    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = f.read()

    with get_connection() as conn:
        conn.executescript(schema)
        conn.commit()
    logger.info("Database schema applied at %s", config.DB_PATH)


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    return [dict(row) for row in rows]


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None
