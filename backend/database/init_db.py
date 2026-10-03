"""Apply schema.sql to the SQLite database.

Usage:
    python -m database.init_db
"""

from __future__ import annotations

from database.db import init_db

if __name__ == "__main__":
    init_db()
    print("Schema applied.")
