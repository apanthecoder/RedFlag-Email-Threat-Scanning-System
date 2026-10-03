"""Create the admin account with a bcrypt-hashed password.

Usage:
    python -m database.seed_admin --username admin --password "change-me"

Without --password, a random password is generated and printed once. It
can't be recovered later because only the hash is stored. An existing
username is left alone unless you pass --force, which resets its password.
"""

from __future__ import annotations

import argparse
import secrets
import sys

import bcrypt

from database.models import create_admin_user, get_admin_by_username
from database.db import get_connection, init_db


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def reset_password(username: str, plain: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE admin_users SET password_hash = ? WHERE username = ?",
            (hash_password(plain), username),
        )
        conn.commit()


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed the RedFlag admin account.")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default=None, help="Omit to auto-generate one.")
    parser.add_argument(
        "--force", action="store_true", help="Reset the password if the account already exists."
    )
    args = parser.parse_args()

    init_db()  # safe even if the schema already exists

    password = args.password or secrets.token_urlsafe(16)

    existing = get_admin_by_username(args.username)
    if existing:
        if not args.force:
            print(
                f"Admin '{args.username}' already exists. Pass --force to reset its password.",
                file=sys.stderr,
            )
            sys.exit(1)
        reset_password(args.username, password)
        print(f"Password reset for existing admin '{args.username}'.")
    else:
        create_admin_user(args.username, hash_password(password))
        print(f"Admin '{args.username}' created.")

    if not args.password:
        print(f"Generated password (shown once): {password}")


if __name__ == "__main__":
    main()
