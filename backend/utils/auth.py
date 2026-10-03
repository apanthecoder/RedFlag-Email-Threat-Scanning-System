"""Admin authentication: bcrypt password checks and the require_admin
decorator. Admin login is a flag in Flask's signed session. It has nothing
to do with the anonymous rf_session cookie that routes/scan.py gives
every visitor.
"""

from __future__ import annotations

from functools import wraps

import bcrypt
from flask import jsonify, session


def verify_password(plain: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, AttributeError):
        return False


def require_admin(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({
                "success": False,
                "data": None,
                "error": {"code": "UNAUTHENTICATED", "message": "Admin authentication required."},
            }), 401
        return view_func(*args, **kwargs)

    return wrapper
