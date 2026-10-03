"""RedFlag Flask entry point.

Registers the blueprints, sets up CORS and adds JSON error handlers, so
the frontend never gets Flask's default HTML error page.
"""

from __future__ import annotations

import os

from flask import Flask, abort, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

import config
from database.db import init_db
from utils.exceptions import (
    ParsingError,
    ProviderError,
    ProviderTimeout,
    ValidationError,
)
from utils.logger import get_logger

logger = get_logger(__name__)


def envelope(success: bool, data=None, error=None):
    return {"success": success, "data": data, "error": error}


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_SIZE_BYTES
    # Flask's signed session cookie is used for admin login only. Visitors
    # get a separate anonymous rf_session cookie (routes/scan.py).
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SECURE"] = config.FLASK_ENV != "development"

    # Trust one proxy hop, the host's load balancer. Without this every
    # request looks like it came from the proxy, and all visitors would
    # share a single login rate-limit bucket.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    CORS(
        app,
        origins=[config.FRONTEND_ORIGIN],
        supports_credentials=True,
    )

    # Safe to run on every boot: the schema uses CREATE ... IF NOT EXISTS
    # and the admin is only created if missing. They have to run every time
    # because the free hosting tier starts from an empty disk.
    init_db()
    ensure_admin_account()

    config.validate_secret_key()
    missing_keys = config.validate_provider_keys()
    if missing_keys:
        logger.warning(
            "Starting with missing provider keys (dev mode only): %s",
            ", ".join(missing_keys),
        )

    from routes.admin import admin_bp
    from routes.health import health_bp
    from routes.scan import scan_bp

    app.register_blueprint(health_bp, url_prefix="/api")
    app.register_blueprint(scan_bp, url_prefix="/api")
    app.register_blueprint(admin_bp, url_prefix="/api")

    register_error_handlers(app)
    register_frontend(app)

    return app


def ensure_admin_account() -> None:
    """Create the admin from ADMIN_USERNAME and ADMIN_PASSWORD if it doesn't
    exist yet. Does nothing if either is unset, as on a development machine."""
    if not config.ADMIN_USERNAME or not config.ADMIN_PASSWORD:
        return

    from database.models import create_admin_user, get_admin_by_username
    from database.seed_admin import hash_password

    if get_admin_by_username(config.ADMIN_USERNAME):
        return
    create_admin_user(config.ADMIN_USERNAME, hash_password(config.ADMIN_PASSWORD))
    logger.info("Created admin account %r from the environment", config.ADMIN_USERNAME)


def register_frontend(app: Flask) -> None:
    """Serve the built React app from the same address as the API.

    /api paths belong to the blueprints. Anything else is either a built
    file or gets index.html, so refreshing /history or /admin still works
    with React Router.
    """

    @app.get("/", defaults={"path": ""})
    @app.get("/<path:path>")
    def frontend(path: str):
        if path.startswith("api/"):
            abort(404)

        if not os.path.isdir(config.FRONTEND_DIST):
            return jsonify(envelope(False, error={
                "code": "NO_FRONTEND_BUILD",
                "message": "The frontend has not been built. Run 'npm run build' in frontend/.",
            })), 501

        candidate = os.path.join(config.FRONTEND_DIST, path)
        if path and os.path.isfile(candidate):
            return send_from_directory(config.FRONTEND_DIST, path)
        return send_from_directory(config.FRONTEND_DIST, "index.html")


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(ValidationError)
    def handle_validation_error(exc: ValidationError):
        return jsonify(envelope(False, error={"code": exc.code, "message": exc.message})), 400

    @app.errorhandler(ParsingError)
    def handle_parsing_error(exc: ParsingError):
        return jsonify(envelope(False, error={"code": exc.code, "message": exc.message})), 400

    @app.errorhandler(ProviderError)
    def handle_provider_error(exc: ProviderError):
        logger.error("Provider error: %s", exc)
        return jsonify(envelope(False, error={"code": "PROVIDER_ERROR", "message": "A threat intelligence provider failed."})), 502

    @app.errorhandler(ProviderTimeout)
    def handle_provider_timeout(exc: ProviderTimeout):
        logger.error("Provider timeout: %s", exc)
        return jsonify(envelope(False, error={"code": "PROVIDER_TIMEOUT", "message": "A threat intelligence provider timed out."})), 504

    @app.errorhandler(400)
    def handle_400(exc):
        return jsonify(envelope(False, error={"code": "BAD_REQUEST", "message": "The request could not be understood."})), 400

    @app.errorhandler(401)
    def handle_401(exc):
        return jsonify(envelope(False, error={"code": "UNAUTHENTICATED", "message": "Authentication required."})), 401

    @app.errorhandler(404)
    def handle_404(exc):
        return jsonify(envelope(False, error={"code": "NOT_FOUND", "message": "The requested resource was not found."})), 404

    @app.errorhandler(413)
    def handle_413(exc):
        return jsonify(envelope(False, error={"code": "FILE_TOO_LARGE", "message": "The uploaded file exceeds the 10 MB limit."})), 413

    @app.errorhandler(429)
    def handle_429(exc):
        return jsonify(envelope(False, error={"code": "RATE_LIMITED", "message": "Too many requests. Please slow down."})), 429

    @app.errorhandler(500)
    def handle_500(exc):
        logger.exception("Unhandled server error")
        return jsonify(envelope(False, error={"code": "INTERNAL_ERROR", "message": "Something went wrong on our end."})), 500


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
