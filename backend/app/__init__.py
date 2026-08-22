"""Flask application factory."""

from __future__ import annotations

import os
from datetime import timedelta

from flask import Flask, g, request, session
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix

from backend.app.api import auth_bp, main_bp
from backend.app.api.extension_routes import api_bp
from backend.app.api.feedback_routes import feedback_bp
from backend.app.api.gmail_routes import gmail_bp
from backend.app.auth.helpers import load_current_user
from backend.app.config import Config
from backend.app.database import User, db
from backend.app.security import (
    apply_security_headers,
    generate_csrf_token,
    validate_csrf,
)


def create_app(config_object: type = Config) -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.from_object(config_object)
    app.permanent_session_lifetime = timedelta(days=7)
    # Trust X-Forwarded-* from Nginx / Cloudflare / Render
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(feedback_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(gmail_bp)

    @app.after_request
    def add_cors_headers(response):
        # Allow extension origins to call the API (token-authenticated)
        origin = request.headers.get("Origin", "")
        if origin.startswith("chrome-extension://") or origin.startswith("moz-extension://"):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-API-Token"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, OPTIONS"
            response.headers["Access-Control-Max-Age"] = "86400"
        return apply_security_headers(response)

    @app.before_request
    def _cors_preflight():
        if request.method == "OPTIONS":
            from flask import make_response
            resp = make_response("", 204)
            origin = request.headers.get("Origin", "")
            if origin.startswith("chrome-extension://") or origin.startswith("moz-extension://"):
                resp.headers["Access-Control-Allow-Origin"] = origin
                resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-API-Token"
                resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, OPTIONS"
                resp.headers["Access-Control-Max-Age"] = "86400"
            return resp

    @app.before_request
    def _csrf_and_user():
        load_current_user()
        # Enforce CSRF on mutating form posts (not JSON API)
        if request.method == "POST" and not request.is_json:
            # Skip CSRF only when explicitly disabled for tests
            if not app.config.get("WTF_CSRF_ENABLED", True):
                return
            # Allow login/register without prior token on first visit by issuing token via GET first
            # Still require token if session already has one OR for authenticated actions
            if request.endpoint not in (None, "static") and request.endpoint not in (
                "auth.login",
                "auth.register",
            ):
                validate_csrf()
            elif request.endpoint in ("auth.login", "auth.register"):
                # Soft CSRF: if token present in session, require match; else accept and set
                session_token = session.get("_csrf_token")
                form_token = request.form.get("csrf_token")
                if session_token and form_token and form_token != session_token:
                    from flask import abort
                    abort(400, description="CSRF validation failed")

    @app.context_processor
    def inject_globals():
        return {
            "current_user": g.get("user"),
            "csrf_token": generate_csrf_token,
        }

    with app.app_context():
        db.create_all()
        _ensure_admin()

    return app


def _ensure_admin() -> None:
    """Create a default admin if none exists (dev convenience)."""
    if User.query.filter_by(role="admin").first():
        return
    admin = User(
        email=os.environ.get("ADMIN_EMAIL", "admin@localhost"),
        role="admin",
    )
    admin.set_password(os.environ.get("ADMIN_PASSWORD", "admin12345"))
    db.session.add(admin)
    try:
        db.session.commit()
    except IntegrityError:
        # Gunicorn workers can race on first boot against SQLite
        db.session.rollback()
