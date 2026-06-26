import secrets

from flask import Flask, abort, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from app.config import Config

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    from app.models.secdebt import SecDebtFinding, SecDebtScanRun  # noqa: F401
    login_manager.init_app(app)
    migrate.init_app(app, db)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."

    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.context_processor
    def inject_csrf_token():
        def csrf_token():
            token = session.get("_csrf_token")
            if not token:
                token = secrets.token_urlsafe(32)
                session["_csrf_token"] = token
            return token

        return {"csrf_token": csrf_token}

    @app.before_request
    def validate_csrf_token():
        if request.method == "OPTIONS":
            abort(405)
        if app.config.get("WTF_CSRF_ENABLED") is False:
            return
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return
        if request.endpoint == "secdebt.api_ingest":
            return

        expected = session.get("_csrf_token")
        provided = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not expected or not secrets.compare_digest(expected, provided or ""):
            abort(400)

    # FIX A02: Add security headers to every response.
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none';"
        )
        response.headers.pop("Server", None)
        return response

    from app.routes.auth import auth_bp
    from app.routes.vault import vault_bp
    from app.routes.admin import admin_bp
    from app.routes.profile import profile_bp
    from app.routes.fetcher import fetcher_bp
    from app.routes.secdebt import secdebt_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(fetcher_bp)
    app.register_blueprint(secdebt_bp)

    return app
