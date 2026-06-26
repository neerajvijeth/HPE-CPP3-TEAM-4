import secrets

from flask import Flask, abort, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from app.config import Config

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()

CSRF_PROTECTED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    from app.models.secdebt import SecDebtFinding, SecDebtScanRun  # noqa: F401
    login_manager.init_app(app)
    migrate.init_app(app, db)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."

    register_login_loader()
    register_csrf_hooks(app)
    register_security_headers(app)
    register_error_handlers(app)
    register_blueprints(app)

    return app


def register_login_loader():
    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


def register_csrf_hooks(app):
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
        if request.method not in CSRF_PROTECTED_METHODS:
            return
        if request.endpoint == "secdebt.api_ingest":
            return

        expected = session.get("_csrf_token")
        provided = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not expected or not secrets.compare_digest(expected, provided or ""):
            abort(400)


def register_security_headers(app):
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


def register_error_handlers(app):
    def _error_response(message, status_code):
        wants_json = (
            request.path.startswith("/secdebt/api/")
            or request.accept_mimetypes.best == "application/json"
        )
        if wants_json:
            return {"error": message}, status_code
        return message, status_code

    @app.errorhandler(400)
    def bad_request_error(error):
        del error
        return _error_response("Bad request", 400)

    @app.errorhandler(403)
    def forbidden_error(error):
        del error
        return _error_response("Forbidden", 403)

    @app.errorhandler(404)
    def not_found_error(error):
        del error
        return _error_response("Not found", 404)

    @app.errorhandler(405)
    def method_not_allowed_error(error):
        del error
        return _error_response("Method not allowed", 405)

    @app.errorhandler(500)
    def internal_error(error):
        del error
        db.session.rollback()
        return _error_response("Internal server error", 500)


def register_blueprints(app):
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
