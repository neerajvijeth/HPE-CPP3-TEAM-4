from flask import Flask, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from app.config import Config

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()

class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            header_names = {h[0].lower() for h in headers}
            if "x-content-type-options" not in header_names:
                headers.append(("X-Content-Type-Options", "nosniff"))
            if "x-frame-options" not in header_names:
                headers.append(("X-Frame-Options", "DENY"))
            if "content-security-policy" not in header_names:
                headers.append(("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self';"))
            if "cross-origin-embedder-policy" not in header_names:
                headers.append(("Cross-Origin-Embedder-Policy", "require-corp"))
            if "cross-origin-opener-policy" not in header_names:
                headers.append(("Cross-Origin-Opener-Policy", "same-origin"))
            if "cross-origin-resource-policy" not in header_names:
                headers.append(("Cross-Origin-Resource-Policy", "same-origin"))
            if "x-xss-protection" not in header_names:
                headers.append(("X-XSS-Protection", "1; mode=block"))
            if "referrer-policy" not in header_names:
                headers.append(("Referrer-Policy", "strict-origin-when-cross-origin"))
            if "strict-transport-security" not in header_names:
                headers.append(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
            
            # Remove Server header if present
            headers = [h for h in headers if h[0].lower() != "server"]
            
            return start_response(status, headers, exc_info)
        return self.app(environ, custom_start_response)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    from app.models.secdebt import SecDebtFinding, SecDebtScanRun
    login_manager.init_app(app)
    migrate.init_app(app, db)
    # FIX A02: Enable CSRF protection on all POST forms
    csrf.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."

    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # FIX A02: Add security headers to every response via WSGI middleware
    app.wsgi_app = SecurityHeadersMiddleware(app.wsgi_app)

    # Custom error handlers to prevent application error disclosure
    @app.errorhandler(404)
    def not_found_error(error):
        return {"error": "Not found"}, 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return {"error": "Internal server error"}, 500

    @app.errorhandler(403)
    def forbidden_error(error):
        return {"error": "Forbidden"}, 403

    @app.errorhandler(400)
    def bad_request_error(error):
        return {"error": "Bad request"}, 400

    @app.errorhandler(405)
    def method_not_allowed_error(error):
        return {"error": "Method not allowed"}, 405

    # Catch-all: prevent Gunicorn/Werkzeug stack traces from leaking
    @app.errorhandler(Exception)
    def unhandled_exception(error):
        db.session.rollback()
        return {"error": "Internal server error"}, 500

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
