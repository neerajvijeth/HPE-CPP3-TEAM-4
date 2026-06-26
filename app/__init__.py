from flask_talisman import Talisman
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

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    from app.models.secdebt import SecDebtFinding, SecDebtScanRun
    login_manager.init_app(app)
    migrate.init_app(app, db)
    # FIX A02: Enable CSRF protection on all POST forms
    csrf.init_app(app)

    # FIX A02: Use Flask-Talisman for robust security headers
    csp = {
        'default-src': '\'self\'',
        'script-src': '\'self\'',
        'style-src': '\'self\'',
        'font-src': '\'self\'',
        'img-src': ['\'self\'', 'data:'],
        'frame-ancestors': '\'self\'',
        'form-action': '\'self\''
    }
    Talisman(app, 
             content_security_policy=csp, 
             frame_options='SAMEORIGIN',
             force_https=False,
             session_cookie_secure=False)


    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."

    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    from flask_wtf.csrf import CSRFError
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return {"error": "CSRF token missing or invalid"}, 400

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
