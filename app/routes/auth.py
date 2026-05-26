from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models.user import User
from app.utils.logger import log_event
from app.utils.validators import validate_password_strength, validate_email
from app.config import Config
from datetime import datetime

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("vault.index"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("vault.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr

        # FIX A05: Parameterized query — user input never touches SQL structure
        user_obj = User.query.filter_by(username=username).first()

        if user_obj is None:
            # FIX A09: Log failed attempt
            # Generic message avoids leaking whether the username exists
            log_event("login_failed", details=f"Unknown username: {username}",
                      ip_address=ip, status="failure")
            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html")

        # FIX: Check disabled BEFORE password check.
        # Original code checked is_active AFTER check_password(), meaning a disabled
        # user who knows their password would pass the bcrypt gate before being blocked.
        # Moving it here is also more secure: no timing difference reveals whether a
        # disabled account's password is correct.
        if not user_obj.is_active:
            log_event("login_blocked", user_id=user_obj.id,
                      details="Disabled account", ip_address=ip, status="failure")
            flash("Your account has been disabled.", "danger")
            return render_template("auth/login.html")

        # FIX A07: Check if account is locked out due to too many failed attempts
        if user_obj.is_locked():
            log_event("login_blocked", user_id=user_obj.id,
                      details="Account locked", ip_address=ip, status="failure")
            flash(
                f"Account locked due to too many failed attempts. "
                f"Try again in {Config.LOGIN_LOCKOUT_MINUTES} minutes.",
                "danger"
            )
            return render_template("auth/login.html")

        if not user_obj.check_password(password):
            # FIX A07: Increment failed login counter and lock if threshold reached
            user_obj.increment_failed_login(
                max_attempts=Config.MAX_LOGIN_ATTEMPTS,
                lockout_minutes=Config.LOGIN_LOCKOUT_MINUTES
            )
            db.session.commit()

            remaining = Config.MAX_LOGIN_ATTEMPTS - user_obj.failed_login_count
            log_event("login_failed", user_id=user_obj.id,
                      details=f"Wrong password. {remaining} attempts remaining.",
                      ip_address=ip, status="failure")

            if user_obj.is_locked():
                flash(
                    f"Too many failed attempts. Account locked for "
                    f"{Config.LOGIN_LOCKOUT_MINUTES} minutes.",
                    "danger"
                )
            else:
                flash(
                    f"Invalid username or password. {remaining} attempts remaining.",
                    "danger"
                )
            return render_template("auth/login.html")

        # Credentials valid — reset counter and complete login
        # FIX A07: Reset failed login counter on successful authentication
        user_obj.reset_failed_login()
        login_user(user_obj)
        user_obj.last_login = datetime.utcnow()
        db.session.commit()

        # FIX A09: Log successful login
        log_event("login_success", user_id=user_obj.id, ip_address=ip)

        next_page = request.args.get("next")
        return redirect(next_page or url_for("vault.index"))

    return render_template("auth/login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("vault.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # FIX A07: Validate email format
        if not validate_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("auth/register.html")

        # FIX A07: Enforce password strength requirements
        is_valid, error_msg = validate_password_strength(password)
        if not is_valid:
            flash(error_msg, "danger")
            return render_template("auth/register.html")

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return render_template("auth/register.html")

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return render_template("auth/register.html")

        user = User(username=username, email=email)
        user.set_password(password)  # FIX A04: bcrypt hash
        db.session.add(user)
        db.session.commit()

        # FIX A09: Log registration event
        log_event("register", user_id=user.id, ip_address=request.remote_addr)

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/logout")
@login_required
def logout():
    # FIX A09: Log logout before clearing the session
    log_event("logout", user_id=current_user.id, ip_address=request.remote_addr)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))