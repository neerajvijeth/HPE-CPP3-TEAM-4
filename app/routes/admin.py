from flask import Blueprint, render_template, redirect, url_for, flash, abort, request
from flask_login import login_required, current_user
from app import db
from app.models.user import User
from app.models.audit import AuditLog
from app.utils.logger import log_event
from functools import wraps

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(f):
    """
    FIX A01: Decorator that enforces admin role server-side.
    Applied to every admin route — not just hidden in the UI.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))
        if not current_user.is_admin():
            log_event("admin_unauthorized_access", user_id=current_user.id,
                      details=f"Attempted to access {request.path}",
                      ip_address=request.remote_addr, status="failure")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route("/dashboard")
@login_required
@admin_required  # FIX A01: Role check enforced server-side
def dashboard():
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_logs = AuditLog.query.count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    log_event("admin_dashboard_view", user_id=current_user.id,
              ip_address=request.remote_addr)
    return render_template("admin/dashboard.html",
                           total_users=total_users,
                           active_users=active_users,
                           total_logs=total_logs,
                           recent_logs=recent_logs)


@admin_bp.route("/users")
@login_required
@admin_required  # FIX A01
def users():
    all_users = User.query.all()
    log_event("admin_users_view", user_id=current_user.id,
              ip_address=request.remote_addr)
    return render_template("admin/users.html", users=all_users)


@admin_bp.route("/users/toggle/<int:user_id>", methods=["POST"])
@login_required
@admin_required  # FIX A01
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot disable your own account.", "danger")
        return redirect(url_for("admin.users"))
    user.is_active = not user.is_active
    db.session.commit()
    status = "enabled" if user.is_active else "disabled"
    log_event("admin_toggle_user", user_id=current_user.id,
              details=f"User {user.username} {status}",
              ip_address=request.remote_addr)
    flash(f"User {user.username} has been {status}.", "info")
    return redirect(url_for("admin.users"))


@admin_bp.route("/logs")
@login_required
@admin_required  # FIX A01
def logs():
    all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template("admin/logs.html", logs=all_logs)
