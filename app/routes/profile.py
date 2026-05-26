from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app
from flask_login import login_required, current_user
from app import db
from app.utils.validators import (allowed_file, validate_file_content,
                                   sanitize_filename, validate_password_strength,
                                   validate_email)
from app.utils.logger import log_event
import os

profile_bp = Blueprint("profile", __name__, url_prefix="/profile")


@profile_bp.route("/")
@login_required
def index():
    return render_template("profile/index.html")


@profile_bp.route("/update", methods=["POST"])
@login_required
def update():
    new_email = request.form.get("email", "").strip()
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if new_email:
        # FIX A07: Validate email format
        if not validate_email(new_email):
            flash("Please enter a valid email address.", "danger")
            return redirect(url_for("profile.index"))
        current_user.email = new_email

    if new_password:
        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("profile.index"))

        # FIX A07: Enforce password strength on update too
        is_valid, error_msg = validate_password_strength(new_password)
        if not is_valid:
            flash(error_msg, "danger")
            return redirect(url_for("profile.index"))

        current_user.set_password(new_password)  # FIX A04: bcrypt

    db.session.commit()
    log_event("profile_update", user_id=current_user.id, ip_address=request.remote_addr)
    flash("Profile updated successfully!", "success")
    return redirect(url_for("profile.index"))


@profile_bp.route("/upload", methods=["POST"])
@login_required
def upload():
    if "profile_picture" not in request.files:
        flash("No file selected.", "danger")
        return redirect(url_for("profile.index"))

    file = request.files["profile_picture"]

    if file.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("profile.index"))

    # FIX A03: Check extension against allowlist
    if not allowed_file(file.filename):
        log_event("upload_rejected", user_id=current_user.id,
                  details=f"Rejected file: {file.filename}",
                  ip_address=request.remote_addr, status="failure")
        flash("File type not allowed. Only PNG, JPG, GIF, WEBP accepted.", "danger")
        return redirect(url_for("profile.index"))

    # FIX A03: Read file bytes and validate magic bytes (not just extension)
    file_bytes = file.read()
    if not validate_file_content(file_bytes):
        flash("File content does not match an allowed image type.", "danger")
        return redirect(url_for("profile.index"))

    # FIX A03: Generate safe random filename — no attacker control over path
    filename = sanitize_filename(file.filename)

    upload_path = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_path, exist_ok=True)

    # FIX A03: Save with safe filename to upload directory only
    save_path = os.path.join(upload_path, filename)
    with open(save_path, "wb") as f:
        f.write(file_bytes)

    current_user.profile_picture = filename
    db.session.commit()

    log_event("profile_picture_upload", user_id=current_user.id,
              details=f"Uploaded {filename}", ip_address=request.remote_addr)
    flash("Profile picture updated!", "success")
    return redirect(url_for("profile.index"))
