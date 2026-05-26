from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, abort
from flask_login import login_required, current_user
from app import db
from app.models.vault import VaultEntry
from app.utils.logger import log_event
from app.utils.crypto import encrypt_password, decrypt_password
from datetime import UTC, datetime

vault_bp = Blueprint("vault", __name__, url_prefix="/vault")


@vault_bp.route("/")
@login_required
def index():
    entries = VaultEntry.query.filter_by(user_id=current_user.id).all()
    for entry in entries:
        entry.plain_password = decrypt_password(entry.password)
    # FIX A09: Log vault access
    log_event("vault_view", user_id=current_user.id, ip_address=request.remote_addr)
    return render_template("vault/index.html", entries=entries)


@vault_bp.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        site_name = request.form.get("site_name", "").strip()
        site_url = request.form.get("site_url", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        notes = request.form.get("notes", "").strip()

        if not site_name or not username or not password:
            flash("Site name, username and password are required.", "danger")
            return render_template("vault/add.html")

        entry = VaultEntry(
            user_id=current_user.id,
            site_name=site_name,
            site_url=site_url,
            username=username,
            # FIX A04: AES-256 encrypted
            password=encrypt_password(password),
            notes=notes
        )
        db.session.add(entry)
        db.session.commit()

        log_event("vault_add", user_id=current_user.id,
                  details=f"Added entry for {site_name}",
                  ip_address=request.remote_addr)

        flash("Entry added successfully!", "success")
        return redirect(url_for("vault.index"))

    return render_template("vault/add.html")


@vault_bp.route("/edit/<int:entry_id>", methods=["GET", "POST"])
@login_required
def edit(entry_id):
    entry = VaultEntry.query.get_or_404(entry_id)

    # FIX A01: Ownership check — abort 403 if entry belongs to another user
    if entry.user_id != current_user.id:
        log_event("vault_unauthorized_edit", user_id=current_user.id,
                  details=f"Attempted to edit entry {entry_id} owned by user {entry.user_id}",
                  ip_address=request.remote_addr, status="failure")
        abort(403)

    if request.method == "POST":
        entry.site_name = request.form.get("site_name", entry.site_name).strip()
        entry.site_url = request.form.get("site_url", entry.site_url).strip()
        entry.username = request.form.get("username", entry.username).strip()
        new_password = request.form.get("password", "")
        if new_password:
            entry.password = encrypt_password(new_password)
        entry.notes = request.form.get("notes", entry.notes).strip()
        entry.updated_at = datetime.now(UTC)
        db.session.commit()

        log_event("vault_edit", user_id=current_user.id,
                  details=f"Edited entry {entry_id}",
                  ip_address=request.remote_addr)

        flash("Entry updated!", "success")
        return redirect(url_for("vault.index"))

    entry.plain_password = decrypt_password(entry.password)
    return render_template("vault/edit.html", entry=entry)


@vault_bp.route("/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete(entry_id):
    entry = VaultEntry.query.get_or_404(entry_id)

    # FIX A01: Ownership check
    if entry.user_id != current_user.id:
        log_event("vault_unauthorized_delete", user_id=current_user.id,
                  details=f"Attempted to delete entry {entry_id} owned by user {entry.user_id}",
                  ip_address=request.remote_addr, status="failure")
        abort(403)

    db.session.delete(entry)
    db.session.commit()

    log_event("vault_delete", user_id=current_user.id,
              details=f"Deleted entry {entry_id}",
              ip_address=request.remote_addr)

    flash("Entry deleted.", "info")
    return redirect(url_for("vault.index"))


@vault_bp.route("/reveal/<int:entry_id>")
@login_required
def reveal(entry_id):
    entry = VaultEntry.query.get_or_404(entry_id)

    # FIX A01: Ownership check
    if entry.user_id != current_user.id:
        log_event("vault_unauthorized_reveal", user_id=current_user.id,
                  details=f"Attempted to reveal entry {entry_id} owned by user {entry.user_id}",
                  ip_address=request.remote_addr, status="failure")
        abort(403)

    log_event("vault_reveal", user_id=current_user.id,
              details=f"Revealed password for entry {entry_id}",
              ip_address=request.remote_addr)

    return jsonify({"password": decrypt_password(entry.password)})
