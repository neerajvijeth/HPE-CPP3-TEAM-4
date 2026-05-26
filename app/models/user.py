from flask_login import UserMixin
from app import db
from datetime import UTC, datetime, timedelta
import bcrypt


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")
    is_active = db.Column(db.Boolean, default=True)

    # Lockout tracking
    failed_login_count = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    profile_picture = db.Column(db.String(255), default="default.png")

    # ✅ FIX: use lambda so it's evaluated at runtime (not import time)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    last_login = db.Column(db.DateTime, nullable=True)

    vault_entries = db.relationship(
        "VaultEntry", backref="owner", lazy=True, cascade="all, delete-orphan"
    )
    audit_logs = db.relationship(
        "AuditLog", backref="user", lazy=True, cascade="all, delete-orphan"
    )

    # ================= PASSWORD =================
    def set_password(self, password):
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(password.encode(), salt).decode()

    def check_password(self, password):
        return bcrypt.checkpw(password.encode(), self.password_hash.encode())

    # ================= ROLE =================
    def is_admin(self):
        return self.role == "admin"

    # ================= LOCKOUT =================
    def is_locked(self):
        if not self.locked_until:
            return False

        locked_until = self.locked_until

        # ✅ FIX: convert old naive datetime → UTC-aware
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=UTC)

        return datetime.now(UTC) < locked_until

    def increment_failed_login(self, max_attempts=5, lockout_minutes=15):
        self.failed_login_count += 1

        if self.failed_login_count >= max_attempts:
            # ✅ FIX: always store UTC-aware datetime
            self.locked_until = datetime.now(UTC) + timedelta(minutes=lockout_minutes)

    def reset_failed_login(self):
        self.failed_login_count = 0
        self.locked_until = None

    def __repr__(self):
        return f"<User {self.username}>"