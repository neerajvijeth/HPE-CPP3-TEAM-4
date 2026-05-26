from app import db
from datetime import datetime


class VaultEntry(db.Model):
    __tablename__ = "vault_entries"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    site_name = db.Column(db.String(200), nullable=False)
    site_url = db.Column(db.String(500), nullable=True)
    username = db.Column(db.String(200), nullable=False)
    # FIX A04: Passwords stored AES-256 encrypted
    password = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<VaultEntry {self.site_name}>"
