from dotenv import load_dotenv
load_dotenv()

from app import create_app, db
from app.models.user import User
from app.models.vault import VaultEntry
from app.models.audit import AuditLog
from app.utils.crypto import encrypt_password
import click

app = create_app()


@app.shell_context_processor
def make_shell_context():
    return {"db": db, "User": User, "VaultEntry": VaultEntry, "AuditLog": AuditLog}


@app.cli.command("seed-db")
def seed_db():
    """Seed the database with demo users and vault entries."""
    db.create_all()

    if User.query.filter_by(username="admin").first():
        click.echo("Database already seeded.")
        return

    # FIX A07: Strong passwords required in fixed version
    # FIX A04: Stored with bcrypt
    admin = User(username="admin", email="admin@securevault.local", role="admin")
    admin.set_password("Admin@SecureVault1!")
    db.session.add(admin)

    alice = User(username="alice", email="alice@example.com", role="user")
    alice.set_password("Alice@Secure123!")
    db.session.add(alice)

    bob = User(username="bob", email="bob@example.com", role="user")
    bob.set_password("Bob@Secure456!")
    db.session.add(bob)

    db.session.flush()

    # FIX A04: Vault passwords stored with AES-256 encryption
    entries = [
        VaultEntry(
            user_id=alice.id,
            site_name="Gmail",
            site_url="https://gmail.com",
            username="alice@gmail.com",
            password=encrypt_password("alicesecret123"),
            notes="Personal Gmail"
        ),
        VaultEntry(
            user_id=alice.id,
            site_name="GitHub",
            site_url="https://github.com",
            username="alice_dev",
            password=encrypt_password("githubPass456"),
        ),
    ]

    for entry in entries:
        db.session.add(entry)

    bob_entry = VaultEntry(
        user_id=bob.id,
        site_name="Twitter",
        site_url="https://twitter.com",
        username="bob_tweets",
        password=encrypt_password("twitter123"),
    )
    db.session.add(bob_entry)
    db.session.commit()

    click.echo("Database seeded successfully!")
    click.echo("Users created:")
    click.echo("  admin / Admin@SecureVault1!  (role: admin)")
    click.echo("  alice / Alice@Secure123!     (role: user)")
    click.echo("  bob   / Bob@Secure456!       (role: user)")


@app.cli.command("generate-keys")
def generate_keys():
    """Generate secure random keys for .env file."""
    import os
    import base64
    import secrets

    secret_key = secrets.token_hex(32)
    vault_key = base64.b64encode(os.urandom(32)).decode()

    click.echo("Add these to your .env file:")
    click.echo(f"SECRET_KEY={secret_key}")
    click.echo(f"VAULT_ENCRYPTION_KEY={vault_key}")


if __name__ == "__main__":
    app.run(debug=False)
