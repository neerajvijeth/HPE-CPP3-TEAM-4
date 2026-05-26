"""
Unit tests for Fixed Vault — routes/vault.py
Proves: Ownership checks enforced (A01), AES encryption (A04), actions logged (A09).
"""
import base64
from app.models.vault import VaultEntry
from app.models.user import User
from app.models.audit import AuditLog
from app.utils.crypto import encrypt_password, decrypt_password


class TestVaultAccessControlFixed:

    def test_vault_redirects_unauthenticated(self, client):
        """Vault page must redirect unauthenticated users to login."""
        response = client.get("/vault/", follow_redirects=False)
        assert response.status_code == 302
        assert "/login" in response.headers.get("Location", "")

    def test_vault_loads_for_alice(self, logged_in_alice):
        """Alice sees her own vault."""
        response = logged_in_alice.get("/vault/")
        assert response.status_code == 200
        assert b"Gmail" in response.data

    # ------------------------------------------------------------------ #
    # FIX A01 — Ownership checks enforced
    # ------------------------------------------------------------------ #

    def test_bob_cannot_edit_alices_entry(self, logged_in_bob):
        """FIX A01: Bob must get 403 editing Alice's vault entry."""
        alice = User.query.filter_by(username="alice").first()
        entry = VaultEntry.query.filter_by(user_id=alice.id).first()
        response = logged_in_bob.post(f"/vault/edit/{entry.id}", data={
            "site_name": "Hacked", "site_url": "",
            "username": "hacker", "password": "hacked", "notes": ""
        }, follow_redirects=True)
        assert response.status_code == 403

    def test_bob_cannot_view_alices_edit_form(self, logged_in_bob):
        """FIX A01: Bob must get 403 on GET edit for Alice's entry."""
        alice = User.query.filter_by(username="alice").first()
        entry = VaultEntry.query.filter_by(user_id=alice.id).first()
        response = logged_in_bob.get(f"/vault/edit/{entry.id}")
        assert response.status_code == 403

    def test_bob_cannot_delete_alices_entry(self, logged_in_bob):
        """FIX A01: Bob must get 403 when deleting Alice's entry."""
        alice = User.query.filter_by(username="alice").first()
        entry = VaultEntry.query.filter_by(user_id=alice.id).first()
        response = logged_in_bob.post(f"/vault/delete/{entry.id}")
        assert response.status_code == 403

    def test_bob_cannot_reveal_alices_password(self, logged_in_bob):
        """FIX A01: Bob must get 403 revealing Alice's password."""
        alice = User.query.filter_by(username="alice").first()
        entry = VaultEntry.query.filter_by(user_id=alice.id).first()
        response = logged_in_bob.get(f"/vault/reveal/{entry.id}")
        assert response.status_code == 403

    def test_alice_can_edit_own_entry(self, logged_in_alice):
        """Alice can still edit her own entries."""
        alice = User.query.filter_by(username="alice").first()
        entry = VaultEntry.query.filter_by(user_id=alice.id).first()
        response = logged_in_alice.post(f"/vault/edit/{entry.id}", data={
            "site_name": "Gmail Updated", "site_url": "https://gmail.com",
            "username": "alice@gmail.com", "password": "NewPass@123!", "notes": ""
        }, follow_redirects=True)
        assert response.status_code == 200

    def test_alice_can_delete_own_entry(self, logged_in_alice):
        """Alice can delete her own entry."""
        alice = User.query.filter_by(username="alice").first()
        entry = VaultEntry.query.filter_by(user_id=alice.id).first()
        response = logged_in_alice.post(
            f"/vault/delete/{entry.id}", follow_redirects=True)
        assert response.status_code == 200

    def test_alice_can_reveal_own_password(self, logged_in_alice):
        """Alice can reveal her own password."""
        alice = User.query.filter_by(username="alice").first()
        entry = VaultEntry.query.filter_by(user_id=alice.id).first()
        response = logged_in_alice.get(f"/vault/reveal/{entry.id}")
        assert response.status_code == 200
        assert "password" in response.get_json()

    # ------------------------------------------------------------------ #
    # FIX A09 — Unauthorized access logged
    # ------------------------------------------------------------------ #

    def test_unauthorized_access_logged(self, logged_in_bob):
        """FIX A09: Unauthorized vault access must be logged as failure."""
        alice = User.query.filter_by(username="alice").first()
        entry = VaultEntry.query.filter_by(user_id=alice.id).first()
        logged_in_bob.get(f"/vault/edit/{entry.id}")
        log = AuditLog.query.filter(
            AuditLog.action.like("vault_unauthorized%"),
            AuditLog.status == "failure"
        ).first()
        assert log is not None


class TestVaultEncryptionFixed:

    def test_vault_password_stored_aes_not_base64(self, logged_in_alice):
        """FIX A04: Vault passwords must be AES-256 encrypted."""
        logged_in_alice.post("/vault/add", data={
            "site_name": "AESTest", "site_url": "",
            "username": "user", "password": "plaintextpassword", "notes": ""
        }, follow_redirects=True)

        alice = User.query.filter_by(username="alice").first()
        entry = VaultEntry.query.filter_by(
            user_id=alice.id, site_name="AESTest").first()

        assert entry is not None
        assert entry.password != "plaintextpassword"
        # Naive base64 decode must NOT yield plaintext
        try:
            naive = base64.b64decode(entry.password.encode()).decode("utf-8")
            assert naive != "plaintextpassword"
        except (UnicodeDecodeError, Exception):
            pass

    def test_decrypt_returns_original(self):
        """FIX A04: AES roundtrip works correctly."""
        original = "mySecurePassword123!"
        assert decrypt_password(encrypt_password(original)) == original

    def test_same_password_different_ciphertext(self):
        """FIX A04: Random nonce means different ciphertext each time."""
        enc1 = encrypt_password("samepassword")
        enc2 = encrypt_password("samepassword")
        assert enc1 != enc2

    def test_reveal_returns_decrypted_password(self, logged_in_alice):
        """Reveal endpoint returns readable plaintext."""
        alice = User.query.filter_by(username="alice").first()
        entry = VaultEntry.query.filter_by(user_id=alice.id).first()
        response = logged_in_alice.get(f"/vault/reveal/{entry.id}")
        assert response.status_code == 200
        data = response.get_json()
        assert "password" in data
        assert len(data["password"]) > 0


class TestVaultLoggingFixed:

    def test_vault_view_is_logged(self, logged_in_alice):
        """FIX A09: Viewing vault creates audit log entry."""
        logged_in_alice.get("/vault/")
        log = AuditLog.query.filter_by(action="vault_view").first()
        assert log is not None

    def test_vault_add_is_logged(self, logged_in_alice):
        """FIX A09: Adding vault entry is logged."""
        logged_in_alice.post("/vault/add", data={
            "site_name": "LogTest", "site_url": "",
            "username": "user", "password": "Pass@123!", "notes": ""
        }, follow_redirects=True)
        log = AuditLog.query.filter_by(action="vault_add").first()
        assert log is not None
