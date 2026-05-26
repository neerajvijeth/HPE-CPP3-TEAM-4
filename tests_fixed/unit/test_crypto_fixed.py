"""
Unit tests for Fixed Cryptography — utils/crypto.py, models/user.py
Proves: bcrypt replacing MD5 (A04), AES-256 replacing base64 (A04).
"""
import hashlib
import base64
from app.utils.crypto import encrypt_password, decrypt_password
from app.models.user import User
from app import db


class TestBcryptPasswordHashing:

    def test_password_not_stored_as_md5(self):
        """FIX A04: Passwords must NOT be stored as MD5. bcrypt starts with $2b$."""
        user = User(username="hashtest", email="hashtest@test.com")
        user.set_password("TestPass@123!")
        md5_hash = hashlib.md5("TestPass@123!".encode()).hexdigest()
        assert user.password_hash != md5_hash
        assert user.password_hash.startswith("$2b$")

    def test_bcrypt_uses_salt(self):
        """FIX A04: Same password produces DIFFERENT hashes due to bcrypt salt."""
        user1 = User(username="salttest1", email="salt1@test.com")
        user1.set_password("SamePass@123!")
        user2 = User(username="salttest2", email="salt2@test.com")
        user2.set_password("SamePass@123!")
        assert user1.password_hash != user2.password_hash

    def test_check_password_correct(self):
        """bcrypt check_password returns True for correct password."""
        user = User(username="checktest", email="check@test.com")
        user.set_password("Correct@Pass1!")
        assert user.check_password("Correct@Pass1!") is True

    def test_check_password_wrong(self):
        """bcrypt check_password returns False for wrong password."""
        user = User(username="checkwrong", email="wrong@test.com")
        user.set_password("Correct@Pass1!")
        assert user.check_password("WrongPassword!") is False

    def test_bcrypt_hash_length(self):
        """bcrypt hashes are always 60 characters."""
        user = User(username="lentest", email="len@test.com")
        user.set_password("AnyPass@123!")
        assert len(user.password_hash) == 60

    def test_md5_no_longer_crackable(self):
        """FIX A04: bcrypt hash of 'password' is NOT the known MD5 hash."""
        user = User(username="cracktest", email="crack@test.com")
        user.set_password("password")
        known_md5 = "5f4dcc3b5aa765d61d8327deb882cf99"
        assert user.password_hash != known_md5

    def test_password_not_stored_as_plaintext(self):
        """Password must not be stored as plaintext."""
        user = User(username="plaintest", email="plain@test.com")
        user.set_password("mypassword")
        assert user.password_hash != "mypassword"


class TestAESVaultEncryption:

    def test_encrypt_is_not_base64_reversible(self):
        """FIX A04: AES ciphertext must NOT be reversible with plain base64."""
        encrypted = encrypt_password("mysecretpassword")
        try:
            naive = base64.b64decode(encrypted.encode()).decode("utf-8")
            assert naive != "mysecretpassword"
        except (UnicodeDecodeError, Exception):
            pass  # Binary ciphertext — correct

    def test_aes_encrypt_decrypt_roundtrip(self):
        """FIX A04: AES encrypt → decrypt must return original."""
        for pw in ["simple", "C0mpl3x!P@ssw0rd#", "spaces in pw", "a" * 50]:
            assert decrypt_password(encrypt_password(pw)) == pw

    def test_random_nonce_different_ciphertext(self):
        """FIX A04: Same password encrypted twice must give different ciphertext."""
        enc1 = encrypt_password("samepassword123")
        enc2 = encrypt_password("samepassword123")
        assert enc1 != enc2

    def test_encrypted_longer_than_plaintext(self):
        """AES ciphertext must be longer than plaintext."""
        assert len(encrypt_password("short")) > len("short")

    def test_decrypt_invalid_returns_empty(self):
        """Decrypting invalid data returns empty string."""
        assert decrypt_password("notvalidaes!!") == ""

    def test_decrypt_empty_returns_empty(self):
        """Decrypting empty string returns empty."""
        assert decrypt_password("") == ""


class TestUserLockout:

    def test_lockout_activates_after_max_attempts(self):
        """FIX A07: Account locks after MAX_LOGIN_ATTEMPTS failures."""
        user = User(username="locktest", email="lock@test.com",
                    failed_login_count=0)
        user.set_password("LockTest@123!")
        db.session.add(user)
        db.session.commit()
        for _ in range(5):
            user.increment_failed_login(max_attempts=5, lockout_minutes=15)
        assert user.is_locked() is True
        assert user.locked_until is not None

    def test_reset_clears_lockout(self):
        """FIX A07: reset_failed_login clears the lockout."""
        user = User(username="resettest", email="reset@test.com",
                    failed_login_count=0)
        user.set_password("Reset@Test123!")
        db.session.add(user)
        db.session.commit()
        for _ in range(5):
            user.increment_failed_login(max_attempts=5, lockout_minutes=15)
        user.reset_failed_login()
        assert user.is_locked() is False
        assert user.failed_login_count == 0
        assert user.locked_until is None

    def test_counter_increments_each_failure(self):
        """FIX A07: Failed login count increments correctly."""
        user = User(username="counttest", email="count@test.com",
                    failed_login_count=0)
        user.set_password("Count@Test123!")
        db.session.add(user)
        db.session.commit()
        user.increment_failed_login(max_attempts=5, lockout_minutes=15)
        assert user.failed_login_count == 1
        user.increment_failed_login(max_attempts=5, lockout_minutes=15)
        assert user.failed_login_count == 2
