"""
Unit tests for Fixed Authentication — routes/auth.py
Proves: SQL injection blocked (A05), lockout works (A07),
password strength enforced (A07), events logged (A09).
"""
import pytest
from app.models.user import User
from app.models.audit import AuditLog
from app import db


class TestLoginFixed:

    def test_login_page_loads(self, client):
        response = client.get("/login")
        assert response.status_code == 200
        assert b"SecureVault" in response.data

    def test_valid_login_succeeds(self, client):
        response = client.post("/login", data={
            "username": "alice", "password": "Alice@Test123!"
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b"Vault" in response.data

    def test_wrong_password_fails(self, client):
        response = client.post("/login", data={
            "username": "alice", "password": "wrongpassword"
        }, follow_redirects=True)
        assert b"Invalid username or password" in response.data

    def test_nonexistent_user_fails(self, client):
        response = client.post("/login", data={
            "username": "nobody", "password": "password"
        }, follow_redirects=True)
        assert b"Invalid username or password" in response.data

    # ------------------------------------------------------------------ #
    # FIX A05 — SQL Injection blocked (ORM parameterized query)
    # ------------------------------------------------------------------ #

    def test_sql_injection_admin_comment_blocked(self, client):
        """
        FIX A05: admin'-- must NOT bypass login.
        ORM query treats the whole string as a literal username — no user found.
        """
        response = client.post("/login", data={
            "username": "admin'--", "password": "anything"
        }, follow_redirects=True)
        # Must land on login page with error, NOT on vault
        assert b"Invalid username or password" in response.data
        assert b"page-title" not in response.data or b"My Vault" not in response.data

    def test_sql_injection_or_1_equals_1_blocked(self, client):
        """FIX A05: OR 1=1 treated as literal username — no user found."""
        response = client.post("/login", data={
            "username": "' OR '1'='1", "password": "anything"
        }, follow_redirects=True)
        assert b"Invalid username or password" in response.data

    def test_sql_union_injection_blocked(self, client):
        """FIX A05: UNION injection treated as literal username."""
        response = client.post("/login", data={
            "username": "' UNION SELECT 1,2,3--", "password": "anything"
        }, follow_redirects=True)
        assert b"Invalid username or password" in response.data

    def test_sql_injection_does_not_log_in_wrong_user(self, client):
        """FIX A05: Injecting admin username must not log in as admin."""
        response = client.post("/login", data={
            "username": "admin'--", "password": "wrongpassword"
        }, follow_redirects=True)
        # Should NOT see admin nav link
        assert b"admin-link" not in response.data

    # ------------------------------------------------------------------ #
    # FIX A07 — Account lockout
    # ------------------------------------------------------------------ #

    def test_account_locked_after_max_attempts(self, client):
        """FIX A07: Account must lock after 5 failed attempts."""
        for i in range(5):
            client.post("/login", data={
                "username": "alice", "password": f"wrong{i}"
            }, follow_redirects=True)

        response = client.post("/login", data={
            "username": "alice", "password": "Alice@Test123!"
        }, follow_redirects=True)
        assert b"locked" in response.data.lower()

    def test_failed_attempts_counter_increments(self, client):
        """FIX A07: failed_login_count increments on wrong password."""
        client.post("/login", data={
            "username": "alice", "password": "wrongpassword"
        }, follow_redirects=True)
        alice = User.query.filter_by(username="alice").first()
        assert alice.failed_login_count > 0

    def test_failed_counter_resets_on_success(self, client):
        """FIX A07: failed_login_count resets to 0 on successful login."""
        client.post("/login", data={"username": "alice", "password": "wrong"})
        client.post("/login", data={
            "username": "alice", "password": "Alice@Test123!"
        }, follow_redirects=True)
        alice = User.query.filter_by(username="alice").first()
        assert alice.failed_login_count == 0

    def test_remaining_attempts_shown_in_flash(self, client):
        """FIX A07: Flash message shown after failed login."""
        response = client.post("/login", data={
            "username": "alice", "password": "wrongpassword"
        }, follow_redirects=True)
        # Either shows attempt count or generic error — both acceptable
        assert (b"Invalid username or password" in response.data or
                b"attempt" in response.data)

    # ------------------------------------------------------------------ #
    # FIX A09 — Login events logged
    # ------------------------------------------------------------------ #

    def test_successful_login_is_logged(self, client):
        """FIX A09: Successful login creates audit log entry."""
        client.post("/login", data={
            "username": "alice", "password": "Alice@Test123!"
        }, follow_redirects=True)
        log = AuditLog.query.filter_by(action="login_success").first()
        assert log is not None

    def test_failed_login_is_logged(self, client):
        """FIX A09: Failed login creates failure audit log entry."""
        client.post("/login", data={
            "username": "alice", "password": "wrongpassword"
        }, follow_redirects=True)
        log = AuditLog.query.filter_by(status="failure").first()
        assert log is not None

    def test_disabled_account_blocked(self, client):
        """Disabled account is rejected at login."""
        alice = User.query.filter_by(username="alice").first()
        alice.is_active = False
        db.session.commit()

        response = client.post("/login", data={
            "username": "alice", "password": "Alice@Test123!"
        }, follow_redirects=True)
        assert b"disabled" in response.data.lower()


class TestRegisterFixed:

    def test_register_page_loads(self, client):
        """Register page returns 200."""
        response = client.get("/register")
        assert response.status_code == 200

    def test_valid_registration_succeeds(self, client):
        """Strong password registration redirects to login with success flash."""
        response = client.post("/register", data={
            "username": "newuser",
            "email": "new@test.com",
            "password": "NewUser@Secure1!"
        }, follow_redirects=True)
        # After successful register it redirects to /login with flash message
        assert b"Registration successful" in response.data

    def test_duplicate_username_rejected(self, client):
        response = client.post("/register", data={
            "username": "alice",
            "email": "other@test.com",
            "password": "Strong@Pass1!"
        }, follow_redirects=True)
        assert b"Registration successful" not in response.data

    # ------------------------------------------------------------------ #
    # FIX A07 — Password strength enforced
    # ------------------------------------------------------------------ #

    def test_weak_password_rejected(self, client):
        """FIX A07: Password '1' must be rejected — stays on register page."""
        response = client.post("/register", data={
            "username": "weakuser",
            "email": "weak@test.com",
            "password": "1"
        }, follow_redirects=True)
        assert b"Registration successful" not in response.data

    def test_password_too_short_rejected(self, client):
        response = client.post("/register", data={
            "username": "shortpw",
            "email": "short@test.com",
            "password": "Ab1!"
        }, follow_redirects=True)
        assert b"Registration successful" not in response.data
        assert b"8" in response.data

    def test_password_no_uppercase_rejected(self, client):
        response = client.post("/register", data={
            "username": "noupperuser",
            "email": "noupper@test.com",
            "password": "lowercase123!"
        }, follow_redirects=True)
        assert b"Registration successful" not in response.data
        assert b"uppercase" in response.data

    def test_password_no_number_rejected(self, client):
        response = client.post("/register", data={
            "username": "nonumuser",
            "email": "nonum@test.com",
            "password": "NoNumber!!"
        }, follow_redirects=True)
        assert b"Registration successful" not in response.data
        assert b"number" in response.data

    def test_password_no_special_char_rejected(self, client):
        response = client.post("/register", data={
            "username": "nospecial",
            "email": "nospecial@test.com",
            "password": "NoSpecial123"
        }, follow_redirects=True)
        assert b"Registration successful" not in response.data
        assert b"special" in response.data

    def test_invalid_email_rejected(self, client):
        response = client.post("/register", data={
            "username": "bademail",
            "email": "notanemail",
            "password": "Strong@Pass1!"
        }, follow_redirects=True)
        assert b"Registration successful" not in response.data
        assert b"email" in response.data.lower()


class TestLogoutFixed:

    def test_logout_redirects_to_login(self, logged_in_alice):
        response = logged_in_alice.get("/logout", follow_redirects=True)
        assert b"Sign in" in response.data or b"login" in response.data.lower()

    def test_cannot_access_vault_after_logout(self, logged_in_alice):
        logged_in_alice.get("/logout")
        response = logged_in_alice.get("/vault/", follow_redirects=True)
        assert b"login" in response.data.lower()
