"""
Unit tests for Fixed Fetcher and Validators.
Proves: SSRF blocked (A10), file upload restricted (A03).
"""
import pytest
import uuid as uuid_module
from unittest.mock import patch, MagicMock
from app.utils.validators import (
    validate_url, allowed_file, validate_file_content,
    sanitize_filename, validate_password_strength, validate_email
)


class TestSSRFProtectionFixed:

    def test_public_https_url_allowed(self):
        assert validate_url("https://google.com") is True

    def test_empty_url_blocked(self):
        assert validate_url("") is False
        assert validate_url(None) is False

    def test_localhost_blocked(self):
        """FIX A10: localhost must be BLOCKED."""
        assert validate_url("http://localhost") is False
        assert validate_url("http://localhost:5432") is False

    def test_loopback_127_blocked(self):
        """FIX A10: 127.0.0.1 must be blocked."""
        assert validate_url("http://127.0.0.1") is False

    def test_private_ip_10_blocked(self):
        assert validate_url("http://10.0.0.1") is False

    def test_private_ip_192_168_blocked(self):
        assert validate_url("http://192.168.1.1") is False

    def test_private_ip_172_16_blocked(self):
        assert validate_url("http://172.16.0.1") is False

    def test_aws_metadata_endpoint_blocked(self):
        """FIX A10: AWS metadata 169.254.169.254 must be BLOCKED."""
        assert validate_url("http://169.254.169.254") is False
        assert validate_url("http://169.254.169.254/latest/meta-data/") is False

    def test_file_scheme_blocked(self):
        assert validate_url("file:///etc/passwd") is False

    def test_ftp_scheme_blocked(self):
        assert validate_url("ftp://example.com") is False


class TestFetcherEndpointFixed:

    def test_fetcher_page_loads_when_logged_in(self, logged_in_alice):
        """Fetcher page loads for authenticated users."""
        response = logged_in_alice.get("/fetcher/")
        assert response.status_code == 200

    def test_fetcher_page_redirects_when_not_logged_in(self, client):
        """Fetcher page redirects unauthenticated users to login."""
        # Use a brand new client with no session
        response = client.get("/fetcher/", follow_redirects=False)
        # Should redirect (302) not serve the page
        assert response.status_code == 302
        assert "/login" in response.headers.get("Location", "")

    def test_internal_url_rejected_before_fetch(self, logged_in_alice):
        """FIX A10: requests.get must NOT be called for blocked URLs."""
        with patch("app.routes.fetcher.http_requests.get") as mock_get:
            response = logged_in_alice.post("/fetcher/fetch-site",
                data={"url": "http://169.254.169.254/latest/meta-data/"})
            mock_get.assert_not_called()
        assert response.status_code == 400

    def test_localhost_rejected_before_fetch(self, logged_in_alice):
        """FIX A10: localhost must be rejected without making a request."""
        with patch("app.routes.fetcher.http_requests.get") as mock_get:
            response = logged_in_alice.post("/fetcher/fetch-site",
                data={"url": "http://localhost:5432"})
            mock_get.assert_not_called()
        assert response.status_code == 400

    def test_valid_url_fetches_title(self, logged_in_alice):
        """Valid public URL must work and return page title."""
        mock_resp = MagicMock()
        mock_resp.text = "<html><title>Test Site</title></html>"
        mock_resp.status_code = 200
        with patch("app.routes.fetcher.http_requests.get", return_value=mock_resp):
            response = logged_in_alice.post("/fetcher/fetch-site",
                data={"url": "https://example.com"})
        assert response.status_code == 200
        assert response.get_json()["title"] == "Test Site"

    def test_response_body_not_leaked(self, logged_in_alice):
        """FIX A10: preview field must NOT be returned."""
        mock_resp = MagicMock()
        mock_resp.text = "SENSITIVE_DATA: secret"
        mock_resp.status_code = 200
        with patch("app.routes.fetcher.http_requests.get", return_value=mock_resp):
            response = logged_in_alice.post("/fetcher/fetch-site",
                data={"url": "https://example.com"})
        data = response.get_json()
        assert "preview" not in data
        assert b"SENSITIVE_DATA" not in response.data

    def test_error_message_not_verbose(self, logged_in_alice):
        """FIX A02: Internal error details must not be exposed."""
        with patch("app.routes.fetcher.http_requests.get",
                   side_effect=Exception("postgres://user:pass@db")):
            response = logged_in_alice.post("/fetcher/fetch-site",
                data={"url": "https://example.com"})
        data = response.get_json()
        assert "postgres://" not in data.get("error", "")

    def test_empty_url_returns_400(self, logged_in_alice):
        """Empty URL must return 400."""
        response = logged_in_alice.post("/fetcher/fetch-site", data={"url": ""})
        assert response.status_code == 400


class TestFileUploadFixed:

    def test_allowed_image_extensions(self):
        for ext in ["photo.png", "photo.jpg", "photo.jpeg", "photo.gif", "photo.webp"]:
            assert allowed_file(ext) is True

    def test_dangerous_extensions_blocked(self):
        """FIX A03: Dangerous extensions must be BLOCKED."""
        for name in ["shell.php", "xss.html", "malware.js", "backdoor.py", "virus.exe"]:
            assert allowed_file(name) is False, f"{name} should be blocked"

    def test_no_extension_blocked(self):
        assert allowed_file("noextension") is False
        assert allowed_file("") is False

    def test_magic_bytes_png_valid(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        assert validate_file_content(png) is True

    def test_magic_bytes_jpg_valid(self):
        jpg = b"\xff\xd8\xff" + b"\x00" * 100
        assert validate_file_content(jpg) is True

    def test_php_blocked_by_magic_bytes(self):
        """FIX A03: PHP renamed to .png blocked by magic bytes."""
        assert validate_file_content(b"<?php system($_GET['cmd']); ?>") is False

    def test_html_blocked_by_magic_bytes(self):
        assert validate_file_content(b"<html><script>alert(1)</script></html>") is False

    def test_sanitize_filename_returns_uuid(self):
        """FIX A03: sanitize_filename returns a UUID — never the original."""
        for name in ["../../config.py", "shell.php", "photo.png"]:
            result = sanitize_filename(name)
            assert ".." not in result
            assert "/" not in result
            parts = result.rsplit(".", 1)
            try:
                uuid_module.UUID(parts[0])
            except ValueError:
                pytest.fail(f"Not a UUID for input: {name}")

    def test_sanitize_preserves_safe_extension(self):
        assert sanitize_filename("photo.png").endswith(".png")

    def test_sanitize_strips_dangerous_extension(self):
        assert not sanitize_filename("shell.php").endswith(".php")


class TestPasswordStrengthFixed:

    def test_strong_password_passes(self):
        valid, _ = validate_password_strength("Strong@Pass1!")
        assert valid is True

    def test_short_password_fails(self):
        valid, msg = validate_password_strength("Ab1!")
        assert valid is False and "8" in msg

    def test_no_uppercase_fails(self):
        valid, msg = validate_password_strength("lowercase1!")
        assert valid is False and "uppercase" in msg

    def test_no_lowercase_fails(self):
        valid, msg = validate_password_strength("UPPERCASE1!")
        assert valid is False and "lowercase" in msg

    def test_no_number_fails(self):
        valid, msg = validate_password_strength("NoNumber!!")
        assert valid is False and "number" in msg

    def test_no_special_char_fails(self):
        valid, msg = validate_password_strength("NoSpecial123")
        assert valid is False and "special" in msg


class TestEmailValidationFixed:

    def test_valid_emails_pass(self):
        assert validate_email("user@example.com") is True
        assert validate_email("user.name+tag@domain.co.uk") is True

    def test_invalid_emails_fail(self):
        assert validate_email("notanemail") is False
        assert validate_email("@nodomain.com") is False
        assert validate_email("") is False
