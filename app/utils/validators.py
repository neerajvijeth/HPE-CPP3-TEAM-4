import os
import re
import ipaddress
import socket
from urllib.parse import urlparse
import uuid


# FIX A03: Strict allowlist of safe image extensions
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

# FIX A03: Magic bytes (file signatures) for allowed types
MAGIC_BYTES = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpg",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",
}

# FIX A10: Blocked IP ranges for SSRF protection
BLOCKED_IP_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # Private
    ipaddress.ip_network("172.16.0.0/12"),     # Private
    ipaddress.ip_network("192.168.0.0/16"),    # Private
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local (AWS metadata)
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 private
]


def allowed_file(filename: str) -> bool:
    """FIX A03: Check file extension against allowlist."""
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def validate_file_content(file_bytes: bytes) -> bool:
    """FIX A03: Validate file by magic bytes, not just extension."""
    for magic, _ in MAGIC_BYTES.items():
        if file_bytes.startswith(magic):
            return True
    return False


def sanitize_filename(filename: str) -> str:
    """
    FIX A03: Generate a safe random filename.
    Never use the original filename — prevents path traversal.
    """
    ext = ""
    if "." in filename:
        ext = "." + filename.rsplit(".", 1)[1].lower()
        if ext.lstrip(".") not in ALLOWED_EXTENSIONS:
            ext = ""
    # Random UUID as filename — no attacker control over the name
    return str(uuid.uuid4()) + ext


def validate_url(url: str) -> bool:
    """
    FIX A10: SSRF protection.
    - Only allow http/https schemes
    - Resolve hostname to IP and check against blocked ranges
    - Block localhost, private IPs, cloud metadata endpoints
    """
    if not url:
        return False

    try:
        parsed = urlparse(url)

        # Only allow http and https
        if parsed.scheme not in ("http", "https"):
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # Block localhost by name
        if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return False

        # Resolve hostname to IP address
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            return False

        ip = ipaddress.ip_address(resolved_ip)

        # Check against all blocked ranges
        for blocked_range in BLOCKED_IP_RANGES:
            if ip in blocked_range:
                return False

        return True

    except Exception:
        return False


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    FIX A07: Enforce password strength requirements.
    Returns (is_valid, error_message).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""


def validate_email(email: str) -> bool:
    """FIX A07: Basic email format validation."""
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))
