import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # FIX A02: Secret key loaded from environment variable — never hardcoded
    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable is not set. Refusing to start.")

    # FIX A02: Debug mode off by default
    DEBUG = os.environ.get("DEBUG", "False").lower() == "true"

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql://securevault:securevault@localhost:5432/securevault"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static/uploads")

    # FIX A03: 2MB file size limit
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024

    # FIX A07: Account lockout after 5 failed attempts
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 15

    # FIX A09: Logging enabled
    LOGGING_ENABLED = True

    # FIX A02: CSRF protection enabled
    WTF_CSRF_ENABLED = True

    # FIX A02: Secure session cookie settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes

    # FIX A03: Only these file extensions allowed
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

    # FIX A04: AES encryption key for vault passwords
    VAULT_ENCRYPTION_KEY = os.environ.get("VAULT_ENCRYPTION_KEY")
    if not VAULT_ENCRYPTION_KEY:
        raise ValueError("VAULT_ENCRYPTION_KEY environment variable is not set.")
