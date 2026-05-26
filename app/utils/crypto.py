import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _get_key() -> bytes:
    """
    FIX A04: Load AES-256 key from environment variable.
    Key must be 32 bytes (256 bits), stored as base64 in env.
    """
    raw = os.environ.get("VAULT_ENCRYPTION_KEY", "")
    key_bytes = base64.urlsafe_b64decode(raw)
    if len(key_bytes) != 32:
        raise ValueError("VAULT_ENCRYPTION_KEY must be 32 bytes (256-bit) base64 encoded.")
    return key_bytes


def encrypt_password(plaintext: str) -> str:
    """
    FIX A04: AES-256-GCM encryption.
    - Random 12-byte nonce for every encryption
    - GCM mode provides authenticated encryption (integrity + confidentiality)
    - Result is base64(nonce + ciphertext)
    """
    key = _get_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit random nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    # Store nonce prepended to ciphertext, base64 encoded
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_password(encoded: str) -> str:
    """
    FIX A04: AES-256-GCM decryption.
    Extracts nonce from first 12 bytes, decrypts the rest.
    """
    try:
        key = _get_key()
        aesgcm = AESGCM(key)
        raw = base64.b64decode(encoded.encode())
        nonce = raw[:12]
        ciphertext = raw[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception:
        return ""
