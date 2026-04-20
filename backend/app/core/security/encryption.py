"""Fernet encryption for API key storage."""

import base64
import hashlib
import logging
import threading

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_or_generate_secret_key


logger = logging.getLogger(__name__)


# Global encryption key cache (initialized once)
_fernet_key = None
_fernet = None
_fernet_lock = threading.Lock()


def _get_fernet():
    """Get or create Fernet cipher instance with key caching."""
    global _fernet_key, _fernet

    if _fernet is not None:
        return _fernet
    with _fernet_lock:
        if _fernet is None:
            # Use the SECRET_KEY from settings for encryption
            # Generate a Fernet-compatible key from SECRET_KEY
            secret = get_or_generate_secret_key().encode()

            # Fernet requires a 32-byte URL-safe base64-encoded key
            # Derive a 32-byte key from SECRET_KEY using SHA256
            key_hash = hashlib.sha256(secret).digest()
            _fernet_key = base64.urlsafe_b64encode(key_hash)

            _fernet = Fernet(_fernet_key)
        return _fernet


def encrypt_data(plaintext: str) -> str:
    """Encrypt sensitive data (e.g., API keys) using Fernet symmetric encryption.

    Args:
        plaintext: The plaintext string to encrypt

    Returns:
        Encrypted string (URL-safe base64-encoded)

    Example:
        >>> encrypted = encrypt_data("my-secret-api-key")
        >>> # Store 'encrypted' in database

    """
    if not plaintext:
        return ""

    fernet = _get_fernet()
    encrypted_bytes = fernet.encrypt(plaintext.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def decrypt_data(ciphertext: str) -> str:
    """Decrypt sensitive data that was encrypted using encrypt_data()."""
    if not ciphertext:
        return ""

    fernet = _get_fernet()
    try:
        decrypted_bytes = fernet.decrypt(ciphertext.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except InvalidToken as err:
        logger.debug(
            "Decryption failed for key prefix %s",
            ciphertext[:10] if len(ciphertext) >= 10 else ciphertext,
        )
        raise ValueError(
            "Decryption failed: The encrypted data was likely encrypted "
            "with a different SECRET_KEY. To fix this, you need to either: "
            "1) Re-enter the API key through the edit page, or "
            "2) Ensure all environments use the same SECRET_KEY from data/.secret_key. "
            f"Data info: length={len(ciphertext)}",
        ) from err
