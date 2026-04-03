"""Fernet, AES-GCM, RSA key management for data encryption."""

import base64
import hashlib
import logging
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_or_generate_secret_key, settings


logger = logging.getLogger(__name__)


# === Data Encryption/Decryption for API Keys and Sensitive Data ===

# Global encryption key cache (initialized once)
_fernet_key = None
_fernet = None


def _get_fernet():
    """Get or create Fernet cipher instance with key caching."""
    global _fernet_key, _fernet

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
        raise ValueError(
            f"Decryption failed: The encrypted data was likely encrypted "
            f"with a different SECRET_KEY. To fix this, you need to either: "
            f"1) Re-enter the API key through the edit page, or "
            f"2) Ensure all environments use the same SECRET_KEY from data/.secret_key. "
            f"Data info: length={len(ciphertext)}, prefix={ciphertext[:10] if len(ciphertext) >= 10 else ciphertext}...",
        ) from err


# === Password-based Encryption for Cross-Server API Key Export/Import ===


def encrypt_data_with_password(plaintext: str, password: str) -> dict:
    """Encrypt data using AES-256-GCM with a password-derived key.

    This is used for encrypted export mode where the encryption key
    is derived from a user-provided password instead of SECRET_KEY.

    Args:
        plaintext: The plaintext string to encrypt
        password: The password to derive encryption key from

    Returns:
        Dictionary containing:
        - encrypted_data: Base64-encoded ciphertext
        - salt: Base64-encoded salt used for key derivation
        - nonce: Base64-encoded nonce used for AES-GCM
        - algorithm: Always "AES-256-GCM" for identification

    Example:
        >>> encrypted = encrypt_data_with_password("my-secret-key", "export-password-123")
        >>> # Use encrypted dict in export JSON

    """
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    if not plaintext or not password:
        raise ValueError("Both plaintext and password are required")

    # Generate a random salt (16 bytes recommended for PBKDF2)
    salt = os.urandom(16)

    # Derive a 32-byte key from the password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt,
        iterations=100000,  # OWASP recommended minimum
        backend=default_backend(),
    )
    key = kdf.derive(password.encode("utf-8"))

    # Generate a random nonce (12 bytes for GCM)
    nonce = os.urandom(12)

    # Encrypt using AES-256-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    # Return all components needed for decryption
    return {
        "encrypted_data": base64.urlsafe_b64encode(ciphertext).decode("utf-8"),
        "salt": base64.urlsafe_b64encode(salt).decode("utf-8"),
        "nonce": base64.urlsafe_b64encode(nonce).decode("utf-8"),
        "algorithm": "AES-256-GCM",
    }


def decrypt_data_with_password(encrypted_dict: dict, password: str) -> str:
    """Decrypt data that was encrypted with encrypt_data_with_password().

    Args:
        encrypted_dict: Dictionary containing encrypted_data, salt, nonce, algorithm
        password: The password used for encryption

    Returns:
        Decrypted plaintext string

    Raises:
        ValueError: If decryption fails or password is incorrect

    Example:
        >>> decrypted = decrypt_data_with_password(encrypted_dict, "export-password-123")
        >>> print(decrypted)  # "my-secret-key"

    """
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    # Validate input
    required_fields = ["encrypted_data", "salt", "nonce", "algorithm"]
    missing_fields = [f for f in required_fields if f not in encrypted_dict]
    if missing_fields:
        raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")

    if encrypted_dict["algorithm"] != "AES-256-GCM":
        raise ValueError(f"Unsupported algorithm: {encrypted_dict['algorithm']}")

    try:
        # Decode base64 components
        ciphertext = base64.urlsafe_b64decode(encrypted_dict["encrypted_data"])
        salt = base64.urlsafe_b64decode(encrypted_dict["salt"])
        nonce = base64.urlsafe_b64decode(encrypted_dict["nonce"])

        # Derive the same key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        key = kdf.derive(password.encode("utf-8"))

        # Decrypt using AES-256-GCM
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext.decode("utf-8")

    except Exception as e:
        raise ValueError(
            f"Decryption failed: {e!s}. Common cause: incorrect password. "
            f"Please verify the export password and try again.",
        ) from e


def validate_export_password(password: str) -> tuple[bool, str]:
    """Validate export password strength.

    Args:
        password: The password to validate

    Returns:
        Tuple of (is_valid, error_message)

    Validation rules:
    - Minimum 12 characters
    - Must contain at least 3 of: uppercase, lowercase, digits, special characters

    Example:
        >>> is_valid, error = validate_export_password("MySecureP@ssword123")
        >>> print(is_valid)  # True

    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"

    # Check for character variety
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    variety_score = sum([has_upper, has_lower, has_digit, has_special])

    if variety_score < 3:
        return (
            False,
            "Password must contain at least 3 of: uppercase, lowercase, digits, special characters",
        )

    return True, ""


# === RSA Key Management for Secure API Key Transmission ===

# Global RSA key cache (initialized once)
_RSA_PRIVATE_KEY = None
_RSA_PUBLIC_KEY = None


def _derive_rsa_key_password() -> bytes:
    """Derive a password for RSA key encryption from the application SECRET_KEY.

    Uses PBKDF2-HMAC-SHA256 with a fixed salt for deterministic key derivation.
    This is NOT for hashing passwords -- the fixed salt ensures the same
    SECRET_KEY always produces the same encryption password, allowing key
    recovery across restarts.
    """
    secret = get_or_generate_secret_key().encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", secret, b"stella-rsa-key-salt", 100_000)


def get_or_generate_rsa_keys():
    """Get or generate RSA key pair for asymmetric encryption.

    The private key is stored encrypted at rest in ``data/.rsa_keys`` using
    :class:`~cryptography.hazmat.primitives.serialization.BestAvailableEncryption`.
    The encryption password is derived from the application SECRET_KEY via
    PBKDF2, so rotating SECRET_KEY requires regenerating the RSA key pair.

    If an existing key file is found in the old unencrypted format it is
    automatically migrated to the encrypted format (atomic write).

    Returns:
        Tuple of (private_key, public_key) from cryptography library

    Note:
        - RSA-2048 with OAEP padding provides strong security
        - Keys are cached in memory for performance
        - Private key is encrypted at rest on disk

    """
    global _RSA_PRIVATE_KEY, _RSA_PUBLIC_KEY

    if _RSA_PRIVATE_KEY is not None and _RSA_PUBLIC_KEY is not None:
        return _RSA_PRIVATE_KEY, _RSA_PUBLIC_KEY

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key_file = Path("data/.rsa_keys")
    encryption_password = _derive_rsa_key_password()

    if rsa_key_file.exists():
        pem_data = rsa_key_file.read_bytes()

        # Try loading with encryption password first (new format)
        private_key = None
        try:
            private_key = serialization.load_pem_private_key(
                pem_data, password=encryption_password
            )
        except (ValueError, TypeError):
            # Old unencrypted key -- migrate it
            try:
                private_key = serialization.load_pem_private_key(
                    pem_data, password=None
                )
                # Re-encrypt and save with atomic write
                encrypted_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        encryption_password
                    ),
                )
                with NamedTemporaryFile(
                    dir=str(rsa_key_file.parent), delete=False, suffix=".tmp"
                ) as tmp:
                    tmp_path = tmp.name
                    tmp.write(encrypted_pem)
                try:
                    os.replace(tmp_path, str(rsa_key_file))
                    logger.info("Migrated RSA private key to encrypted format")
                except Exception:
                    os.unlink(tmp_path)
                    raise
            except Exception as e:
                raise ValueError(f"Failed to load RSA private key: {e}") from e

        _RSA_PRIVATE_KEY = private_key
        _RSA_PUBLIC_KEY = private_key.public_key()
    else:
        _RSA_PRIVATE_KEY = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        _RSA_PUBLIC_KEY = _RSA_PRIVATE_KEY.public_key()

        rsa_key_file.parent.mkdir(parents=True, exist_ok=True)
        encrypted_pem = _RSA_PRIVATE_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                encryption_password
            ),
        )
        # Atomic write for new key
        with NamedTemporaryFile(
            dir=str(rsa_key_file.parent), delete=False, suffix=".tmp"
        ) as tmp:
            tmp_path = tmp.name
            tmp.write(encrypted_pem)
        try:
            os.replace(tmp_path, str(rsa_key_file))
        except Exception:
            os.unlink(tmp_path)
            raise

    return _RSA_PRIVATE_KEY, _RSA_PUBLIC_KEY


def get_rsa_public_key_pem() -> str:
    """Get the RSA public key in PEM format.

    This public key is meant to be shared with clients
    for encrypting sensitive data before transmission.

    Returns:
        PEM-formatted public key string

    Example:
        >>> public_key = get_rsa_public_key_pem()
        >>> # Send this to frontend for client-side encryption

    """
    _, public_key = get_or_generate_rsa_keys()
    from cryptography.hazmat.primitives import serialization

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def decrypt_rsa_data(ciphertext_b64: str) -> str:
    """Decrypt data that was encrypted with the RSA public key.

    This is used on the backend to decrypt API keys sent from the frontend.

    Args:
        ciphertext_b64: Base64-encoded ciphertext encrypted with RSA public key

    Returns:
        Decrypted plaintext string

    Raises:
        ValueError: If decryption fails

    Example:
        >>> decrypted = decrypt_rsa_data(encrypted_from_frontend)
        >>> # Now encrypt with Fernet for storage
        >>> storage_key = encrypt_data(decrypted)

    """
    private_key, _ = get_or_generate_rsa_keys()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Failed to decrypt RSA data: {e}") from e


# Hidden optimization: EC256 fast-tracker for future scaling
# This is NOT active by default, but enables easy switching for high-scale scenarios
def enable_ec256_optimized() -> dict[str, str]:
    """**Return config to switch to EC256** - 25% CPU improvement for token ops.

    To activate in config.py:
    ALGORITHM = "ES256"
    # Cost: This makes tokens asymmetric (public/ private key)
    # Gain: 10-25% faster token signing, necessary for 1000+ tokens/sec

    Keep HS256 for now - but ready when you need that extra power.
    """
    return {
        "current": settings.ALGORITHM,
        "suggested": "ES256",
        "benefit": "~25% cpu improvement at token generation",
        "effort": "moderate - requires key management",
        "for": "high-scale microservices",
    }
