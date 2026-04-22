from base64 import urlsafe_b64encode

from cryptography.fernet import Fernet

from app.core.config import get_settings


def generate_key() -> str:
    """Generate a new Fernet encryption key."""
    return Fernet.generate_key().decode()


def get_fernet() -> Fernet:
    """Get a Fernet instance using the configured encryption key."""
    settings = get_settings()
    key = settings.ENCRYPTION_KEY
    if not key:
        raise ValueError("ENCRYPTION_KEY is not configured. Set it in .env or environment variables.")
    return Fernet(key.encode())


def encrypt_api_key(api_key: str) -> str:
    """Encrypt an API key using Fernet symmetric encryption."""
    fernet = get_fernet()
    encrypted = fernet.encrypt(api_key.encode())
    return urlsafe_b64encode(encrypted).decode()


def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypt an API key using Fernet symmetric encryption."""
    from base64 import urlsafe_b64decode

    fernet = get_fernet()
    encrypted_bytes = urlsafe_b64decode(encrypted_key.encode())
    decrypted = fernet.decrypt(encrypted_bytes)
    return decrypted.decode()
