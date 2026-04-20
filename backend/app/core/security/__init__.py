"""Security utilities for API key authentication and data encryption."""

import secrets

from app.core.security.encryption import (  # noqa: F401
    decrypt_data,
    encrypt_data,
)


def generate_api_key() -> str:
    """Generate a secure API key."""
    return secrets.token_urlsafe(32)
