"""Password hashing (bcrypt), API key generation, and password reset tokens."""

import logging
import secrets
from datetime import UTC, datetime, timedelta

import jwt as pyjwt
from passlib.context import CryptContext

from app.core.config import settings


logger = logging.getLogger(__name__)


# Password hashing context
# Note: Use bcrypt without prefix to avoid base64 encoding issues
try:
    import bcrypt

    # Test if bcrypt has the expected API
    _test = bcrypt.hashpw(b"test", bcrypt.gensalt())
    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    """Hash password using bcrypt."""
    if _HAS_BCRYPT:
        # Use raw bcrypt to avoid passlib issues
        if isinstance(password, str):
            password = password.encode("utf-8")
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password, salt).decode("utf-8")
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against hashed password."""
    if _HAS_BCRYPT:
        # Use raw bcrypt to avoid passlib issues
        if isinstance(plain_password, str):
            plain_password = plain_password.encode("utf-8")
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode("utf-8")
        try:
            return bcrypt.checkpw(plain_password, hashed_password)
        except Exception as exc:
            logger.warning("Password verification failed: %s", type(exc).__name__)
            return False
    else:
        return pwd_context.verify(plain_password, hashed_password)


def generate_password_reset_token(email: str) -> str:
    """Generate password reset token."""
    delta = timedelta(hours=settings.EMAIL_RESET_TOKEN_EXPIRE_HOURS)
    now = datetime.now(UTC)
    expires = now + delta
    exp = expires.timestamp()
    encoded_jwt = pyjwt.encode(
        {"exp": exp, "nbf": now, "sub": email},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    return encoded_jwt


def verify_password_reset_token(token: str) -> str | None:
    """Verify password reset token."""
    try:
        decoded_token = pyjwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        return decoded_token["sub"]
    except pyjwt.InvalidTokenError:
        return None


def generate_api_key() -> str:
    """Generate a secure API key."""
    return secrets.token_urlsafe(32)


def generate_random_string(length: int = 32) -> str:
    """Generate a random string."""
    return secrets.token_urlsafe(length)
