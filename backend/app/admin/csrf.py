"""CSRF protection utilities for admin panel."""
import secrets
from typing import Optional

from fastapi import Cookie, Form, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.core.config import settings

# CSRF token serializer
csrf_serializer = URLSafeTimedSerializer(settings.SECRET_KEY, salt="csrf")

# CSRF token timeout (1 hour)
CSRF_TOKEN_TIMEOUT = 3600


def generate_csrf_token() -> str:
    """Generate a new CSRF token."""
    random_string = secrets.token_urlsafe(32)
    return csrf_serializer.dumps(random_string)


def verify_csrf_token(token: str) -> bool:
    """Verify a CSRF token."""
    try:
        csrf_serializer.loads(token, max_age=CSRF_TOKEN_TIMEOUT)
        return True
    except (SignatureExpired, BadSignature):
        return False


def get_csrf_token_from_request(request: Request) -> Optional[str]:
    """Get CSRF token from request cookies."""
    return request.cookies.get("csrf_token")


def validate_csrf_token(
    request: Request,
    csrf_token: str = Form(..., alias="csrf_token"),
) -> bool:
    """Validate CSRF token from form data against cookie."""
    # Get token from cookie
    cookie_token = get_csrf_token_from_request(request)

    if not cookie_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing from cookie",
        )

    if not csrf_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing from form",
        )

    # Verify both tokens
    if not verify_csrf_token(cookie_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token expired or invalid",
        )

    # Compare tokens
    if cookie_token != csrf_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch",
        )

    return True
