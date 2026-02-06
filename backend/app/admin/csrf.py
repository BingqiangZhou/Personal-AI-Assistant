"""CSRF protection utilities for admin panel."""
import secrets

from fastapi import Form, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.core.config import settings


class CSRFException(HTTPException):
    """
    Custom exception for CSRF validation errors.

    This exception allows for custom error messages and page redirection
    instead of returning JSON errors.
    """

    def __init__(
        self,
        detail: str,
        status_code: int = status.HTTP_403_FORBIDDEN,
        error_type: str = "csrf_error",
        user_message: str = None,
    ):
        """
        Initialize CSRF exception.

        Args:
            detail: Technical error message (for logging)
            status_code: HTTP status code (default: 403)
            error_type: Type of CSRF error
            user_message: User-friendly error message (for display)
        """
        super().__init__(status_code=status_code, detail=detail)
        self.error_type = error_type
        self.user_message = user_message or detail

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


def get_csrf_token_from_request(request: Request) -> str | None:
    """Get CSRF token from request cookies."""
    return request.cookies.get("csrf_token")


def validate_csrf_token(
    request: Request,
    csrf_token: str = Form(..., alias="csrf_token"),
) -> bool:
    """
    Validate CSRF token from form data against cookie.

    Raises:
        CSRFException: With user-friendly error messages for display
    """
    # Get token from cookie
    cookie_token = get_csrf_token_from_request(request)

    if not cookie_token:
        raise CSRFException(
            detail="CSRF token missing from cookie",
            error_type="missing_cookie",
            user_message="CSRF Token 已过期，请刷新页面后重试",
        )

    if not csrf_token:
        raise CSRFException(
            detail="CSRF token missing from form",
            error_type="missing_form",
            user_message="表单验证失败，请刷新页面后重试",
        )

    # Verify both tokens
    if not verify_csrf_token(cookie_token):
        raise CSRFException(
            detail="CSRF token expired or invalid",
            error_type="expired",
            user_message="CSRF Token 已过期，请刷新页面后重新提交",
        )

    # Compare tokens
    if cookie_token != csrf_token:
        raise CSRFException(
            detail="CSRF token mismatch",
            error_type="mismatch",
            user_message="CSRF Token 不匹配，请刷新页面后重试",
        )

    return True
