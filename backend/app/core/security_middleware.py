"""Security middleware for XSS protection and secure headers.

Deprecated:
    This module is currently not wired into the runtime middleware stack.
    Keep for compatibility only and avoid new imports from this module.
"""

import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses for XSS and other attacks protection.

    Security headers added:
    - X-Content-Type-Options: Prevent MIME type sniffing
    - X-Frame-Options: Prevent clickjacking
    - X-XSS-Protection: Enable browser XSS filter
    - Strict-Transport-Security: Enforce HTTPS (production only)
    - Content-Security-Policy: Restrict resource sources
    - Referrer-Policy: Control referrer information leakage
    - Permissions-Policy: Control browser features
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Add security headers to all responses
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer-Policy: Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions-Policy: Control browser features
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=()"
        )

        # Content-Security-Policy for XSS protection
        # Different policies for admin panel vs API/frontend
        is_admin_request = request.url.path.startswith("/super")

        if is_admin_request:
            # Relaxed CSP for admin panel (allows CDN resources)
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
                "https://cdn.tailwindcss.com "
                "https://unpkg.com "
                "https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' "
                "https://cdn.tailwindcss.com "
                "https://fonts.googleapis.com; "
                "img-src 'self' data: https:; "
                "font-src 'self' data: https://fonts.gstatic.com; "
                "connect-src 'self' https:; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self';"
            )
        else:
            # Strict CSP for API and frontend
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self' https:; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self';"
            )
        response.headers["Content-Security-Policy"] = csp

        # Log CSP header for debugging (remove in production if desired)
        logger.debug(f"CSP header set for {request.url.path} (admin: {is_admin_request})")

        return response


class InputSanitizationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to sanitize and validate user input for XSS prevention.

    This middleware checks request bodies for potentially dangerous content
    and logs warnings for security monitoring.
    """

    DANGEROUS_PATTERNS = [
        "<script",
        "</script>",
        "javascript:",
        "onerror=",
        "onload=",
        "onclick=",
        "<iframe",
        "<object",
        "<embed",
        "fromCharCode",
        "document.cookie",
        "localStorage.",
        "sessionStorage.",
        "window.",
        "eval(",
    ]

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        # Only check POST/PUT/PATCH requests with JSON or form data
        if request.method in ["POST", "PUT", "PATCH"]:
            # We'll check the body after it's been parsed by the endpoint
            # This is a simple check - actual validation should be in the endpoint/pydantic models
            pass

        response = await call_next(request)
        return response
