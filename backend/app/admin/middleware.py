"""CSRF middleware for admin panel."""
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.admin.csrf import generate_csrf_token, get_csrf_token_from_request


class CSRFMiddleware(BaseHTTPMiddleware):
    """Middleware to add CSRF token to all admin pages."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add CSRF token to request state and response cookies."""
        # Only process admin routes
        if not request.url.path.startswith("/admin"):
            return await call_next(request)

        # Skip CSRF for GET requests to login page (will be set there)
        if request.url.path == "/admin/login" and request.method == "GET":
            return await call_next(request)

        # Get or generate CSRF token
        csrf_token = get_csrf_token_from_request(request)
        if not csrf_token:
            csrf_token = generate_csrf_token()

        # Add to request state for templates
        request.state.csrf_token = csrf_token

        # Process request
        response = await call_next(request)

        # Set CSRF token cookie if not already set
        if not get_csrf_token_from_request(request):
            response.set_cookie(
                key="csrf_token",
                value=csrf_token,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=3600,
            )

        return response
