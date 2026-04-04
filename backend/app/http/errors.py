"""HTTP error helpers for route handlers.

Convention:
- Route layer uses these helpers for user-facing error messages.
- Service layer should raise typed exceptions from app.core.exceptions instead.
"""

from typing import Any

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import RedirectResponse


def raise_not_found(
    entity_type: str,
    entity_id: int | str | None = None,
) -> None:
    """Raise standardized 404 Not Found error."""
    detail = f"{entity_type} not found"
    if entity_id:
        detail += f" (id={entity_id})"
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


def raise_validation_error(
    field_name: str,
    reason: str,
) -> None:
    """Raise standardized 400 Bad Request validation error."""
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Invalid {field_name}: {reason}",
    )


def raise_unauthorized(message: str = "Unauthorized") -> None:
    """Raise standardized 401 Unauthorized error."""
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=message)


def raise_forbidden(message: str = "Forbidden") -> None:
    """Raise standardized 403 Forbidden error."""
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=message)


def raise_conflict(message: str) -> None:
    """Raise standardized 409 Conflict error."""
    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=message)


def raise_internal_error(
    operation: str,
    exc: Exception | None = None,
) -> None:
    """Raise standardized 500 Internal Server Error."""
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"Internal error during {operation}",
    ) from exc


def raise_bad_request(message: str) -> None:
    """Raise standardized 400 Bad Request error."""
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)


def raise_not_implemented(feature: str) -> None:
    """Raise standardized 501 Not Implemented error."""
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=f"Feature not implemented: {feature}",
    )


def create_error_response(
    message: str,
    status_code: int = 500,
) -> dict[str, Any]:
    """Create a standardized error response dict without raising."""
    return {
        "error": True,
        "status_code": status_code,
        "message": message,
    }


def register_admin_http_exception_handler(app: FastAPI) -> None:
    """Register admin-specific redirects and HTML error rendering.

    This handler extends the global http_exception_handler from app.core.exceptions
    with admin-specific behavior (redirects, HTML error pages). For non-admin routes,
    it delegates to the global custom handler to ensure consistent JSON error responses.
    """
    from app.core.exceptions import (
        http_exception_handler as global_http_exception_handler,
    )

    @app.exception_handler(HTTPException)
    async def custom_http_exception_handler(request, exc):
        is_admin_request = request.url.path.startswith("/api/v1/admin/")

        if exc.status_code == status.HTTP_307_TEMPORARY_REDIRECT:
            return RedirectResponse(
                url=exc.headers.get("Location", "/api/v1/admin/2fa/setup"),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        if (
            is_admin_request
            and exc.status_code == status.HTTP_401_UNAUTHORIZED
            and request.url.path != "/api/v1/admin/login"
        ):
            return RedirectResponse(
                url="/api/v1/admin/login",
                status_code=status.HTTP_303_SEE_OTHER,
            )

        if is_admin_request and exc.status_code >= 400:
            from fastapi.templating import Jinja2Templates

            templates = Jinja2Templates(directory="app/admin/templates")
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error_message": exc.detail
                    if isinstance(exc.detail, str)
                    else "An unexpected error occurred.",
                    "error_detail": f"Error code: {exc.status_code}",
                },
                status_code=exc.status_code,
            )

        # Delegate to the global custom handler for consistent JSON error responses
        return await global_http_exception_handler(request, exc)
