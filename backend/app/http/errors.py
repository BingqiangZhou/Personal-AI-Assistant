"""Shared HTTP exception helpers."""

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import RedirectResponse


def bilingual_http_exception(
    message_en: str,
    message_zh: str,
    status_code: int,
) -> HTTPException:
    """Create a bilingual HTTPException payload."""
    return HTTPException(
        status_code=status_code,
        detail={"message_en": message_en, "message_zh": message_zh},
    )


def register_admin_http_exception_handler(app: FastAPI) -> None:
    """Register admin-specific redirects and HTML error rendering."""

    @app.exception_handler(HTTPException)
    async def custom_http_exception_handler(request, exc):
        is_admin_request = request.url.path.startswith("/super/")

        if exc.status_code == status.HTTP_307_TEMPORARY_REDIRECT:
            return RedirectResponse(
                url=exc.headers.get("Location", "/super/2fa/setup"),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        if (
            is_admin_request
            and exc.status_code == status.HTTP_401_UNAUTHORIZED
            and request.url.path != "/super/login"
        ):
            return RedirectResponse(
                url="/super/login",
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

        from fastapi.exception_handlers import http_exception_handler

        return await http_exception_handler(request, exc)
