"""Custom exception handlers."""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import Union
import logging

logger = logging.getLogger(__name__)


class BaseCustomException(Exception):
    """Base custom exception."""

    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class NotFoundError(BaseCustomException):
    """Resource not found exception."""

    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, 404)


class BadRequestError(BaseCustomException):
    """Bad request exception."""

    def __init__(self, message: str = "Bad request"):
        super().__init__(message, 400)


class UnauthorizedError(BaseCustomException):
    """Unauthorized exception."""

    def __init__(self, message: str = "Unauthorized"):
        super().__init__(message, 401)


class ForbiddenError(BaseCustomException):
    """Forbidden exception."""

    def __init__(self, message: str = "Forbidden"):
        super().__init__(message, 403)


class ConflictError(BaseCustomException):
    """Conflict exception."""

    def __init__(self, message: str = "Conflict"):
        super().__init__(message, 409)


class ValidationError(BaseCustomException):
    """Validation exception."""

    def __init__(self, message: str = "Validation failed"):
        super().__init__(message, 400)


class DatabaseError(BaseCustomException):
    """Database exception."""

    def __init__(self, message: str = "Database error"):
        super().__init__(message, 500)


async def custom_exception_handler(request: Request, exc: BaseCustomException) -> JSONResponse:
    """Handle custom exceptions."""
    logger.error(f"Custom exception: {exc.message} - Status: {exc.status_code}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message, "type": exc.__class__.__name__}
    )


async def http_exception_handler(request: Request, exc: Union[HTTPException, StarletteHTTPException]) -> JSONResponse:
    """Handle HTTP exceptions."""
    logger.error(f"HTTP exception: {exc.detail} - Status: {exc.status_code}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "type": "HTTPException"}
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle validation exceptions."""
    errors = []
    for error in exc.errors():
        errors.append({
            "field": " -> ".join(str(x) for x in error["loc"]),
            "message": error["msg"],
            "type": error["type"]
        })

    logger.error(f"Validation error: {errors}")
    return JSONResponse(
        status_code=422,
        content={"detail": "Validation failed", "errors": errors}
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle general exceptions."""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "type": "InternalServerError"}
    )


def setup_exception_handlers(app: FastAPI) -> None:
    """Setup exception handlers for the FastAPI app."""
    app.add_exception_handler(BaseCustomException, custom_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)
