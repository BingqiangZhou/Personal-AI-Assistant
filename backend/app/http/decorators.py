"""Standardized error handling decorators for routes.

This module provides decorators to reduce boilerplate error handling
code across API and admin routes.
"""

import logging
from collections.abc import Callable
from functools import wraps
from typing import TypeVar

from fastapi import HTTPException, status


logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable)


def handle_api_errors(
    operation: str,
    *,
    error_message: str | None = None,
) -> Callable[[F], F]:
    """Decorator for consistent error handling in API routes.

    This decorator:
    - Re-raises HTTPException as-is
    - Catches other exceptions and converts to 500 Internal Server Error
    - Logs errors with context

    Args:
        operation: Description of the operation (for logging)
        error_message: Custom error message (optional)

    Returns:
        Decorated function

    Example:
        @router.get("/users/{user_id}")
        @handle_api_errors("get user", error_message="Failed to get user")
        async def get_user(user_id: int, service: UserService = Depends()):
            return await service.get_user(user_id)
    """

    def decorator(func: F) -> F:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except HTTPException:
                raise
            except Exception as exc:
                logger.error("%s error: %s", operation, exc)
                detail = error_message or f"Failed to {operation}"
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=detail,
                ) from exc

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except HTTPException:
                raise
            except Exception as exc:
                logger.error("%s error: %s", operation, exc)
                detail = error_message or f"Failed to {operation}"
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=detail,
                ) from exc

        if hasattr(func, "__code__") and func.__code__.co_flags & 0x80:
            return async_wrapper  # type: ignore
        return sync_wrapper  # type: ignore

    return decorator


def handle_admin_errors(
    operation: str,
    *,
    error_detail: str | None = None,
) -> Callable[[F], F]:
    """Decorator for consistent error handling in admin routes.

    Similar to handle_api_errors but uses simpler error messages
    suitable for admin panel responses.

    Args:
        operation: Description of the operation (for logging)
        error_detail: Custom error detail message (optional)

    Returns:
        Decorated function

    Example:
        @router.post("/settings")
        @handle_admin_errors("update settings")
        async def update_settings(request: Request):
            ...
    """

    def decorator(func: F) -> F:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except HTTPException:
                raise
            except Exception as exc:
                logger.error("%s error: %s", operation, exc)
                detail = error_detail or f"Failed to {operation}"
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=detail,
                ) from exc

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except HTTPException:
                raise
            except Exception as exc:
                logger.error("%s error: %s", operation, exc)
                detail = error_detail or f"Failed to {operation}"
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=detail,
                ) from exc

        if hasattr(func, "__code__") and func.__code__.co_flags & 0x80:
            return async_wrapper  # type: ignore
        return sync_wrapper  # type: ignore

    return decorator
