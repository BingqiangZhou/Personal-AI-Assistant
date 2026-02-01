"""
ETag Dependencies for FastAPI

Provides FastAPI dependency functions for ETag validation.
"""
from typing import Optional

from fastapi import Header, Request


async def get_if_none_match(
    if_none_match: Optional[str] = Header(None)
) -> Optional[str]:
    """Dependency to get If-None-Match header value.

    Args:
        if_none_match: The If-None-Match header from the request

    Returns:
        The raw If-None-Match header value, or None if not present

    Usage:
        ```python
        @router.get("/items")
        async def get_items(
            etag: Optional[str] = Depends(get_if_none_match),
            ...
        ):
            if etag:
                # Client has ETag, check if we can return 304
                ...
        ```
    """
    return if_none_match


async def get_if_match(
    if_match: Optional[str] = Header(None)
) -> Optional[str]:
    """Dependency to get If-Match header value.

    Used for conditional PUT/PATCH requests to prevent
    lost update problems.

    Args:
        if_match: The If-Match header from the request

    Returns:
        The raw If-Match header value, or None if not present
    """
    return if_match


def get_etag_context(request: Request) -> dict:
    """Get ETag-related context from request.

    Helper function to extract ETag related information
    from the request for use in endpoint logic.

    Args:
        request: The FastAPI request object

    Returns:
        Dictionary with ETag context:
        - has_if_none_match: bool
        - if_none_match: str | None
        - has_if_match: bool
        - if_match: str | None
    """
    return {
        'has_if_none_match': 'if-none-match' in request.headers,
        'if_none_match': request.headers.get('if-none-match'),
        'has_if_match': 'if-match' in request.headers,
        'if_match': request.headers.get('if-match'),
    }
