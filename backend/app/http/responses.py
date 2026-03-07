"""Shared HTTP response helpers."""

from fastapi import Request

from app.core.etag import build_conditional_etag_response


def build_etag_response(
    *,
    request: Request,
    content,
    max_age: int,
    cache_control: str,
):
    """Thin wrapper around the ETag response builder for route consistency."""
    return build_conditional_etag_response(
        request=request,
        content=content,
        max_age=max_age,
        cache_control=cache_control,
    )
