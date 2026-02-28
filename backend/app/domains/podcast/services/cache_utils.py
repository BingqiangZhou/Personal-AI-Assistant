"""Shared cache access helpers for best-effort read/write/invalidate flows."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeVar


T = TypeVar("T")


async def safe_cache_get(
    getter: Callable[[], Awaitable[T]],
    *,
    log_warning: Callable[[str], None],
    error_message: str,
) -> T | None:
    """Try cache read and swallow backend cache errors."""
    try:
        return await getter()
    except Exception as exc:
        log_warning(f"{error_message}: {exc}")
        return None


async def safe_cache_write(
    writer: Callable[[], Awaitable[object]],
    *,
    log_warning: Callable[[str], None],
    error_message: str,
) -> bool:
    """Try cache write and return success status."""
    try:
        await writer()
        return True
    except Exception as exc:
        log_warning(f"{error_message}: {exc}")
        return False


async def safe_cache_invalidate(
    invalidator: Callable[[], Awaitable[object]],
    *,
    log_warning: Callable[[str], None],
    error_message: str,
) -> bool:
    """Try cache invalidation and return success status."""
    try:
        await invalidator()
        return True
    except Exception as exc:
        log_warning(f"{error_message}: {exc}")
        return False
