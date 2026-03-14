"""Shared aiohttp client session management."""

from __future__ import annotations

import asyncio

import aiohttp


_shared_http_session: aiohttp.ClientSession | None = None
_shared_http_session_loop_token: int | None = None
_http_session_lock = asyncio.Lock()


def _current_loop_token() -> int | None:
    try:
        return id(asyncio.get_running_loop())
    except RuntimeError:
        return None


async def get_shared_http_session() -> aiohttp.ClientSession:
    """Return a process-level shared aiohttp session for outbound HTTP calls."""
    global _shared_http_session, _shared_http_session_loop_token

    current_loop_token = _current_loop_token()

    async with _http_session_lock:
        if (
            _shared_http_session is not None
            and _shared_http_session_loop_token == current_loop_token
            and not _shared_http_session.closed
        ):
            return _shared_http_session

        if _shared_http_session is not None and not _shared_http_session.closed:
            await _shared_http_session.close()

        connector = aiohttp.TCPConnector(limit=100, limit_per_host=20)
        # Per-request timeout should be passed explicitly by callers.
        _shared_http_session = aiohttp.ClientSession(connector=connector)
        _shared_http_session_loop_token = current_loop_token
        return _shared_http_session


async def close_shared_http_session() -> None:
    """Close and clear the shared aiohttp session."""
    global _shared_http_session, _shared_http_session_loop_token

    async with _http_session_lock:
        if _shared_http_session is not None and not _shared_http_session.closed:
            await _shared_http_session.close()
        _shared_http_session = None
        _shared_http_session_loop_token = None
