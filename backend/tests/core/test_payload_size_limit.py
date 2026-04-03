"""Tests for PayloadSizeLimitMiddleware — especially chunked transfer-encoding.

Verifies that both Content-Length (fast path) and Transfer-Encoding: chunked
(streaming path) requests are properly limited to the configured maximum.
"""

from __future__ import annotations

import pytest

from app.core.middleware.response_optimization import PayloadSizeLimitMiddleware


# ---------------------------------------------------------------------------
# Helpers — lightweight ASGI app / receive / send stubs
# ---------------------------------------------------------------------------

class _SentMessages(list):
    """Collects ASGI messages sent by the middleware."""


def _make_asgi_app(status: int = 200, body: bytes = b"ok"):
    """Return a minimal ASGI app that reads the full request and replies."""

    async def app(scope, receive, send):
        # Read all request body
        chunks: list[bytes] = []
        while True:
            msg = await receive()
            if msg.get("type") == "http.request":
                chunks.append(msg.get("body", b""))
                if not msg.get("more_body", False):
                    break
            else:
                break

        total = b"".join(chunks)
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [[b"content-type", b"text/plain"]],
        })
        await send({
            "type": "http.response.body",
            "body": str(len(total)).encode(),
        })

    return app


def _make_scope(
    method: str = "POST",
    path: str = "/api/v1/test",
    headers: dict[bytes, bytes] | None = None,
) -> dict:
    scope: dict = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [
            [k, v] for k, v in (headers or {}).items()
        ],
    }
    return scope


class _ChunkedReceive:
    """Simulate a chunked ASGI receive — yields ``http.request`` messages."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._messages: list[dict] = []
        for i, chunk in enumerate(chunks):
            self._messages.append({
                "type": "http.request",
                "body": chunk,
                "more_body": i < len(chunks) - 1,
            })

    async def __call__(self) -> dict:
        if self._messages:
            return self._messages.pop(0)
        return {"type": "http.disconnect"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def max_size() -> int:
    """Small limit (1 KB) for fast tests."""
    return 1024


@pytest.fixture()
def middleware(max_size: int) -> PayloadSizeLimitMiddleware:
    app = _make_asgi_app()
    return PayloadSizeLimitMiddleware(app, max_content_length=max_size)


async def _invoke(middleware, scope, receive, sent: _SentMessages):
    """Run the middleware, collecting send() messages."""

    async def send(msg):
        sent.append(msg)

    await middleware(scope, receive, send)


# ---------------------------------------------------------------------------
# Tests — Content-Length fast path
# ---------------------------------------------------------------------------

class TestContentLengthFastPath:
    """Verify the existing Content-Length checks still work."""

    @pytest.mark.asyncio
    async def test_within_limit_passes(self, middleware, max_size):
        sent = _SentMessages()
        scope = _make_scope(headers={b"content-length": str(max_size).encode()})
        receive = _ChunkedReceive([b"x" * max_size])
        await _invoke(middleware, scope, receive, sent)

        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert len(starts) == 1
        assert starts[0]["status"] == 200

    @pytest.mark.asyncio
    async def test_over_limit_rejected(self, middleware, max_size):
        sent = _SentMessages()
        scope = _make_scope(headers={b"content-length": str(max_size + 1).encode()})
        receive = _ChunkedReceive([b"x" * (max_size + 1)])
        await _invoke(middleware, scope, receive, sent)

        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert len(starts) == 1
        assert starts[0]["status"] == 413

    @pytest.mark.asyncio
    async def test_exact_limit_passes(self, middleware, max_size):
        sent = _SentMessages()
        scope = _make_scope(headers={b"content-length": str(max_size).encode()})
        receive = _ChunkedReceive([b"x" * max_size])
        await _invoke(middleware, scope, receive, sent)

        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert starts[0]["status"] == 200


# ---------------------------------------------------------------------------
# Tests — Chunked transfer-encoding (the fix)
# ---------------------------------------------------------------------------

class TestChunkedTransferEncoding:
    """Verify chunked bodies are properly tracked and rejected."""

    @pytest.mark.asyncio
    async def test_single_chunk_within_limit(self, middleware, max_size):
        sent = _SentMessages()
        scope = _make_scope()  # No Content-Length header
        receive = _ChunkedReceive([b"x" * max_size])
        await _invoke(middleware, scope, receive, sent)

        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert len(starts) == 1
        assert starts[0]["status"] == 200

    @pytest.mark.asyncio
    async def test_single_chunk_over_limit(self, middleware, max_size):
        sent = _SentMessages()
        scope = _make_scope()
        receive = _ChunkedReceive([b"x" * (max_size + 1)])
        await _invoke(middleware, scope, receive, sent)

        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert len(starts) == 1
        assert starts[0]["status"] == 413

    @pytest.mark.asyncio
    async def test_multiple_chunks_accumulate(self, middleware, max_size):
        """Several small chunks that together exceed the limit must be rejected."""
        sent = _SentMessages()
        scope = _make_scope()
        # 10 chunks of 200 bytes each = 2000 bytes > 1024 limit
        chunks = [b"x" * 200] * 10
        receive = _ChunkedReceive(chunks)
        await _invoke(middleware, scope, receive, sent)

        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert len(starts) == 1
        assert starts[0]["status"] == 413

    @pytest.mark.asyncio
    async def test_multiple_chunks_within_limit(self, middleware, max_size):
        """Several small chunks that stay within limit must pass."""
        sent = _SentMessages()
        scope = _make_scope()
        chunks = [b"x" * 200] * 5  # 1000 bytes < 1024 limit
        receive = _ChunkedReceive(chunks)
        await _invoke(middleware, scope, receive, sent)

        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert starts[0]["status"] == 200

    @pytest.mark.asyncio
    async def test_chunked_bypass_is_blocked(self):
        """The core fix: chunked encoding cannot bypass the 10 MB default limit.

        Send many small chunks totaling more than the default 10 MB.
        The middleware must reject the request with 413.
        """
        # Use the real 10 MB default
        app = _make_asgi_app()
        mw = PayloadSizeLimitMiddleware(app)

        sent = _SentMessages()
        scope = _make_scope()

        # 11 chunks of 1 MB each = 11 MB > 10 MB default
        one_mb = b"x" * (1024 * 1024)
        chunks = [one_mb] * 11
        receive = _ChunkedReceive(chunks)

        await _invoke(mw, scope, receive, sent)

        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert len(starts) == 1
        assert starts[0]["status"] == 413

        # Verify the response body contains the expected error detail
        bodies = [m for m in sent if m["type"] == "http.response.body"]
        assert len(bodies) >= 1
        import orjson
        error_body = orjson.loads(bodies[0]["body"])
        assert "detail" in error_body
        assert "too large" in error_body["detail"].lower()

    @pytest.mark.asyncio
    async def test_exactly_at_limit_across_chunks(self, middleware, max_size):
        """Exact-limit across multiple chunks should pass."""
        sent = _SentMessages()
        scope = _make_scope()
        chunks = [b"x" * 512, b"x" * 512]  # 1024 bytes == limit
        receive = _ChunkedReceive(chunks)
        await _invoke(middleware, scope, receive, sent)

        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert starts[0]["status"] == 200

    @pytest.mark.asyncio
    async def test_one_byte_over_limit_across_chunks(self, middleware, max_size):
        """One byte over the limit across chunks must be rejected."""
        sent = _SentMessages()
        scope = _make_scope()
        chunks = [b"x" * 512, b"x" * 512, b"x"]  # 1025 bytes > 1024
        receive = _ChunkedReceive(chunks)
        await _invoke(middleware, scope, receive, sent)

        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert starts[0]["status"] == 413


# ---------------------------------------------------------------------------
# Tests — Non-body methods & excluded paths
# ---------------------------------------------------------------------------

class TestPassthrough:
    """Methods without bodies and excluded paths bypass the check."""

    @pytest.mark.asyncio
    async def test_get_passes_through(self, middleware):
        sent = _SentMessages()
        scope = _make_scope(method="GET")
        receive = _ChunkedReceive([])
        await _invoke(middleware, scope, receive, sent)

        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert starts[0]["status"] == 200

    @pytest.mark.asyncio
    async def test_delete_passes_through(self, middleware):
        sent = _SentMessages()
        scope = _make_scope(method="DELETE")
        receive = _ChunkedReceive([])
        await _invoke(middleware, scope, receive, sent)

        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert starts[0]["status"] == 200

    @pytest.mark.asyncio
    async def test_health_path_excluded(self, max_size):
        app = _make_asgi_app()
        mw = PayloadSizeLimitMiddleware(
            app, max_content_length=max_size, exclude_paths={"/api/v1/health"}
        )
        sent = _SentMessages()
        scope = _make_scope(path="/api/v1/health", headers={b"content-length": b"999999999"})
        receive = _ChunkedReceive([b"x" * 100])
        await _invoke(mw, scope, receive, sent)

        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert starts[0]["status"] == 200

    @pytest.mark.asyncio
    async def test_websocket_passes_through(self, middleware):
        """Non-http scope types should pass through unchanged."""
        sent: list[dict] = []

        async def receive():
            return {"type": "websocket.connect"}

        async def send(msg: dict):
            sent.append(msg)

        async def ws_app(scope, receive, send):
            await send({"type": "websocket.accept"})

        mw = PayloadSizeLimitMiddleware(ws_app, max_content_length=100)
        await mw({"type": "websocket"}, receive, send)
        assert sent[0]["type"] == "websocket.accept"


# ---------------------------------------------------------------------------
# Tests — Invalid Content-Length falls through to chunked handler
# ---------------------------------------------------------------------------

class TestInvalidContentLength:
    """Invalid Content-Length values should fall through to the streaming check."""

    @pytest.mark.asyncio
    async def test_non_numeric_content_length(self, middleware):
        sent = _SentMessages()
        scope = _make_scope(headers={b"content-length": b"not-a-number"})
        receive = _ChunkedReceive([b"x" * 100])
        await _invoke(middleware, scope, receive, sent)

        # Falls through to chunked handler, body is small, should pass
        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert starts[0]["status"] == 200

    @pytest.mark.asyncio
    async def test_non_numeric_with_large_body(self, middleware, max_size):
        sent = _SentMessages()
        scope = _make_scope(headers={b"content-length": b"garbage"})
        receive = _ChunkedReceive([b"x" * (max_size + 1)])
        await _invoke(middleware, scope, receive, sent)

        # Falls through to chunked handler, body exceeds limit
        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert starts[0]["status"] == 413
