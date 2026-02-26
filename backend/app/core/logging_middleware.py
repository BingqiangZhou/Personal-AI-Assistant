"""
Request logging middleware.
"""

import logging
import time
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


logger = logging.getLogger(__name__)


SKIP_LOG_PATHS = {
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/api/v1/openapi.json",
}


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log request/response metadata with minimal overhead."""

    def __init__(self, app: ASGIApp, log_level: int = logging.INFO):
        super().__init__(app)
        self.log_level = log_level

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in SKIP_LOG_PATHS:
            return await call_next(request)

        start_time = time.time()

        method = request.method
        path = request.url.path
        client_host = request.client.host if request.client else "unknown"

        # Avoid expensive token/session verification in middleware.
        user_id = "anonymous"
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            user_id = "authenticated"
        elif "admin_session" in request.cookies:
            user_id = "admin_session"

        logger.info(
            "API request started: %s %s | client=%s | user=%s",
            method,
            path,
            client_host,
            user_id,
        )

        try:
            response = await call_next(request)

            process_time = time.time() - start_time
            status_code = response.status_code
            log_msg = (
                f"API request completed: {method} {path} | "
                f"status={status_code} | elapsed={process_time:.3f}s | "
                f"client={client_host}"
            )

            if status_code >= 500:
                logger.error(log_msg)
            elif status_code >= 400:
                logger.warning(log_msg)
            else:
                logger.info(log_msg)

            response.headers["X-Process-Time"] = f"{process_time:.3f}"
            return response

        except Exception as exc:
            process_time = time.time() - start_time
            logger.error(
                "API request failed: %s %s | error=%s | elapsed=%.3fs | client=%s",
                method,
                path,
                str(exc),
                process_time,
                client_host,
                exc_info=True,
            )
            raise


class SlowRequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs requests exceeding the configured latency threshold."""

    def __init__(self, app: ASGIApp, slow_threshold: float = 5.0):
        super().__init__(app)
        self.slow_threshold = slow_threshold

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in SKIP_LOG_PATHS:
            return await call_next(request)

        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time

        if process_time > self.slow_threshold:
            logger.warning(
                "Slow request detected: %s %s | elapsed=%.3fs (threshold=%.3fs)",
                request.method,
                request.url.path,
                process_time,
                self.slow_threshold,
            )

        return response


def setup_logging_middleware(app, slow_threshold: float = 5.0) -> None:
    """Configure logging middleware for a FastAPI app."""
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(SlowRequestLoggingMiddleware, slow_threshold=slow_threshold)
