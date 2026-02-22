"""
Performance monitoring middleware.
"""

import logging
import time
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


logger = logging.getLogger(__name__)

SLOW_API_THRESHOLD_MS = 500


class PerformanceMetricsStore:
    """Process-wide request metrics store."""

    def __init__(self):
        self.request_counts: dict[str, int] = {}
        self.response_times: dict[str, dict[str, float]] = {}
        self.error_counts: dict[str, int] = {}

    def track_request(self, key: str, duration_ms: float) -> None:
        self.request_counts[key] = self.request_counts.get(key, 0) + 1

        if key not in self.response_times:
            self.response_times[key] = {
                "count": 0,
                "total_ms": 0.0,
                "min_ms": float("inf"),
                "max_ms": 0.0,
            }

        stats = self.response_times[key]
        stats["count"] += 1
        stats["total_ms"] += duration_ms
        stats["min_ms"] = min(stats["min_ms"], duration_ms)
        stats["max_ms"] = max(stats["max_ms"], duration_ms)

    def track_error(self, key: str) -> None:
        self.error_counts[key] = self.error_counts.get(key, 0) + 1

    def get_metrics(self) -> dict:
        response_stats: dict[str, dict[str, float]] = {}
        for key, stats in self.response_times.items():
            count = stats["count"]
            response_stats[key] = {
                "count": count,
                "avg_ms": (stats["total_ms"] / count) if count else 0.0,
                "min_ms": stats["min_ms"],
                "max_ms": stats["max_ms"],
            }

        return {
            "request_counts": self.request_counts.copy(),
            "response_times": response_stats,
            "error_counts": self.error_counts.copy(),
        }

    def reset_metrics(self) -> None:
        self.request_counts.clear()
        self.response_times.clear()
        self.error_counts.clear()


_performance_metrics_store = PerformanceMetricsStore()


def _get_store_from_app(app: ASGIApp | None) -> PerformanceMetricsStore:
    """Return app-bound store when available, otherwise fallback store."""
    if app is not None:
        state = getattr(app, "state", None)
        if state is not None:
            store = getattr(state, "performance_metrics_store", None)
            if store is None:
                state.performance_metrics_store = _performance_metrics_store
                return _performance_metrics_store
            return store
    return _performance_metrics_store


class PerformanceMonitoringMiddleware(BaseHTTPMiddleware):
    """Track API response times and request counts."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in {"/health", "/metrics", "/api/v1/health"}:
            return await call_next(request)

        start_time = time.time()
        key = f"{request.method} {request.url.path}"
        store = _get_store_from_app(request.app)

        try:
            response = await call_next(request)
            duration_ms = (time.time() - start_time) * 1000

            store.track_request(key, duration_ms)
            if duration_ms > SLOW_API_THRESHOLD_MS:
                logger.warning(
                    "Slow API: %s took %.2fms",
                    key,
                    duration_ms,
                )

            response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"
            return response

        except Exception as exc:
            store.track_error(key)
            logger.error("API error on %s: %s", key, exc)
            raise


def get_performance_middleware(app: ASGIApp | None = None) -> PerformanceMetricsStore:
    """Get performance metrics store bound to app state when possible."""
    return _get_store_from_app(app)


def set_performance_middleware(
    middleware: PerformanceMonitoringMiddleware,
):
    """Backward-compatible no-op setter."""
    return middleware
