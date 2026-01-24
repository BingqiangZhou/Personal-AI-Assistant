"""
Performance Monitoring Middleware

Tracks API response times, cache hit rates, and slow queries.
"""

import time
import logging
from typing import Callable, Awaitable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# Performance thresholds
SLOW_QUERY_THRESHOLD_MS = 100
SLOW_API_THRESHOLD_MS = 500


class PerformanceMonitoringMiddleware(BaseHTTPMiddleware):
    """
    Middleware to track API performance metrics.

    Tracks:
    - Response times for each endpoint
    - Slow queries (>100ms)
    - Request counts
    - Error rates
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.request_counts = {}
        self.response_times = {}
        self.error_counts = {}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip monitoring for health checks and metrics endpoint
        if request.url.path in ['/health', '/metrics', '/api/v1/health']:
            return await call_next(request)

        # Start timer
        start_time = time.time()

        # Process request
        try:
            response = await call_next(request)

            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000

            # Track metrics
            self._track_request(request, duration_ms, response.status_code)

            # Log slow requests
            if duration_ms > SLOW_API_THRESHOLD_MS:
                logger.warning(
                    f"🐌 SLOW API: {request.method} {request.url.path} "
                    f"took {duration_ms:.2f}ms"
                )

            # Add performance header
            response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"

            return response

        except Exception as e:
            # Track errors
            duration_ms = (time.time() - start_time) * 1000
            self._track_error(request, duration_ms)
            logger.error(f"❌ API Error: {request.method} {request.url.path} - {e}")
            raise

    def _track_request(self, request: Request, duration_ms: float, status_code: int):
        """Track request metrics"""
        path = request.url.path

        # Update request counts
        key = f"{request.method} {path}"
        self.request_counts[key] = self.request_counts.get(key, 0) + 1

        # Update response times (track min, max, avg)
        if key not in self.response_times:
            self.response_times[key] = {
                'count': 0,
                'total_ms': 0,
                'min_ms': float('inf'),
                'max_ms': 0,
            }

        stats = self.response_times[key]
        stats['count'] += 1
        stats['total_ms'] += duration_ms
        stats['min_ms'] = min(stats['min_ms'], duration_ms)
        stats['max_ms'] = max(stats['max_ms'], duration_ms)

        # Log performance data periodically
        if stats['count'] % 100 == 0:
            avg_ms = stats['total_ms'] / stats['count']
            logger.info(
                f"📊 Performance [100 requests]: {key}\n"
                f"   Avg: {avg_ms:.2f}ms | Min: {stats['min_ms']:.2f}ms | "
                f"Max: {stats['max_ms']:.2f}ms"
            )

    def _track_error(self, request: Request, duration_ms: float):
        """Track error metrics"""
        key = f"{request.method} {request.url.path}"
        self.error_counts[key] = self.error_counts.get(key, 0) + 1

    def get_metrics(self) -> dict:
        """Get current performance metrics"""
        metrics = {
            'request_counts': self.request_counts.copy(),
            'response_times': {},
            'error_counts': self.error_counts.copy(),
        }

        # Calculate average response times
        for key, stats in self.response_times.items():
            metrics['response_times'][key] = {
                'count': stats['count'],
                'avg_ms': stats['total_ms'] / stats['count'],
                'min_ms': stats['min_ms'],
                'max_ms': stats['max_ms'],
            }

        return metrics

    def reset_metrics(self):
        """Reset all metrics"""
        self.request_counts.clear()
        self.response_times.clear()
        self.error_counts.clear()


# Global middleware instance
_performance_middleware: PerformanceMonitoringMiddleware | None = None


def get_performance_middleware() -> PerformanceMonitoringMiddleware | None:
    """Get the global performance middleware instance"""
    return _performance_middleware


def set_performance_middleware(middleware: PerformanceMonitoringMiddleware):
    """Set the global performance middleware instance"""
    global _performance_middleware
    _performance_middleware = middleware
