import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.core.config import settings
from app.core.database import get_db_pool_snapshot, init_db
from app.core.exceptions import setup_exception_handlers
from app.core.json_encoder import CustomJSONResponse
from app.core.logging_config import setup_logging_from_env
from app.core.logging_middleware import setup_logging_middleware
from app.core.middleware import (
    PerformanceMonitoringMiddleware,
    get_performance_middleware,
)
from app.core.observability import ObservabilityThresholds, build_observability_snapshot
from app.core.redis import get_redis_runtime_metrics


# 初始化日志系统
setup_logging_from_env()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info(
        f"启动 {settings.PROJECT_NAME} v{settings.VERSION} - 环境: {settings.ENVIRONMENT}"
    )
    await init_db()

    # Reset stale transcription tasks
    try:
        from app.core.database import async_session_factory
        from app.domains.podcast.transcription_manager import (
            DatabaseBackedTranscriptionService,
        )

        async with async_session_factory() as session:
            service = DatabaseBackedTranscriptionService(session)
            await service.reset_stale_tasks()
            logger.info("重置过期转录任务完成")
    except Exception as e:
        logger.error(f"启动时重置过期任务失败: {e}")

    logger.info("服务启动完成")
    yield
    # Shutdown
    from app.core.database import close_db

    await close_db()
    logger.info("服务已关闭")


def create_application() -> FastAPI:
    """Create and configure FastAPI application."""

    app = FastAPI(
        title=settings.PROJECT_NAME,
        description="Personal AI Assistant API",
        version="1.0.0",
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        lifespan=lifespan,
        default_response_class=CustomJSONResponse,  # 使用自定义 JSON 响应类
    )

    # Set up a single app-scoped metrics store.
    app.state.performance_metrics_store = get_performance_middleware(app)
    app.add_middleware(PerformanceMonitoringMiddleware)
    logger.info("Performance monitoring middleware enabled")

    # Set up CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_HOSTS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Set up logging middleware
    setup_logging_middleware(app, slow_threshold=5.0)

    # Set up first-run middleware for admin setup
    from app.admin.first_run import first_run_middleware

    app.middleware("http")(first_run_middleware)

    # Set up exception handlers
    setup_exception_handlers(app)

    # Add custom exception handler for admin panel
    @app.exception_handler(HTTPException)
    async def custom_http_exception_handler(request, exc):
        # Check if this is an admin panel request
        is_admin_request = request.url.path.startswith("/super/")

        # Handle 2FA redirect
        if exc.status_code == status.HTTP_307_TEMPORARY_REDIRECT:
            return RedirectResponse(
                url=exc.headers.get("Location", "/super/2fa/setup"),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        # Handle 401 Unauthorized for admin panel - redirect to login
        if (
            is_admin_request
            and exc.status_code == status.HTTP_401_UNAUTHORIZED
            and request.url.path != "/super/login"
        ):
            return RedirectResponse(
                url="/super/login", status_code=status.HTTP_303_SEE_OTHER
            )

        # Handle other errors for admin panel - show error page
        if is_admin_request and exc.status_code >= 400:
            from fastapi.templating import Jinja2Templates

            templates = Jinja2Templates(directory="app/admin/templates")
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error_message": exc.detail
                    if isinstance(exc.detail, str)
                    else "发生了一个错误",
                    "error_detail": f"错误代码: {exc.status_code}",
                },
                status_code=exc.status_code,
            )

        # For other HTTP exceptions, use default handler
        from fastapi.exception_handlers import http_exception_handler

        return await http_exception_handler(request, exc)

    # Include routers
    from app.admin.csrf import CSRFException
    from app.admin.exception_handlers import csrf_exception_handler
    from app.admin.router import router as admin_router
    from app.domains.ai.api.routes import router as ai_model_router
    from app.domains.podcast.api.routes import router as podcast_router
    from app.domains.subscription.api.routes import router as subscription_router
    from app.domains.user.api.routes import router as user_router

    app.include_router(
        user_router, prefix=f"{settings.API_V1_STR}/auth", tags=["authentication"]
    )

    app.include_router(
        subscription_router,
        prefix=f"{settings.API_V1_STR}/subscriptions",
        tags=["subscriptions"],
    )

    app.include_router(
        podcast_router, prefix=f"{settings.API_V1_STR}/podcasts", tags=["podcasts"]
    )

    app.include_router(
        ai_model_router, prefix=f"{settings.API_V1_STR}/ai", tags=["ai-models"]
    )

    # Admin panel routes (changed to /super for security)
    app.include_router(admin_router, prefix="/super", tags=["admin"])

    # Register CSRF exception handler for admin panel
    app.add_exception_handler(CSRFException, csrf_exception_handler)

    # Root endpoint - Welcome page
    @app.get("/")
    async def root():
        return {
            "message": "Personal AI Assistant API is running",
            "status": "healthy",
            "version": "1.0.0",
            "docs": "/api/v1/docs",
            "health": "/health",
        }

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        return {"status": "healthy"}

    @app.get(f"{settings.API_V1_STR}/health")
    async def health_check_v1():
        return {"status": "healthy"}

    observability_thresholds = ObservabilityThresholds(
        api_p95_ms=settings.OBS_ALERT_API_P95_MS,
        api_error_rate=settings.OBS_ALERT_API_ERROR_RATE,
        db_pool_occupancy_ratio=settings.OBS_ALERT_DB_POOL_OCCUPANCY_RATIO,
        redis_command_avg_ms=settings.OBS_ALERT_REDIS_COMMAND_AVG_MS,
        redis_command_max_ms=settings.OBS_ALERT_REDIS_COMMAND_MAX_MS,
        redis_cache_hit_rate_min=settings.OBS_ALERT_REDIS_CACHE_HIT_RATE_MIN,
        redis_cache_lookups_min=settings.OBS_ALERT_REDIS_CACHE_LOOKUPS_MIN,
    )

    def _build_metrics_payload() -> dict:
        middleware = get_performance_middleware(app)
        if not middleware:
            return {"error": "Performance monitoring not enabled"}

        metrics = middleware.get_metrics()
        db_pool = get_db_pool_snapshot()
        redis_runtime = get_redis_runtime_metrics()
        observability = build_observability_snapshot(
            performance_metrics=metrics,
            db_pool=db_pool,
            redis_runtime=redis_runtime,
            thresholds=observability_thresholds,
        )
        metrics["db_pool"] = db_pool
        metrics["redis_runtime"] = redis_runtime
        metrics["observability"] = observability
        return metrics

    # Performance metrics endpoint
    @app.get("/metrics", include_in_schema=False)
    async def get_metrics():
        """Get performance metrics (internal use only)."""
        return _build_metrics_payload()

    @app.get("/metrics/summary", include_in_schema=False)
    async def get_metrics_summary():
        """Get compact observability summary for dashboards and alerts."""
        payload = _build_metrics_payload()
        if "error" in payload:
            return payload
        return payload["observability"]

    return app


app = create_application()

# raise Exception("TEST RELOAD")

if __name__ == "__main__":
    command = [
        "gunicorn",
        "app.main:app",
        "--worker-class",
        "uvicorn.workers.UvicornWorker",
        "--bind",
        "0.0.0.0:8000",
    ]
    if settings.ENVIRONMENT == "development":
        command.append("--reload")
    else:
        command.extend(["--workers", "4", "--timeout", "120", "--log-level", "info"])
    os.execvp(command[0], command)
