from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

from app.core.config import settings
from app.core.database import init_db
from app.core.exceptions import setup_exception_handlers


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    yield
    # Shutdown
    pass


def create_application() -> FastAPI:
    """Create and configure FastAPI application."""

    app = FastAPI(
        title=settings.PROJECT_NAME,
        description="Personal AI Assistant API",
        version="1.0.0",
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        lifespan=lifespan
    )

    # Set up CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_HOSTS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Set up exception handlers
    setup_exception_handlers(app)

    # Include routers
    from app.domains.user.api.routes import router as user_router
    from app.domains.subscription.api.routes import router as subscription_router
    from app.domains.knowledge.api.routes import router as knowledge_router
    from app.domains.assistant.api.routes import router as assistant_router
    from app.domains.multimedia.api.routes import router as multimedia_router
    from app.domains.podcast.api.routes import router as podcast_router

    app.include_router(
        user_router,
        prefix=f"{settings.API_V1_STR}/auth",
        tags=["authentication"]
    )

    app.include_router(
        subscription_router,
        prefix=f"{settings.API_V1_STR}/subscriptions",
        tags=["subscriptions"]
    )

    app.include_router(
        podcast_router,
        prefix=f"{settings.API_V1_STR}/podcasts",
        tags=["podcasts"]
    )

    app.include_router(
        knowledge_router,
        prefix=f"{settings.API_V1_STR}/knowledge",
        tags=["knowledge"]
    )

    app.include_router(
        assistant_router,
        prefix=f"{settings.API_V1_STR}/assistant",
        tags=["assistant"]
    )

    app.include_router(
        multimedia_router,
        prefix=f"{settings.API_V1_STR}/multimedia",
        tags=["multimedia"]
    )

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        return {"status": "healthy"}

    return app


app = create_application()


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True if settings.ENVIRONMENT == "development" else False
    )