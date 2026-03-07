"""FastAPI application entrypoint."""

import logging
import os

from fastapi import FastAPI

from app.bootstrap.http import (
    configure_exception_handlers,
    configure_middlewares,
    register_internal_routes,
)
from app.bootstrap.lifecycle import application_lifespan
from app.bootstrap.routers import include_application_routers
from app.core.config import get_settings
from app.core.json_encoder import CustomJSONResponse
from app.core.logging_config import setup_logging_from_env


setup_logging_from_env()
logger = logging.getLogger(__name__)


def create_application() -> FastAPI:
    """Create and configure FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.PROJECT_NAME,
        description="Personal AI Assistant API",
        version=settings.VERSION,
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        lifespan=application_lifespan,
        default_response_class=CustomJSONResponse,
    )

    configure_middlewares(app)
    configure_exception_handlers(app)
    include_application_routers(app)
    register_internal_routes(app)

    return app


app = create_application()


if __name__ == "__main__":
    settings = get_settings()
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

    logger.info("Launching application with %s", command)
    os.execvp(command[0], command)
