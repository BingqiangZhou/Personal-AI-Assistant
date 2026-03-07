"""Application lifespan bootstrap."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import get_settings
from app.core.database import close_db, get_async_session_factory, init_db


logger = logging.getLogger(__name__)


@asynccontextmanager
async def application_lifespan(app: FastAPI):
    """Manage startup and shutdown lifecycle hooks."""
    settings = get_settings()

    logger.info(
        "Starting %s v%s - environment: %s",
        settings.PROJECT_NAME,
        settings.VERSION,
        settings.ENVIRONMENT,
    )
    await init_db()

    try:
        from app.domains.podcast.transcription_manager import (
            DatabaseBackedTranscriptionService,
        )

        session_factory = get_async_session_factory()
        async with session_factory() as session:
            service = DatabaseBackedTranscriptionService(session)
            await service.reset_stale_tasks()
            logger.info("Reset stale transcription tasks during startup")
    except Exception as exc:
        logger.error("Failed to reset stale tasks during startup: %s", exc)

    logger.info("Service startup completed")
    try:
        yield
    finally:
        await close_db()
        logger.info("Service shutdown completed")
