"""Shared runtime helpers for podcast Celery tasks."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

# Import ALL models to ensure SQLAlchemy properly initializes all relationships
# This is critical for Celery workers which create isolated DB engines
from app.admin.models import BackgroundTaskRun  # noqa: F401
from app.core.config import settings
from app.domains.ai.models import AIModelConfig  # noqa: F401
from app.domains.podcast.models import (  # noqa: F401
    PodcastConversation,
    PodcastEpisode,
    PodcastPlaybackState,
    TranscriptionTask,
)
from app.domains.podcast.tasks._runlog import _insert_run_async
from app.domains.subscription.models import (  # noqa: F401
    Subscription,
    SubscriptionCategory,
    SubscriptionCategoryMapping,
    SubscriptionItem,
    UserSubscription,
)
from app.domains.user.models import PasswordReset, User, UserSession  # noqa: F401


def _new_session_factory(
    application_name: str,
) -> tuple[async_sessionmaker[AsyncSession], Any]:
    # Use NullPool to avoid event loop conflicts when asyncio.run() is called
    # multiple times in Celery workers. Connection pools retain connections
    # bound to a specific event loop, which causes "Future attached to a
    # different loop" errors when a new loop is created.
    engine = create_async_engine(
        settings.DATABASE_URL,
        poolclass=NullPool,  # No pooling - fresh connection each time
        pool_pre_ping=False,  # CRITICAL: Disable ping to avoid event loop conflicts in Celery workers
        connect_args={
            "server_settings": {
                "application_name": application_name,
                "client_encoding": "utf8",
            },
            "timeout": settings.DATABASE_CONNECT_TIMEOUT,
        },
    )
    return (
        async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False),
        engine,
    )


@asynccontextmanager
async def worker_session(application_name: str) -> AsyncIterator[AsyncSession]:
    """Create an isolated worker DB session and always dispose its engine."""
    session_factory, engine = _new_session_factory(application_name)
    try:
        async with session_factory() as session:
            yield session
    finally:
        await engine.dispose()


def run_async(coro):
    """Run async code from sync Celery workers safely."""
    return asyncio.run(coro)


def log_task_run(
    *,
    task_name: str,
    queue_name: str,
    status: str,
    started_at: datetime,
    finished_at: datetime | None = None,
    error_message: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    run_async(
        _insert_run_async(
            task_name=task_name,
            queue_name=queue_name,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            error_message=error_message,
            metadata=metadata,
        )
    )
