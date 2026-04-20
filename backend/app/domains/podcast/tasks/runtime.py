"""Shared runtime helpers for podcast Celery tasks."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession


_logger = logging.getLogger(__name__)

from app.core.database import (
    get_async_session_factory,
    register_orm_models,
)
from app.core.redis import get_shared_redis
from app.domains.podcast.tasks._runlog import _insert_run_async


def ensure_orm_models_registered() -> None:
    """Register ORM models when the worker runtime first needs them."""
    register_orm_models()


@asynccontextmanager
async def worker_session(application_name: str) -> AsyncIterator[AsyncSession]:
    """Create an isolated worker DB session."""
    ensure_orm_models_registered()
    session_factory = get_async_session_factory()
    async with session_factory() as session:
        yield session


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
    """Record a task run to the BackgroundTaskRun table.

    Failures are logged but never propagated to the caller, so they
    cannot mask the original task exception or prevent retry logic.
    """
    try:
        run_async(
            _insert_run_async(
                task_name=task_name,
                queue_name=queue_name,
                status=status,
                started_at=started_at,
                finished_at=finished_at,
                error_message=error_message,
                metadata=metadata,
            ),
        )
    except Exception:
        _logger.exception("Failed to log task run for %s", task_name)


@asynccontextmanager
async def single_instance_task_lock(
    lock_name: str,
    *,
    ttl_seconds: int,
) -> AsyncIterator[bool]:
    """Guard a periodic task so only one worker instance runs it at a time."""
    redis = get_shared_redis()
    acquired = await redis.acquire_lock(lock_name, expire=ttl_seconds)
    try:
        yield acquired
    finally:
        if acquired:
            await redis.release_lock(lock_name)
