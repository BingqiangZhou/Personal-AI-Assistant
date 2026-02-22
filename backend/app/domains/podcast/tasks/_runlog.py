"""Task run logging utilities."""

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.admin.models import BackgroundTaskRun
from app.core.config import settings


async def _insert_run_async(
    task_name: str,
    queue_name: str,
    status: str,
    started_at: datetime,
    finished_at: datetime | None = None,
    error_message: str | None = None,
    metadata: dict | None = None,
) -> None:
    # Create an isolated engine and session to avoid event loop conflicts
    # when this is called via asyncio.run() in Celery workers.
    # The shared async_session_factory from database.py cannot be safely
    # used across multiple asyncio.run() calls.
    #
    # Using NullPool is critical here: connection pools can retain connections
    # that were bound to a different event loop. When asyncio.run() creates
    # a new loop, pool_pre_ping or any pooled connection would try to use
    # a Future from the old loop, causing:
    # "RuntimeError: Task got Future attached to a different loop"
    engine = create_async_engine(
        settings.DATABASE_URL,
        poolclass=NullPool,  # No pooling - fresh connection each time
        pool_pre_ping=False,  # CRITICAL: Disable ping to avoid event loop conflicts in Celery workers
        connect_args={
            "server_settings": {
                "application_name": "celery-runlog",
                "client_encoding": "utf8",
            },
            "timeout": settings.DATABASE_CONNECT_TIMEOUT,
        },
    )
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    try:
        async with session_factory() as session:
            duration_ms = None
            if finished_at is not None:
                duration_ms = int((finished_at - started_at).total_seconds() * 1000)
            session.add(
                BackgroundTaskRun(
                    task_name=task_name,
                    queue_name=queue_name,
                    status=status,
                    started_at=started_at,
                    finished_at=finished_at,
                    duration_ms=duration_ms,
                    error_message=error_message,
                    metadata_json=metadata or {},
                )
            )
            await session.commit()
    finally:
        await engine.dispose()
