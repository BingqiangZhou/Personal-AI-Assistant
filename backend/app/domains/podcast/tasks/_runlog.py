"""Task run logging utilities."""

from datetime import datetime

from app.admin.models import BackgroundTaskRun
from app.core.database import async_session_factory


async def _insert_run_async(
    task_name: str,
    queue_name: str,
    status: str,
    started_at: datetime,
    finished_at: datetime | None = None,
    error_message: str | None = None,
    metadata: dict | None = None,
) -> None:
    async with async_session_factory() as session:
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

