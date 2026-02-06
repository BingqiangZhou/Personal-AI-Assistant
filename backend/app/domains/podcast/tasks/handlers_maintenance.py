"""Handlers for maintenance and housekeeping tasks."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select

from app.admin.storage_service import StorageCleanupService
from app.domains.podcast.models import PodcastPlaybackState, TranscriptionTask
from app.domains.podcast.transcription_manager import DatabaseBackedTranscriptionService


logger = logging.getLogger(__name__)


async def get_task_statistics_handler(session) -> dict:
    """Collect transcription task queue statistics."""
    count_stmt = select(TranscriptionTask.status, func.count(TranscriptionTask.id)).group_by(
        TranscriptionTask.status
    )
    count_result = await session.execute(count_stmt)
    grouped = dict(count_result.all())

    pending_time_stmt = select(
        func.min(TranscriptionTask.created_at),
        func.max(TranscriptionTask.created_at),
    ).where(TranscriptionTask.status == "pending")
    pending_time_result = await session.execute(pending_time_stmt)
    oldest_pending, newest_pending = pending_time_result.one()

    return {
        "pending": grouped.get("pending", 0),
        "in_progress": grouped.get("in_progress", 0),
        "completed": grouped.get("completed", 0),
        "failed": grouped.get("failed", 0),
        "cancelled": grouped.get("cancelled", 0),
        "oldest_pending": oldest_pending,
        "newest_pending": newest_pending,
    }


async def log_periodic_task_statistics_handler(session) -> dict:
    """Log current task statistics and return snapshot."""
    stats = await get_task_statistics_handler(session)
    total_waiting = stats["pending"] + stats["in_progress"]
    total_processed = stats["completed"] + stats["failed"] + stats["cancelled"]
    logger.info(
        "Task stats: waiting=%s processed=%s pending=%s in_progress=%s failed=%s",
        total_waiting,
        total_processed,
        stats["pending"],
        stats["in_progress"],
        stats["failed"],
    )
    return {"status": "success", "stats": stats, "logged_at": datetime.utcnow().isoformat()}


async def cleanup_old_playback_states_handler(session) -> dict:
    """Delete playback states older than 90 days."""
    cutoff_date = datetime.utcnow() - timedelta(days=90)
    stmt = delete(PodcastPlaybackState).where(PodcastPlaybackState.last_updated_at < cutoff_date)
    result = await session.execute(stmt)
    await session.commit()
    return {
        "status": "success",
        "deleted_count": result.rowcount or 0,
        "processed_at": datetime.utcnow().isoformat(),
    }


async def cleanup_old_transcription_temp_files_handler(session, days: int = 7) -> dict:
    """Clean stale transcription temporary files."""
    service = DatabaseBackedTranscriptionService(session)
    result = await service.cleanup_old_temp_files(days=days)
    return {"status": "success", **result, "processed_at": datetime.utcnow().isoformat()}


async def auto_cleanup_cache_files_handler(session) -> dict:
    """Execute cache cleanup when enabled by admin settings."""
    service = StorageCleanupService(session)
    config = await service.get_cleanup_config()

    if not config.get("enabled"):
        return {
            "status": "skipped",
            "reason": "Auto cleanup is disabled",
            "checked_at": datetime.utcnow().isoformat(),
        }

    result = await service.execute_cleanup(keep_days=1)
    return {"status": "success", **result, "executed_at": datetime.utcnow().isoformat()}
