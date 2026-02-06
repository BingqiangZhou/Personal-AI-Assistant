"""Handlers for transcription Celery tasks."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from sqlalchemy import select

from app.core.redis import PodcastRedis
from app.domains.podcast.models import PodcastEpisode, TranscriptionTask
from app.domains.podcast.services import PodcastService
from app.domains.podcast.services.sync_service import PodcastSyncService
from app.domains.podcast.transcription_manager import DatabaseBackedTranscriptionService
from app.domains.podcast.transcription_state import get_transcription_state_manager


logger = logging.getLogger(__name__)


async def _claim_dispatched(task_id: int) -> bool:
    redis = PodcastRedis()
    key = f"podcast:transcription:dispatched:{task_id}"
    client = await redis._get_client()
    # First worker sets the key; others skip.
    result = await client.set(key, "1", nx=True, ex=7200)
    return result is not None


async def process_audio_transcription_handler(
    session,
    task_id: int,
    config_db_id: int | None = None,
) -> dict:
    """Execute transcription with lock + redis state updates."""
    if not await _claim_dispatched(task_id):
        return {"status": "skipped", "reason": "task_already_dispatched", "task_id": task_id}

    state_manager = await get_transcription_state_manager()

    stmt = select(TranscriptionTask).where(TranscriptionTask.id == task_id)
    result = await session.execute(stmt)
    task = result.scalar_one_or_none()
    if task is None:
        return {"status": "error", "reason": "task_not_found", "task_id": task_id}

    episode_id = task.episode_id
    lock_acquired = await state_manager.acquire_task_lock(episode_id, task_id, expire_seconds=3600)
    if not lock_acquired:
        locked_task_id = await state_manager.is_episode_locked(episode_id)
        return {
            "status": "skipped",
            "reason": "episode_locked",
            "task_id": task_id,
            "locked_by": locked_task_id,
        }

    service = DatabaseBackedTranscriptionService(session)
    original_update = service._update_task_progress_with_session

    async def redis_update_progress(db_session, internal_task_id, status, progress, message, error_message=None):
        await original_update(
            db_session,
            internal_task_id,
            status,
            progress,
            message,
            error_message,
        )
        status_value = status.value if hasattr(status, "value") else str(status)
        await state_manager.set_task_progress(internal_task_id, status_value, progress, message)

    service._update_task_progress_with_session = redis_update_progress

    try:
        await state_manager.set_task_progress(
            task_id,
            "pending",
            0,
            "Worker starting transcription process...",
        )
        await service.execute_transcription_task(task_id, session, config_db_id)
        await state_manager.clear_task_state(task_id, episode_id)
        return {
            "status": "success",
            "task_id": task_id,
            "config_db_id": config_db_id,
            "processed_at": datetime.utcnow().isoformat(),
        }
    except Exception as exc:
        await state_manager.fail_task_state(task_id, episode_id, str(exc))
        logger.exception("Transcription task failed for task_id=%s", task_id)
        raise
    finally:
        await state_manager.release_task_lock(episode_id, task_id)


async def process_podcast_episode_with_transcription_handler(
    session,
    episode_id: int,
    user_id: int,
) -> dict:
    """Process episode end-to-end: transcription then summary."""
    stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode_id)
    result = await session.execute(stmt)
    episode = result.scalar_one_or_none()
    if episode is None:
        return {"status": "error", "message": "Episode not found", "episode_id": episode_id}

    sync_service = PodcastSyncService(session, user_id)
    transcription_task = await sync_service.trigger_transcription(episode_id)
    transcription_task_id = transcription_task["task_id"] if transcription_task else None

    max_wait_time = 1800
    check_interval = 10
    waited = 0
    while waited < max_wait_time:
        trans_stmt = (
            select(TranscriptionTask)
            .where(TranscriptionTask.episode_id == episode_id)
            .order_by(TranscriptionTask.created_at.desc())
        )
        trans_result = await session.execute(trans_stmt)
        trans_task = trans_result.scalar_one_or_none()

        if trans_task is None:
            break
        if trans_task.status == "completed":
            await session.refresh(episode)
            break
        if trans_task.status in {"failed", "cancelled"}:
            break

        await asyncio.sleep(check_interval)
        waited += check_interval

    await session.refresh(episode)
    if not episode.ai_summary:
        service = PodcastService(session, user_id)
        await service._generate_summary(episode)
        await session.refresh(episode)

    return {
        "status": "success",
        "episode_id": episode_id,
        "transcription_task_id": transcription_task_id,
        "transcription_completed": episode.transcript_content is not None,
        "summary_generated": episode.ai_summary is not None,
        "processed_at": datetime.utcnow().isoformat(),
    }
