"""Handlers for summary generation tasks."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import and_, or_, select

from app.domains.podcast.models import PodcastEpisode, TranscriptionTask
from app.domains.podcast.repositories import PodcastRepository
from app.domains.podcast.services import PodcastService
from app.domains.subscription.models import UserSubscription


logger = logging.getLogger(__name__)


async def generate_pending_summaries_handler(session) -> dict:
    """Generate summaries for pending episodes."""
    repo = PodcastRepository(session)
    pending_episodes = await repo.get_unsummarized_episodes()

    max_episodes_per_run = 10
    episodes_to_process = pending_episodes[:max_episodes_per_run]
    if len(pending_episodes) > max_episodes_per_run:
        logger.info(
            "Found %s pending summaries, processing %s this run",
            len(pending_episodes),
            max_episodes_per_run,
        )

    processed_count = 0
    failed_count = 0

    for episode in episodes_to_process:
        try:
            trans_stmt = select(TranscriptionTask).where(
                and_(
                    TranscriptionTask.episode_id == episode.id,
                    or_(
                        TranscriptionTask.status == "pending",
                        TranscriptionTask.status == "in_progress",
                    ),
                )
            )
            trans_result = await session.execute(trans_stmt)
            running_task = trans_result.scalar_one_or_none()
            if running_task:
                continue

            user_sub_stmt = (
                select(UserSubscription)
                .where(
                    UserSubscription.subscription_id == episode.subscription_id,
                    UserSubscription.is_archived == False,  # noqa: E712
                )
                .limit(1)
            )
            user_sub_result = await session.execute(user_sub_stmt)
            user_sub = user_sub_result.scalar_one_or_none()
            user_id = user_sub.user_id if user_sub else 1

            service = PodcastService(session, user_id)
            await service._generate_summary(episode)
            processed_count += 1
        except Exception as exc:
            failed_count += 1
            logger.exception("Failed to generate summary for episode %s", episode.id)
            await repo.mark_summary_failed(episode.id, str(exc))

    return {
        "status": "success",
        "processed": processed_count,
        "failed": failed_count,
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }


async def generate_summary_for_episode_handler(
    session,
    episode_id: int,
    user_id: int,
) -> dict:
    """Generate summary for a single episode."""
    episode_stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode_id)
    episode_result = await session.execute(episode_stmt)
    episode = episode_result.scalar_one_or_none()
    if episode is None:
        return {"status": "error", "message": "Episode not found", "episode_id": episode_id}

    service = PodcastService(session, user_id)
    summary = await service._generate_summary_task(episode)

    return {
        "status": "success",
        "episode_id": episode_id,
        "summary": summary,
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }
