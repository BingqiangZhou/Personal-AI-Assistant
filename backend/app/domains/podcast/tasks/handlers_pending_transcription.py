"""Handlers for periodic transcription backlog dispatch."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import and_, func, or_, select

from app.core.config import settings
from app.domains.podcast.models import PodcastEpisode, TranscriptionTask
from app.domains.podcast.transcription_manager import DatabaseBackedTranscriptionService
from app.domains.subscription.models import (
    Subscription,
    SubscriptionStatus,
    UserSubscription,
)


logger = logging.getLogger(__name__)

_DISPATCHED_ACTIONS = {"created", "redispatched_pending", "redispatched_failed_with_temp"}


def _eligible_episode_filters() -> list:
    return [
        Subscription.source_type == "podcast-rss",
        Subscription.status == SubscriptionStatus.ACTIVE.value,
        UserSubscription.is_archived.is_(False),
        PodcastEpisode.audio_url.is_not(None),
        PodcastEpisode.audio_url != "",
        or_(
            PodcastEpisode.transcript_content.is_(None),
            PodcastEpisode.transcript_content == "",
        ),
        or_(
            TranscriptionTask.id.is_(None),
            TranscriptionTask.status.in_(["failed", "cancelled"]),
        ),
    ]


async def _fetch_pending_episode_ids(session, batch_size: int) -> tuple[int, list[int]]:
    filters = _eligible_episode_filters()

    count_stmt = (
        select(func.count(func.distinct(PodcastEpisode.id)))
        .select_from(PodcastEpisode)
        .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
        .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
        .outerjoin(TranscriptionTask, TranscriptionTask.episode_id == PodcastEpisode.id)
        .where(and_(*filters))
    )
    total_candidates = int((await session.execute(count_stmt)).scalar() or 0)
    if total_candidates == 0:
        return 0, []

    id_stmt = (
        select(PodcastEpisode.id, PodcastEpisode.published_at)
        .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
        .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
        .outerjoin(TranscriptionTask, TranscriptionTask.episode_id == PodcastEpisode.id)
        .where(and_(*filters))
        .distinct()
        .order_by(PodcastEpisode.published_at.desc(), PodcastEpisode.id.desc())
        .limit(batch_size)
    )
    rows = await session.execute(id_stmt)
    return total_candidates, [row[0] for row in rows.all()]


async def process_pending_transcriptions_handler(session) -> dict:
    """Dispatch periodic backlog transcription tasks."""
    if not settings.TRANSCRIPTION_BACKLOG_ENABLED:
        return {
            "status": "skipped",
            "reason": "backlog_transcription_disabled",
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    batch_size = max(1, settings.TRANSCRIPTION_BACKLOG_BATCH_SIZE)
    total_candidates, episode_ids = await _fetch_pending_episode_ids(session, batch_size)

    if not episode_ids:
        return {
            "status": "success",
            "total_candidates": total_candidates,
            "checked": 0,
            "dispatched": 0,
            "skipped": 0,
            "failed": 0,
            "skipped_reasons": {},
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    transcription_service = DatabaseBackedTranscriptionService(session)
    dispatched_count = 0
    skipped_count = 0
    failed_count = 0
    skipped_reasons: dict[str, int] = {}

    for episode_id in episode_ids:
        try:
            result = await transcription_service.start_transcription(episode_id, force=False)
            action = result.get("action", "unknown")
            if action in _DISPATCHED_ACTIONS:
                dispatched_count += 1
                continue

            skipped_count += 1
            skipped_reasons[action] = skipped_reasons.get(action, 0) + 1
        except Exception:
            failed_count += 1
            logger.exception(
                "Failed to dispatch backlog transcription for episode %s",
                episode_id,
            )

    logger.info(
        "Backlog transcription run completed: total_candidates=%s checked=%s dispatched=%s skipped=%s failed=%s skipped_reasons=%s",
        total_candidates,
        len(episode_ids),
        dispatched_count,
        skipped_count,
        failed_count,
        skipped_reasons,
    )

    return {
        "status": "success",
        "total_candidates": total_candidates,
        "checked": len(episode_ids),
        "dispatched": dispatched_count,
        "skipped": skipped_count,
        "failed": failed_count,
        "skipped_reasons": skipped_reasons,
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }
