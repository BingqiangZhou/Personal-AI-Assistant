"""Handlers for OPML-import episode parsing tasks."""

from __future__ import annotations

from app.domains.podcast.services.task_orchestration_service import (
    PodcastTaskOrchestrationService,
)


async def process_opml_subscription_episodes_handler(
    session,
    *,
    subscription_id: int,
    user_id: int,
    source_url: str,
) -> dict:
    """
    Parse and upsert episodes for one OPML subscription in background.

    Important status rule:
    - This handler must not mutate existing ``podcast_episodes.status``.
    - New rows are initialized to ``pending_summary`` by repository layer.
    """
    return await PodcastTaskOrchestrationService(
        session
    ).process_opml_subscription_episodes(
        subscription_id=subscription_id,
        user_id=user_id,
        source_url=source_url,
    )
