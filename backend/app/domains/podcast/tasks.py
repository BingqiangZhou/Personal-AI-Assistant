import asyncio
import logging
from uuid import UUID

from sqlalchemy import select

from app.core.celery_app import celery_app
from app.core.database import async_session_factory

logger = logging.getLogger(__name__)


@celery_app.task(name="app.domains.podcast.tasks.sync_rankings_task", bind=True, max_retries=3)
def sync_rankings_task(self) -> dict:
    """Celery task: sync podcast rankings from xyzrank.com API."""
    import asyncio
    from app.domains.podcast.service import PodcastService

    async def _run() -> dict:
        async with async_session_factory() as session:
            try:
                service = PodcastService(session)
                result = await service.sync_rankings()
                await session.commit()
                return result
            except Exception:
                await session.rollback()
                raise

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error(f"Ranking sync failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@celery_app.task(name="app.domains.podcast.tasks.sync_episodes_task", bind=True, max_retries=3)
def sync_episodes_task(self, podcast_id: str | None = None) -> dict:
    """Celery task: sync episodes from RSS feeds.

    After syncing, automatically dispatch transcription tasks for new episodes.

    Args:
        podcast_id: If provided, sync only this podcast via sync_podcast_episodes_task.
                     Otherwise sync all tracked.
    """
    if podcast_id:
        result = sync_podcast_episodes_task.delay(podcast_id)
        return {"task_id": result.id, "podcast_id": podcast_id}

    import asyncio
    from app.domains.podcast.service import EpisodeService

    async def _run() -> dict:
        async with async_session_factory() as session:
            try:
                service = EpisodeService(session)
                result = await service.sync_episodes()
                await session.commit()
                return result
            except Exception:
                await session.rollback()
                raise

    try:
        result = asyncio.run(_run())
    except Exception as exc:
        logger.error(f"Episode sync failed: {exc}")
        raise self.retry(exc=exc, countdown=60)

    # Dispatch transcription tasks for new episodes with priority
    new_episode_ids = result.get("new_episode_ids", [])

    # Fetch priorities for podcasts in a separate session
    if new_episode_ids:
        async def _get_priorities():
            async with async_session_factory() as session:
                from app.domains.podcast.models import Episode, Podcast
                stmt = (
                    select(Episode.id, Podcast.priority)
                    .join(Podcast, Episode.podcast_id == Podcast.id)
                    .where(Episode.id.in_([UUID(eid) for eid in new_episode_ids]))
                )
                res = await session.execute(stmt)
                return {str(row[0]): row[1] for row in res.all()}

        priorities = asyncio.run(_get_priorities())
    else:
        priorities = {}

    for episode_id in new_episode_ids:
        priority = priorities.get(episode_id, 0)
        celery_app.send_task(
            "app.domains.transcription.tasks.transcribe_episode_task",
            args=[episode_id],
            priority=priority,
        )
        logger.info(f"Dispatched transcription task for episode {episode_id} (priority={priority})")

    return result


@celery_app.task(name="app.domains.podcast.tasks.sync_podcast_episodes_task", bind=True, max_retries=3)
def sync_podcast_episodes_task(self, podcast_id: str) -> dict:
    """Celery task: sync episodes for a specific podcast by ID."""
    import asyncio
    from uuid import UUID

    from app.domains.podcast.service import EpisodeService

    async def _run() -> dict:
        async with async_session_factory() as session:
            try:
                service = EpisodeService(session)
                result = await service.sync_episodes(podcast_id=UUID(podcast_id))
                await session.commit()
                return result
            except Exception:
                await session.rollback()
                raise

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error(f"Podcast episode sync failed for {podcast_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)
