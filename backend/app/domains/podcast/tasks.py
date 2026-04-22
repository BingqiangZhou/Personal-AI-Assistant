import logging
from uuid import UUID

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

    Args:
        podcast_id: If provided, sync only this podcast. Otherwise sync all tracked.
    """
    import asyncio
    from app.domains.podcast.service import EpisodeService, PodcastService

    async def _run() -> dict:
        async with async_session_factory() as session:
            try:
                if podcast_id:
                    # Sync episodes for a specific podcast
                    service = PodcastService(session)
                    result = await service.sync_rankings()
                    await session.commit()
                    return result
                else:
                    # Sync all tracked podcasts
                    service = EpisodeService(session)
                    result = await service.sync_episodes()
                    await session.commit()
                    return result
            except Exception:
                await session.rollback()
                raise

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error(f"Episode sync failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@celery_app.task(name="app.domains.podcast.tasks.sync_podcast_episodes_task", bind=True, max_retries=3)
def sync_podcast_episodes_task(self, podcast_id: str) -> dict:
    """Celery task: sync episodes for a specific podcast by ID."""
    import asyncio
    from uuid import UUID

    from app.domains.podcast.repository import PodcastRepository
    from app.domains.podcast.service import EpisodeService

    async def _run() -> dict:
        async with async_session_factory() as session:
            try:
                # First ensure podcast is synced
                podcast_repo = PodcastRepository(session)
                podcast = await podcast_repo.get(UUID(podcast_id))
                if podcast is None:
                    return {"error": "Podcast not found"}

                service = EpisodeService(session)
                result = await service.sync_episodes()
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
