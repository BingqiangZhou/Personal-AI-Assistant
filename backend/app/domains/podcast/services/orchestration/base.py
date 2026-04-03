"""Shared utilities and base class for podcast task orchestrators."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import get_shared_redis
from app.domains.podcast.models import PodcastEpisode


class BaseOrchestrator:
    """Common infrastructure shared across all orchestrators."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.redis = get_shared_redis()

    async def lookup_episode(self, episode_id: int) -> PodcastEpisode | None:
        """Look up a single episode by ID."""
        stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
