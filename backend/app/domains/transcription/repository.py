from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.transcription.models import Transcript
from app.shared.base import BaseRepository


class TranscriptRepository(BaseRepository[Transcript]):
    def __init__(self, session: AsyncSession):
        super().__init__(Transcript, session)

    async def get_by_episode(self, episode_id: UUID) -> Transcript | None:
        result = await self.session.execute(
            select(self.model).where(self.model.episode_id == episode_id)
        )
        return result.scalars().first()

    async def get_or_create(self, episode_id: UUID) -> Transcript:
        existing = await self.get_by_episode(episode_id)
        if existing:
            return existing
        return await self.create({"episode_id": episode_id})
