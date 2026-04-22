from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.domains.settings.models import AIModelConfig, AIProviderConfig
from app.shared.base import BaseRepository


class AIProviderRepository(BaseRepository[AIProviderConfig]):
    def __init__(self, session: AsyncSession):
        super().__init__(AIProviderConfig, session)

    async def get_active_providers(self) -> list[AIProviderConfig]:
        result = await self.session.execute(
            select(self.model).where(self.model.is_active == True)  # noqa: E712
        )
        return list(result.scalars().all())

    async def get_by_name(self, name: str) -> AIProviderConfig | None:
        result = await self.session.execute(
            select(self.model).where(self.model.name == name)
        )
        return result.scalars().first()

    async def get_with_models(self, provider_id: UUID) -> AIProviderConfig | None:
        result = await self.session.execute(
            select(self.model)
            .options(selectinload(self.model.models))
            .where(self.model.id == provider_id)
        )
        return result.scalars().first()


class AIModelRepository(BaseRepository[AIModelConfig]):
    def __init__(self, session: AsyncSession):
        super().__init__(AIModelConfig, session)

    async def get_by_provider(self, provider_id: UUID) -> list[AIModelConfig]:
        result = await self.session.execute(
            select(self.model).where(self.model.provider_id == provider_id)
        )
        return list(result.scalars().all())

    async def get_default_for_provider(self, provider_id: UUID) -> AIModelConfig | None:
        result = await self.session.execute(
            select(self.model).where(
                self.model.provider_id == provider_id,
                self.model.is_default == True,  # noqa: E712
            )
        )
        return result.scalars().first()

    async def get_first_for_provider(self, provider_id: UUID) -> AIModelConfig | None:
        result = await self.session.execute(
            select(self.model).where(self.model.provider_id == provider_id).limit(1)
        )
        return result.scalars().first()


class SettingsRepository:
    """Combined repository for settings domain."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.provider_repo = AIProviderRepository(session)
        self.model_repo = AIModelRepository(session)

    async def get_active_provider(self) -> AIProviderConfig | None:
        """Get the first active provider."""
        providers = await self.provider_repo.get_active_providers()
        return providers[0] if providers else None

    async def get_default_model(self, provider_id: UUID) -> AIModelConfig | None:
        """Get the default model for a provider, or the first one."""
        model = await self.model_repo.get_default_for_provider(provider_id)
        if model is None:
            model = await self.model_repo.get_first_for_provider(provider_id)
        return model
