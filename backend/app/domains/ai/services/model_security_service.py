"""Security and credential helpers for AI model services."""

from __future__ import annotations

import logging

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import ValidationError
from app.domains.ai.models import AIModelConfig, ModelType
from app.domains.ai.schemas import PresetModelConfig


logger = logging.getLogger(__name__)


class AIModelSecurityService:
    """Handle API-key encryption, decryption, and default-model state."""

    def __init__(self, db: AsyncSession):
        self.db = db

    def encrypt_api_key(self, api_key: str) -> str:
        """Encrypt a user-provided API key for storage."""
        from app.core.security import encrypt_data

        return encrypt_data(api_key)

    async def get_decrypted_api_key(self, model: AIModelConfig) -> str:
        """Resolve the decrypted API key for runtime use."""
        if not model.api_key_encrypted:
            return model.api_key

        if model.is_system:
            return self.get_preset_api_key_from_env(model.name)

        from app.core.security import decrypt_data

        try:
            decrypted = decrypt_data(model.api_key)
            logger.debug("API key decrypted for model %s", model.name)
            return decrypted
        except Exception as exc:
            logger.error("Failed to decrypt API key for model %s: %s", model.name, exc)
            raise ValidationError(
                f"Failed to decrypt API key for model {model.name}"
            ) from exc

    async def clear_default_models(self, model_type: ModelType) -> None:
        """Unset existing default models for a model type."""
        stmt = (
            update(AIModelConfig)
            .where(AIModelConfig.model_type == model_type, AIModelConfig.is_default)
            .values(is_default=False)
        )
        await self.db.execute(stmt)
        await self.db.commit()

    def get_preset_api_key(self, preset: PresetModelConfig) -> str | None:
        """Resolve a preset-model API key from environment settings."""
        if preset.provider == "openai":
            return getattr(settings, "OPENAI_API_KEY", None)
        if preset.provider == "siliconflow":
            return getattr(settings, "TRANSCRIPTION_API_KEY", None)
        return None

    def get_preset_api_key_from_env(self, model_name: str) -> str | None:
        """Resolve a preset-model API key by well-known model name."""
        if model_name in ["whisper-1", "gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"]:
            return getattr(settings, "OPENAI_API_KEY", None)
        if model_name == "sensevoice-small":
            return getattr(settings, "TRANSCRIPTION_API_KEY", None)
        return None