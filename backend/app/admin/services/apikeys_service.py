"""Admin service helpers for API key management pages."""

import logging

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_data
from app.domains.ai.models import AIModelConfig


logger = logging.getLogger(__name__)


class AdminApiKeysService:
    """Query and serialize admin API-key page data."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_page_context(
        self,
        *,
        model_type_filter: str | None,
        page: int,
        per_page: int,
    ) -> dict:
        query = select(AIModelConfig)
        if model_type_filter and model_type_filter in {
            "transcription",
            "text_generation",
        }:
            query = query.where(AIModelConfig.model_type == model_type_filter)

        count_query = select(func.count()).select_from(query.subquery())
        total_count_result = await self.db.execute(count_query)
        total_count = total_count_result.scalar() or 0
        total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1
        offset = (page - 1) * per_page

        result = await self.db.execute(
            query.order_by(AIModelConfig.priority.asc(), AIModelConfig.created_at.desc())
            .limit(per_page)
            .offset(offset)
        )
        apikeys = result.scalars().all()

        for config in apikeys:
            config.api_key = self._mask_api_key_for_display(config)

        return {
            "apikeys": apikeys,
            "model_type_filter": model_type_filter or "",
            "page": page,
            "per_page": per_page,
            "total_count": total_count,
            "total_pages": total_pages,
        }

    def _mask_api_key_for_display(self, config: AIModelConfig) -> str:
        raw_key = (config.api_key or "").strip()
        if not raw_key:
            logger.warning(
                "API key for config %s (%s) is empty or None",
                config.id,
                config.name,
            )
            return "****"

        if config.api_key_encrypted:
            try:
                raw_key = decrypt_data(raw_key)
            except Exception as exc:
                logger.warning(
                    "Failed to decrypt API key for config %s (%s): %s",
                    config.id,
                    config.name,
                    exc,
                )
                return "[密钥无法解密-请重新编辑]"

        if len(raw_key) <= 8:
            return "****"
        return f"{raw_key[:4]}****{raw_key[-4:]}"
