"""Dependency providers for AI model API routes."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.domains.ai.services import AIModelConfigService


def get_ai_model_config_service(
    db: AsyncSession = Depends(get_db_session),
) -> AIModelConfigService:
    """Provide a request-scoped AIModelConfigService."""
    return AIModelConfigService(db)

