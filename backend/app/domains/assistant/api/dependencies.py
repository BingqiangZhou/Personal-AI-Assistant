"""Dependency providers for assistant API routes."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.dependencies import get_current_active_user
from app.domains.assistant.services import AssistantService
from app.domains.user.models import User


def get_assistant_service(
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_active_user),
) -> AssistantService:
    """Provide a request-scoped AssistantService."""
    return AssistantService(db, current_user.id)

