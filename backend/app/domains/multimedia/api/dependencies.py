"""Dependency providers for multimedia API routes."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.dependencies import get_current_active_user
from app.domains.multimedia.services import MultimediaService
from app.domains.user.models import User


def get_multimedia_service(
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_active_user),
) -> MultimediaService:
    """Provide a request-scoped MultimediaService."""
    return MultimediaService(db, current_user.id)

