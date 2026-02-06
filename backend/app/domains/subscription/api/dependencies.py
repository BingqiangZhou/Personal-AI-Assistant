"""Dependency providers for subscription API routes."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.dependencies import get_current_active_user
from app.domains.subscription.services import SubscriptionService
from app.domains.user.models import User


def get_subscription_service(
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_active_user),
) -> SubscriptionService:
    """Provide a request-scoped SubscriptionService."""
    return SubscriptionService(db, current_user.id)

