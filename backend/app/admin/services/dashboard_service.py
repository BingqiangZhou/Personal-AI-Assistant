"""Admin dashboard service."""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.ai.models import AIModelConfig
from app.domains.subscription.models import Subscription
from app.domains.user.models import User


class AdminDashboardService:
    """Build dashboard statistics payloads."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_dashboard_context(self) -> dict[str, int]:
        apikey_count = int(
            (await self.db.execute(select(func.count()).select_from(AIModelConfig)))
            .scalar()
            or 0,
        )
        subscription_count = int(
            (await self.db.execute(select(func.count()).select_from(Subscription)))
            .scalar()
            or 0,
        )
        user_count = int(
            (await self.db.execute(select(func.count()).select_from(User))).scalar()
            or 0,
        )
        return {
            "apikey_count": apikey_count,
            "subscription_count": subscription_count,
            "user_count": user_count,
        }
