"""Shared repository helpers for the subscription domain."""

from __future__ import annotations

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.domains.subscription.models import (
    Subscription,
    SubscriptionCategory,
    SubscriptionItem,
    UserSubscription,
)


class SubscriptionRepositoryCommon:
    """Provide common DB helpers shared by split subscription repositories."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def _resolve_window_total(
        self,
        rows: list,
        *,
        total_index: int,
        fallback_count_query,
    ) -> int:
        if rows:
            return int(rows[0][total_index] or 0)
        return int(await self.db.scalar(fallback_count_query) or 0)

    async def get_subscription_by_id(
        self,
        user_id: int,
        sub_id: int,
    ) -> Subscription | None:
        query = (
            select(Subscription)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .options(selectinload(Subscription.categories))
            .where(
                Subscription.id == sub_id,
                UserSubscription.user_id == user_id,
                UserSubscription.is_archived.is_(False),
            )
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_subscription_by_url(self, user_id: int, url: str) -> Subscription | None:
        query = select(Subscription).where(Subscription.source_url == url)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_subscription_by_title(self, user_id: int, title: str) -> Subscription | None:
        query = select(Subscription).where(
            func.lower(Subscription.title) == func.lower(title)
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_duplicate_subscription(
        self,
        user_id: int,
        url: str,
        title: str,
    ) -> Subscription | None:
        query_url = select(Subscription).where(Subscription.source_url == url)
        result = await self.db.execute(query_url)
        subscription = result.scalar_one_or_none()
        if subscription:
            return subscription

        query_title = select(Subscription).where(
            func.lower(Subscription.title) == func.lower(title)
        )
        result = await self.db.execute(query_title)
        return result.scalar_one_or_none()

    async def get_item_by_id(self, item_id: int, user_id: int) -> SubscriptionItem | None:
        query = (
            select(SubscriptionItem)
            .join(Subscription, SubscriptionItem.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                SubscriptionItem.id == item_id,
                UserSubscription.user_id == user_id,
                UserSubscription.is_archived.is_(False),
            )
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_category_by_id(
        self,
        category_id: int,
        user_id: int,
    ) -> SubscriptionCategory | None:
        query = select(SubscriptionCategory).where(
            SubscriptionCategory.id == category_id,
            SubscriptionCategory.user_id == user_id,
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_unread_count(self, user_id: int) -> int:
        count_query = (
            select(func.count(SubscriptionItem.id))
            .select_from(SubscriptionItem)
            .join(Subscription, SubscriptionItem.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    UserSubscription.user_id == user_id,
                    UserSubscription.is_archived.is_(False),
                    SubscriptionItem.read_at.is_(None),
                )
            )
        )
        return await self.db.scalar(count_query) or 0