"""Query-focused subscription repositories."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.domains.subscription.models import (
    Subscription,
    SubscriptionCategory,
    SubscriptionItem,
    UserSubscription,
)

from .common import SubscriptionRepositoryCommon


class SubscriptionQueryRepository(SubscriptionRepositoryCommon):
    """Read-oriented subscription queries."""

    async def get_user_subscriptions(
        self,
        user_id: int,
        page: int = 1,
        size: int = 20,
        status: str | None = None,
        source_type: str | None = None,
    ) -> tuple[list[Subscription], int, dict[int, int]]:
        skip = (page - 1) * size
        base_query = (
            select(Subscription)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(UserSubscription.user_id == user_id)
        )
        if status:
            base_query = base_query.where(Subscription.status == status)
        if source_type:
            base_query = base_query.where(Subscription.source_type == source_type)
        base_query = base_query.where(UserSubscription.is_archived.is_(False))

        item_count_subquery = (
            select(
                SubscriptionItem.subscription_id.label("subscription_id"),
                func.count(SubscriptionItem.id).label("item_count"),
            )
            .group_by(SubscriptionItem.subscription_id)
            .subquery()
        )
        query = (
            base_query.outerjoin(
                item_count_subquery,
                item_count_subquery.c.subscription_id == Subscription.id,
            )
            .options(selectinload(Subscription.categories))
            .add_columns(
                func.coalesce(item_count_subquery.c.item_count, 0),
                func.count(Subscription.id).over(),
            )
            .offset(skip)
            .limit(size)
            .order_by(Subscription.updated_at.desc())
        )
        result = await self.db.execute(query)
        rows = result.all()
        total = await self._resolve_window_total(
            rows,
            total_index=2,
            fallback_count_query=select(func.count()).select_from(base_query.subquery()),
        )
        items = [row[0] for row in rows]
        item_counts = {row[0].id: int(row[1]) for row in rows}
        return items, total, item_counts

    async def get_subscription_items(
        self,
        subscription_id: int,
        user_id: int,
        page: int = 1,
        size: int = 20,
        unread_only: bool = False,
        bookmarked_only: bool = False,
    ) -> tuple[list[SubscriptionItem], int]:
        skip = (page - 1) * size
        base_query = (
            select(SubscriptionItem)
            .join(
                UserSubscription,
                UserSubscription.subscription_id == SubscriptionItem.subscription_id,
            )
            .where(
                SubscriptionItem.subscription_id == subscription_id,
                UserSubscription.user_id == user_id,
                UserSubscription.is_archived.is_(False),
            )
        )
        if unread_only:
            base_query = base_query.where(SubscriptionItem.read_at.is_(None))
        if bookmarked_only:
            base_query = base_query.where(SubscriptionItem.bookmarked.is_(True))

        query = (
            base_query.add_columns(func.count(SubscriptionItem.id).over())
            .offset(skip)
            .limit(size)
            .order_by(SubscriptionItem.published_at.desc())
        )
        result = await self.db.execute(query)
        rows = result.all()
        total = await self._resolve_window_total(
            rows,
            total_index=1,
            fallback_count_query=select(func.count()).select_from(base_query.subquery()),
        )
        return [row[0] for row in rows], total

    async def get_all_user_items(
        self,
        user_id: int,
        page: int = 1,
        size: int = 50,
        unread_only: bool = False,
        bookmarked_only: bool = False,
    ) -> tuple[list[SubscriptionItem], int]:
        skip = (page - 1) * size
        base_query = (
            select(SubscriptionItem)
            .join(
                UserSubscription,
                UserSubscription.subscription_id == SubscriptionItem.subscription_id,
            )
            .where(
                UserSubscription.user_id == user_id,
                UserSubscription.is_archived.is_(False),
            )
        )
        if unread_only:
            base_query = base_query.where(SubscriptionItem.read_at.is_(None))
        if bookmarked_only:
            base_query = base_query.where(SubscriptionItem.bookmarked.is_(True))

        query = (
            base_query.add_columns(func.count(SubscriptionItem.id).over())
            .offset(skip)
            .limit(size)
            .order_by(SubscriptionItem.published_at.desc())
        )
        result = await self.db.execute(query)
        rows = result.all()
        total = await self._resolve_window_total(
            rows,
            total_index=1,
            fallback_count_query=select(func.count()).select_from(base_query.subquery()),
        )
        return [row[0] for row in rows], total

    async def get_user_categories(self, user_id: int) -> list[SubscriptionCategory]:
        query = (
            select(SubscriptionCategory)
            .where(SubscriptionCategory.user_id == user_id)
            .order_by(SubscriptionCategory.name)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())