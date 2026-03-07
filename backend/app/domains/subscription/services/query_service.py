"""Query-oriented subscription domain services."""

from __future__ import annotations

from sqlalchemy import func, select

from app.domains.subscription.models import SubscriptionItem

from .common import SubscriptionServiceSupport


class SubscriptionQueryService:
    """Read-side subscription, item, and unread-count workflows."""

    def __init__(self, support: SubscriptionServiceSupport):
        self.support = support
        self.db = support.db
        self.user_id = support.user_id
        self.repo = support.repo

    async def list_subscriptions(
        self,
        page: int = 1,
        size: int = 20,
        status: str | None = None,
        source_type: str | None = None,
    ) -> tuple:
        """Return (items, total, item_counts) for assembly at the API layer."""
        items, total, item_counts = await self.repo.get_user_subscriptions(
            self.user_id,
            page,
            size,
            status,
            source_type,
        )
        return items, total, item_counts

    async def get_subscription(self, sub_id: int):
        """Return (subscription, item_count) or None."""
        sub = await self.repo.get_subscription_by_id(self.user_id, sub_id)
        if not sub:
            return None

        count_query = select(func.count()).where(SubscriptionItem.subscription_id == sub_id)
        item_count = await self.db.scalar(count_query) or 0
        return sub, item_count

    async def get_subscription_items(
        self,
        sub_id: int,
        page: int = 1,
        size: int = 20,
        unread_only: bool = False,
        bookmarked_only: bool = False,
    ) -> tuple:
        """Return (items, total) for assembly at the API layer."""
        items, total = await self.repo.get_subscription_items(
            sub_id,
            self.user_id,
            page,
            size,
            unread_only,
            bookmarked_only,
        )
        return items, total

    async def get_all_items(
        self,
        page: int = 1,
        size: int = 50,
        unread_only: bool = False,
        bookmarked_only: bool = False,
    ) -> tuple:
        """Return (items, total) for assembly at the API layer."""
        items, total = await self.repo.get_all_user_items(
            self.user_id,
            page,
            size,
            unread_only,
            bookmarked_only,
        )
        return items, total

    async def get_unread_count(self) -> int:
        return await self.repo.get_unread_count(self.user_id)