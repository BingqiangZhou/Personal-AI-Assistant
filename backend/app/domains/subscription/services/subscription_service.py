"""Compatibility facade for split subscription services."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.subscription.repositories import SubscriptionRepository
from app.shared.schemas import SubscriptionCreate, SubscriptionUpdate

from .category_service import SubscriptionCategoryService
from .common import SubscriptionServiceSupport
from .export_service import SubscriptionExportService
from .fetch_service import SubscriptionFetchService
from .mutation_service import SubscriptionMutationService
from .query_service import SubscriptionQueryService


class SubscriptionService:
    """Thin compatibility facade preserving the historical subscription API."""

    def __init__(self, db: AsyncSession, user_id: int):
        self.db = db
        self.user_id = user_id
        self.repo = SubscriptionRepository(db)
        self.support = SubscriptionServiceSupport(db, user_id, self.repo)
        self.query_service = SubscriptionQueryService(self.support)
        self.mutation_service = SubscriptionMutationService(self.support, self.query_service)
        self.fetch_service = SubscriptionFetchService(self.support)
        self.category_service = SubscriptionCategoryService(self.support)
        self.export_service = SubscriptionExportService(self.support)

    async def list_subscriptions(self, page: int = 1, size: int = 20, status: str | None = None, source_type: str | None = None):
        return await self.query_service.list_subscriptions(page, size, status, source_type)

    async def create_subscription(self, sub_data: SubscriptionCreate):
        return await self.mutation_service.create_subscription(sub_data)

    async def create_subscriptions_batch(self, subscriptions_data: list[SubscriptionCreate]):
        return await self.mutation_service.create_subscriptions_batch(subscriptions_data)

    async def get_subscription(self, sub_id: int):
        return await self.query_service.get_subscription(sub_id)

    async def update_subscription(self, sub_id: int, sub_data: SubscriptionUpdate):
        return await self.mutation_service.update_subscription(sub_id, sub_data)

    async def delete_subscription(self, sub_id: int) -> bool:
        return await self.mutation_service.delete_subscription(sub_id)

    async def fetch_subscription(self, sub_id: int):
        return await self.fetch_service.fetch_subscription(sub_id)

    async def fetch_all_subscriptions(self):
        return await self.fetch_service.fetch_all_subscriptions()

    async def get_subscription_items(self, sub_id: int, page: int = 1, size: int = 20, unread_only: bool = False, bookmarked_only: bool = False):
        return await self.query_service.get_subscription_items(sub_id, page, size, unread_only, bookmarked_only)

    async def get_all_items(self, page: int = 1, size: int = 50, unread_only: bool = False, bookmarked_only: bool = False):
        return await self.query_service.get_all_items(page, size, unread_only, bookmarked_only)

    async def mark_item_as_read(self, item_id: int):
        return await self.mutation_service.mark_item_as_read(item_id)

    async def mark_item_as_unread(self, item_id: int):
        return await self.mutation_service.mark_item_as_unread(item_id)

    async def toggle_bookmark(self, item_id: int):
        return await self.mutation_service.toggle_bookmark(item_id)

    async def delete_item(self, item_id: int) -> bool:
        return await self.mutation_service.delete_item(item_id)

    async def get_unread_count(self) -> int:
        return await self.query_service.get_unread_count()

    async def list_categories(self):
        return await self.category_service.list_categories()

    async def create_category(self, name: str, description: str | None = None, color: str | None = None):
        return await self.category_service.create_category(name, description, color)

    async def update_category(self, category_id: int, **kwargs):
        return await self.category_service.update_category(category_id, **kwargs)

    async def delete_category(self, category_id: int) -> bool:
        return await self.category_service.delete_category(category_id)

    async def add_subscription_to_category(self, subscription_id: int, category_id: int) -> bool:
        return await self.category_service.add_subscription_to_category(subscription_id, category_id)

    async def remove_subscription_from_category(self, subscription_id: int, category_id: int) -> bool:
        return await self.category_service.remove_subscription_from_category(subscription_id, category_id)

    async def generate_opml_content(self, user_id: int | None = None, status_filter: str | None = None):
        return await self.export_service.generate_opml_content(user_id, status_filter)