"""Category-oriented subscription workflows."""

from __future__ import annotations

from .common import SubscriptionServiceSupport


class SubscriptionCategoryService:
    """Handle category CRUD and category-to-subscription mappings."""

    def __init__(self, support: SubscriptionServiceSupport):
        self.support = support
        self.user_id = support.user_id
        self.repo = support.repo

    async def list_categories(self) -> list:
        """Return raw ORM Category objects for assembly at the API layer."""
        return await self.repo.get_user_categories(self.user_id)

    async def create_category(
        self,
        name: str,
        description: str | None = None,
        color: str | None = None,
    ):
        """Return raw ORM Category for assembly at the API layer."""
        return await self.repo.create_category(self.user_id, name, description, color)

    async def update_category(self, category_id: int, **kwargs):
        """Return raw ORM Category (or None) for assembly at the API layer."""
        return await self.repo.update_category(category_id, self.user_id, **kwargs)

    async def delete_category(self, category_id: int) -> bool:
        return await self.repo.delete_category(category_id, self.user_id)

    async def add_subscription_to_category(
        self,
        subscription_id: int,
        category_id: int,
    ) -> bool:
        sub = await self.repo.get_subscription_by_id(self.user_id, subscription_id)
        category = await self.repo.get_category_by_id(category_id, self.user_id)
        if not sub or not category:
            return False
        return await self.repo.add_subscription_to_category(subscription_id, category_id)

    async def remove_subscription_from_category(
        self,
        subscription_id: int,
        category_id: int,
    ) -> bool:
        return await self.repo.remove_subscription_from_category(subscription_id, category_id)