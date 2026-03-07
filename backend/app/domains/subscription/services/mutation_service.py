"""Mutation-oriented subscription workflows."""

from __future__ import annotations

from typing import Any

from app.shared.schemas import SubscriptionCreate, SubscriptionUpdate

from .common import SubscriptionServiceSupport
from .query_service import SubscriptionQueryService


class SubscriptionMutationService:
    """Handle subscription creation, updates, and destructive actions."""

    def __init__(
        self,
        support: SubscriptionServiceSupport,
        query_service: SubscriptionQueryService,
    ):
        self.support = support
        self.user_id = support.user_id
        self.repo = support.repo
        self.query_service = query_service

    async def create_subscription(self, sub_data: SubscriptionCreate):
        status, sub, _ = await self.support.subscribe_or_attach(
            sub_data,
            raise_on_active_duplicate=True,
        )
        if status == "skipped":
            raise ValueError(f"Already subscribed to: {sub.title}")
        return sub

    async def create_subscriptions_batch(
        self,
        subscriptions_data: list[SubscriptionCreate],
    ) -> list[dict[str, Any]]:
        results = []
        for sub_data in subscriptions_data:
            try:
                status, sub, message = await self.support.subscribe_or_attach(sub_data)
                results.append(
                    {
                        "source_url": sub_data.source_url,
                        "title": sub_data.title,
                        "status": status,
                        "id": sub.id,
                        "message": message,
                    }
                )
            except ValueError as exc:
                results.append(
                    {
                        "source_url": sub_data.source_url,
                        "title": sub_data.title,
                        "status": "skipped",
                        "message": str(exc),
                    }
                )
            except Exception as exc:
                results.append(
                    {
                        "source_url": sub_data.source_url,
                        "title": sub_data.title,
                        "status": "error",
                        "message": str(exc),
                    }
                )
        return results

    async def update_subscription(self, sub_id: int, sub_data: SubscriptionUpdate):
        sub = await self.repo.update_subscription(self.user_id, sub_id, sub_data)
        if not sub:
            return None
        return await self.query_service.get_subscription(sub_id)

    async def delete_subscription(self, sub_id: int) -> bool:
        return await self.repo.delete_subscription(self.user_id, sub_id)

    async def mark_item_as_read(self, item_id: int) -> dict[str, Any] | None:
        item = await self.repo.mark_item_as_read(item_id, self.user_id)
        if not item:
            return None
        return {"id": item.id, "read_at": item.read_at.isoformat() if item.read_at else None}

    async def mark_item_as_unread(self, item_id: int) -> dict[str, Any] | None:
        item = await self.repo.mark_item_as_unread(item_id, self.user_id)
        if not item:
            return None
        return {"id": item.id, "read_at": None}

    async def toggle_bookmark(self, item_id: int) -> dict[str, Any] | None:
        item = await self.repo.toggle_bookmark(item_id, self.user_id)
        if not item:
            return None
        return {"id": item.id, "bookmarked": item.bookmarked}

    async def delete_item(self, item_id: int) -> bool:
        return await self.repo.delete_item(item_id, self.user_id)