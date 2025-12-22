"""Subscription domain services."""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import feedparser
import httpx

from app.domains.subscription.repositories import SubscriptionRepository
from app.domains.subscription.models import Subscription, SubscriptionItem, SubscriptionStatus
from app.shared.schemas import (
    SubscriptionCreate,
    SubscriptionUpdate,
    SubscriptionResponse,
    PaginatedResponse
)

logger = logging.getLogger(__name__)


class SubscriptionService:
    """Service for orchestrating subscription logic."""

    def __init__(self, db: AsyncSession, user_id: int):
        self.db = db
        self.user_id = user_id
        self.repo = SubscriptionRepository(db)

    # Subscription operations
    async def list_subscriptions(
        self,
        page: int = 1,
        size: int = 20,
        status: Optional[str] = None,
        source_type: Optional[str] = None
    ) -> PaginatedResponse:
        """List user's subscriptions."""
        items, total = await self.repo.get_user_subscriptions(
            self.user_id, page, size, status, source_type
        )

        response_items = []
        for sub in items:
            # Get item count for this subscription
            count_query = select(func.count()).select_from(
                select(SubscriptionItem).where(
                    SubscriptionItem.subscription_id == sub.id
                ).subquery()
            )
            item_count = await self.db.scalar(count_query) or 0

            response_items.append(SubscriptionResponse(
                id=sub.id,
                user_id=sub.user_id,
                title=sub.title,
                description=sub.description,
                source_type=sub.source_type,
                source_url=sub.source_url,
                config=sub.config,
                status=sub.status,
                last_fetched_at=sub.last_fetched_at,
                error_message=sub.error_message,
                fetch_interval=sub.fetch_interval,
                item_count=item_count,
                created_at=sub.created_at,
                updated_at=sub.updated_at
            ))

        return PaginatedResponse.create(
            items=response_items,
            total=total,
            page=page,
            size=size
        )

    async def create_subscription(
        self,
        sub_data: SubscriptionCreate
    ) -> SubscriptionResponse:
        """Create a new subscription."""
        # Check if URL already exists
        existing = await self.repo.get_subscription_by_url(self.user_id, sub_data.source_url)
        if existing:
            raise ValueError("Subscription with this URL already exists")

        sub = await self.repo.create_subscription(self.user_id, sub_data)
        return SubscriptionResponse(
            id=sub.id,
            user_id=sub.user_id,
            title=sub.title,
            description=sub.description,
            source_type=sub.source_type,
            source_url=sub.source_url,
            config=sub.config,
            status=sub.status,
            last_fetched_at=sub.last_fetched_at,
            error_message=sub.error_message,
            fetch_interval=sub.fetch_interval,
            item_count=0,
            created_at=sub.created_at,
            updated_at=sub.updated_at
        )

    async def get_subscription(
        self,
        sub_id: int
    ) -> Optional[SubscriptionResponse]:
        """Get subscription details."""
        sub = await self.repo.get_subscription_by_id(self.user_id, sub_id)
        if not sub:
            return None

        # Get item count
        from sqlalchemy import select, func
        from app.domains.subscription.models import SubscriptionItem
        count_query = select(func.count()).where(
            SubscriptionItem.subscription_id == sub_id
        )
        item_count = await self.db.scalar(count_query) or 0

        return SubscriptionResponse(
            id=sub.id,
            user_id=sub.user_id,
            title=sub.title,
            description=sub.description,
            source_type=sub.source_type,
            source_url=sub.source_url,
            config=sub.config,
            status=sub.status,
            last_fetched_at=sub.last_fetched_at,
            error_message=sub.error_message,
            fetch_interval=sub.fetch_interval,
            item_count=item_count,
            created_at=sub.created_at,
            updated_at=sub.updated_at
        )

    async def update_subscription(
        self,
        sub_id: int,
        sub_data: SubscriptionUpdate
    ) -> Optional[SubscriptionResponse]:
        """Update subscription."""
        sub = await self.repo.update_subscription(self.user_id, sub_id, sub_data)
        if not sub:
            return None

        return await self.get_subscription(sub_id)

    async def delete_subscription(
        self,
        sub_id: int
    ) -> bool:
        """Delete subscription."""
        return await self.repo.delete_subscription(self.user_id, sub_id)

    async def fetch_subscription(
        self,
        sub_id: int
    ) -> Dict[str, Any]:
        """Manually trigger subscription fetch (for RSS feeds)."""
        sub = await self.repo.get_subscription_by_id(self.user_id, sub_id)
        if not sub:
            raise ValueError("Subscription not found")

        if sub.source_type != "rss":
            raise ValueError("Only RSS subscriptions support manual fetch")

        # Fetch RSS feed
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(sub.source_url)
                response.raise_for_status()
                feed = feedparser.parse(response.content)

            # Process feed items
            new_items = 0
            updated_items = 0

            for entry in feed.entries[:50]:  # Limit to 50 items
                published_at = None
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    published_at = datetime(*entry.published_parsed[:6])
                elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                    published_at = datetime(*entry.updated_parsed[:6])

                # Create or update item
                item = await self.repo.create_or_update_item(
                    subscription_id=sub.id,
                    external_id=entry.get('id', entry.get('link', '')),
                    title=entry.get('title', 'Untitled'),
                    content=entry.get('content', [{}])[0].get('value') if hasattr(entry, 'content') else entry.get('description'),
                    summary=entry.get('summary'),
                    author=entry.get('author'),
                    source_url=entry.get('link'),
                    image_url=entry.get('image', {}).get('href') if hasattr(entry, 'image') else None,
                    tags=[tag.term for tag in entry.get('tags', [])] if hasattr(entry, 'tags') else [],
                    published_at=published_at
                )

                # Check if this was a new item (simplified check)
                if item.created_at == item.updated_at:
                    new_items += 1
                else:
                    updated_items += 1

            # Update subscription status
            await self.repo.update_fetch_status(sub.id, SubscriptionStatus.ACTIVE)

            return {
                "subscription_id": sub.id,
                "status": "success",
                "new_items": new_items,
                "updated_items": updated_items,
                "total_items": new_items + updated_items
            }

        except Exception as e:
            logger.error(f"Error fetching subscription {sub_id}: {e}")
            await self.repo.update_fetch_status(
                sub.id,
                SubscriptionStatus.ERROR,
                str(e)
            )
            raise

    async def fetch_all_subscriptions(
        self
    ) -> List[Dict[str, Any]]:
        """Fetch all active RSS subscriptions."""
        subs, _ = await self.repo.get_user_subscriptions(
            self.user_id,
            page=1,
            size=100,
            status=SubscriptionStatus.ACTIVE,
            source_type="rss"
        )

        results = []
        for sub in subs:
            try:
                result = await self.fetch_subscription(sub.id)
                results.append(result)
            except Exception as e:
                results.append({
                    "subscription_id": sub.id,
                    "status": "error",
                    "error": str(e)
                })

        return results

    # Subscription Item operations
    async def get_subscription_items(
        self,
        sub_id: int,
        page: int = 1,
        size: int = 20,
        unread_only: bool = False,
        bookmarked_only: bool = False
    ) -> PaginatedResponse:
        """Get items from a subscription."""
        items, total = await self.repo.get_subscription_items(
            sub_id, self.user_id, page, size, unread_only, bookmarked_only
        )

        response_items = [
            {
                "id": item.id,
                "subscription_id": item.subscription_id,
                "external_id": item.external_id,
                "title": item.title,
                "content": item.content,
                "summary": item.summary,
                "author": item.author,
                "source_url": item.source_url,
                "image_url": item.image_url,
                "tags": item.tags,
                "metadata": item.metadata_json,
                "published_at": item.published_at.isoformat() if item.published_at else None,
                "read_at": item.read_at.isoformat() if item.read_at else None,
                "bookmarked": item.bookmarked,
                "created_at": item.created_at.isoformat()
            }
            for item in items
        ]

        return PaginatedResponse.create(
            items=response_items,
            total=total,
            page=page,
            size=size
        )

    async def get_all_items(
        self,
        page: int = 1,
        size: int = 50,
        unread_only: bool = False,
        bookmarked_only: bool = False
    ) -> PaginatedResponse:
        """Get all items from all subscriptions."""
        items, total = await self.repo.get_all_user_items(
            self.user_id, page, size, unread_only, bookmarked_only
        )

        response_items = [
            {
                "id": item.id,
                "subscription_id": item.subscription_id,
                "external_id": item.external_id,
                "title": item.title,
                "content": item.content,
                "summary": item.summary,
                "author": item.author,
                "source_url": item.source_url,
                "image_url": item.image_url,
                "tags": item.tags,
                "metadata": item.metadata_json,
                "published_at": item.published_at.isoformat() if item.published_at else None,
                "read_at": item.read_at.isoformat() if item.read_at else None,
                "bookmarked": item.bookmarked,
                "created_at": item.created_at.isoformat()
            }
            for item in items
        ]

        return PaginatedResponse.create(
            items=response_items,
            total=total,
            page=page,
            size=size
        )

    async def mark_item_as_read(
        self,
        item_id: int
    ) -> Optional[Dict[str, Any]]:
        """Mark an item as read."""
        item = await self.repo.mark_item_as_read(item_id, self.user_id)
        if not item:
            return None

        return {
            "id": item.id,
            "read_at": item.read_at.isoformat() if item.read_at else None
        }

    async def mark_item_as_unread(
        self,
        item_id: int
    ) -> Optional[Dict[str, Any]]:
        """Mark an item as unread."""
        item = await self.repo.mark_item_as_unread(item_id, self.user_id)
        if not item:
            return None

        return {
            "id": item.id,
            "read_at": None
        }

    async def toggle_bookmark(
        self,
        item_id: int
    ) -> Optional[Dict[str, Any]]:
        """Toggle item bookmark status."""
        item = await self.repo.toggle_bookmark(item_id, self.user_id)
        if not item:
            return None

        return {
            "id": item.id,
            "bookmarked": item.bookmarked
        }

    async def delete_item(
        self,
        item_id: int
    ) -> bool:
        """Delete an item."""
        return await self.repo.delete_item(item_id, self.user_id)

    async def get_unread_count(
        self
    ) -> int:
        """Get total unread items count."""
        return await self.repo.get_unread_count(self.user_id)

    # Category operations
    async def list_categories(
        self
    ) -> List[Dict[str, Any]]:
        """Get all user's categories."""
        categories = await self.repo.get_user_categories(self.user_id)

        return [
            {
                "id": cat.id,
                "name": cat.name,
                "description": cat.description,
                "color": cat.color,
                "created_at": cat.created_at.isoformat()
            }
            for cat in categories
        ]

    async def create_category(
        self,
        name: str,
        description: Optional[str] = None,
        color: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new category."""
        cat = await self.repo.create_category(self.user_id, name, description, color)

        return {
            "id": cat.id,
            "name": cat.name,
            "description": cat.description,
            "color": cat.color,
            "created_at": cat.created_at.isoformat()
        }

    async def update_category(
        self,
        category_id: int,
        **kwargs
    ) -> Optional[Dict[str, Any]]:
        """Update category."""
        cat = await self.repo.update_category(category_id, self.user_id, **kwargs)
        if not cat:
            return None

        return {
            "id": cat.id,
            "name": cat.name,
            "description": cat.description,
            "color": cat.color
        }

    async def delete_category(
        self,
        category_id: int
    ) -> bool:
        """Delete category."""
        return await self.repo.delete_category(category_id, self.user_id)

    async def add_subscription_to_category(
        self,
        subscription_id: int,
        category_id: int
    ) -> bool:
        """Add subscription to category."""
        # Verify ownership
        sub = await self.repo.get_subscription_by_id(self.user_id, subscription_id)
        cat = await self.repo.get_category_by_id(category_id, self.user_id)

        if not sub or not cat:
            return False

        return await self.repo.add_subscription_to_category(subscription_id, category_id)

    async def remove_subscription_from_category(
        self,
        subscription_id: int,
        category_id: int
    ) -> bool:
        """Remove subscription from category."""
        return await self.repo.remove_subscription_from_category(subscription_id, category_id)
