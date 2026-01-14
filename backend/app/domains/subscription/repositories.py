"""Subscription domain repositories."""

from datetime import datetime
from typing import List, Optional, Tuple

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.domains.subscription.models import (
    Subscription,
    SubscriptionCategory,
    SubscriptionCategoryMapping,
    SubscriptionItem,
    SubscriptionStatus,
    SubscriptionType,
)
from app.shared.schemas import SubscriptionCreate, SubscriptionUpdate


class SubscriptionRepository:
    """Repository for managing subscription data."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # Subscription operations
    async def get_user_subscriptions(
        self,
        user_id: int,
        page: int = 1,
        size: int = 20,
        status: Optional[str] = None,
        source_type: Optional[str] = None,
    ) -> Tuple[List[Subscription], int]:
        """Get user's subscriptions with pagination and filters."""
        skip = (page - 1) * size

        # Build base query
        base_query = select(Subscription).where(Subscription.user_id == user_id)
        if status:
            base_query = base_query.where(Subscription.status == status)
        if source_type:
            base_query = base_query.where(Subscription.source_type == source_type)

        # Get total count
        count_query = select(func.count()).select_from(base_query.subquery())
        total = await self.db.scalar(count_query) or 0

        # Get items with categories
        query = (
            base_query.options(selectinload(Subscription.categories))
            .offset(skip)
            .limit(size)
            .order_by(Subscription.updated_at.desc())
        )
        result = await self.db.execute(query)
        items = result.scalars().all()

        return list(items), total

    async def get_subscription_by_id(
        self, user_id: int, sub_id: int
    ) -> Optional[Subscription]:
        """Get subscription by ID with user ownership verification."""
        query = (
            select(Subscription)
            .options(selectinload(Subscription.categories))
            .where(Subscription.id == sub_id, Subscription.user_id == user_id)
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_subscription_by_url(
        self, user_id: int, url: str
    ) -> Optional[Subscription]:
        """Get subscription by source URL."""
        query = select(Subscription).where(
            Subscription.user_id == user_id, Subscription.source_url == url
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_subscription_by_title(
        self, user_id: int, title: str
    ) -> Optional[Subscription]:
        """
        Get subscription by title (case-insensitive).

        按标题查找订阅（不区分大小写）。
        """
        query = select(Subscription).where(
            Subscription.user_id == user_id,
            func.lower(Subscription.title) == func.lower(title),
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_duplicate_subscription(
        self, user_id: int, url: str, title: str
    ) -> Optional[Subscription]:
        """
        Check for duplicate subscription by URL or title.

        Returns the first matching subscription found.

        检查重复订阅（通过URL或标题）。
        返回第一个匹配的订阅。
        """
        # First check by URL (exact match)
        query_url = select(Subscription).where(
            Subscription.user_id == user_id, Subscription.source_url == url
        )

        result = await self.db.execute(query_url)
        sub = result.scalar_one_or_none()

        if sub:
            return sub

        # Then check by title (case-insensitive)
        query_title = select(Subscription).where(
            Subscription.user_id == user_id,
            func.lower(Subscription.title) == func.lower(title),
        )

        result = await self.db.execute(query_title)
        return result.scalar_one_or_none()

    async def create_subscription(
        self, user_id: int, sub_data: SubscriptionCreate
    ) -> Subscription:
        """Create a new subscription."""
        # Get global RSS frequency settings from SystemSettings
        from app.admin.models import SystemSettings
        from app.domains.subscription.models import UpdateFrequency

        # Default values
        update_frequency = UpdateFrequency.HOURLY.value
        update_time = None
        update_day_of_week = None

        # Try to get global settings from SystemSettings
        settings_result = await self.db.execute(
            select(SystemSettings).where(SystemSettings.key == "rss.frequency_settings")
        )
        setting = settings_result.scalar_one_or_none()
        if setting and setting.value:
            update_frequency = setting.value.get(
                "update_frequency", UpdateFrequency.HOURLY.value
            )
            update_time = setting.value.get("update_time")
            update_day_of_week = setting.value.get("update_day_of_week")

        sub = Subscription(
            user_id=user_id,
            title=sub_data.title,
            description=sub_data.description,
            source_type=sub_data.source_type,
            source_url=sub_data.source_url,
            config=sub_data.config,
            fetch_interval=sub_data.fetch_interval,
            status=SubscriptionStatus.ACTIVE,
            # Use global frequency settings
            update_frequency=update_frequency,
            update_time=update_time,
            update_day_of_week=update_day_of_week,
        )
        self.db.add(sub)
        await self.db.commit()
        await self.db.refresh(sub)
        return sub

    async def update_subscription(
        self, user_id: int, sub_id: int, sub_data: SubscriptionUpdate
    ) -> Optional[Subscription]:
        """Update subscription."""
        sub = await self.get_subscription_by_id(user_id, sub_id)
        if not sub:
            return None

        update_data = sub_data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            if key == "is_active":
                sub.status = (
                    SubscriptionStatus.INACTIVE
                    if not value
                    else SubscriptionStatus.ACTIVE
                )
            else:
                setattr(sub, key, value)

        await self.db.commit()
        await self.db.refresh(sub)
        return sub

    async def delete_subscription(self, user_id: int, sub_id: int) -> bool:
        """Delete subscription."""
        sub = await self.get_subscription_by_id(user_id, sub_id)
        if not sub:
            return False

        await self.db.delete(sub)
        await self.db.commit()
        return True

    async def update_fetch_status(
        self,
        sub_id: int,
        status: str = SubscriptionStatus.ACTIVE,
        error_message: Optional[str] = None,
    ) -> Optional[Subscription]:
        """Update subscription fetch status."""
        query = select(Subscription).where(Subscription.id == sub_id)
        result = await self.db.execute(query)
        sub = result.scalar_one_or_none()

        if not sub:
            return None

        sub.status = status
        sub.error_message = error_message
        sub.last_fetched_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(sub)
        return sub

    # Subscription Item operations
    async def get_subscription_items(
        self,
        subscription_id: int,
        user_id: int,
        page: int = 1,
        size: int = 20,
        unread_only: bool = False,
        bookmarked_only: bool = False,
    ) -> Tuple[List[SubscriptionItem], int]:
        """Get items from a subscription."""
        skip = (page - 1) * size

        # First verify subscription ownership
        sub = await self.get_subscription_by_id(user_id, subscription_id)
        if not sub:
            return [], 0

        # Build query
        base_query = select(SubscriptionItem).where(
            SubscriptionItem.subscription_id == subscription_id
        )

        if unread_only:
            base_query = base_query.where(SubscriptionItem.read_at.is_(None))
        if bookmarked_only:
            base_query = base_query.where(SubscriptionItem.bookmarked == True)

        # Get total count
        count_query = select(func.count()).select_from(base_query.subquery())
        total = await self.db.scalar(count_query) or 0

        # Get items
        query = (
            base_query.offset(skip)
            .limit(size)
            .order_by(SubscriptionItem.published_at.desc())
        )
        result = await self.db.execute(query)
        items = result.scalars().all()

        return list(items), total

    async def get_all_user_items(
        self,
        user_id: int,
        page: int = 1,
        size: int = 50,
        unread_only: bool = False,
        bookmarked_only: bool = False,
    ) -> Tuple[List[SubscriptionItem], int]:
        """Get all items from all user's subscriptions."""
        skip = (page - 1) * size

        # Get user's subscription IDs
        sub_query = select(Subscription.id).where(Subscription.user_id == user_id)
        sub_result = await self.db.execute(sub_query)
        sub_ids = [row[0] for row in sub_result.fetchall()]

        if not sub_ids:
            return [], 0

        # Build query
        base_query = select(SubscriptionItem).where(
            SubscriptionItem.subscription_id.in_(sub_ids)
        )

        if unread_only:
            base_query = base_query.where(SubscriptionItem.read_at.is_(None))
        if bookmarked_only:
            base_query = base_query.where(SubscriptionItem.bookmarked == True)

        # Get total count
        count_query = select(func.count()).select_from(base_query.subquery())
        total = await self.db.scalar(count_query) or 0

        # Get items
        query = (
            base_query.offset(skip)
            .limit(size)
            .order_by(SubscriptionItem.published_at.desc())
        )
        result = await self.db.execute(query)
        items = result.scalars().all()

        return list(items), total

    async def get_item_by_id(
        self, item_id: int, user_id: int
    ) -> Optional[SubscriptionItem]:
        """Get item by ID with user ownership verification."""
        query = (
            select(SubscriptionItem)
            .join(Subscription)
            .where(SubscriptionItem.id == item_id, Subscription.user_id == user_id)
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def create_or_update_item(
        self,
        subscription_id: int,
        external_id: str,
        title: str,
        content: Optional[str] = None,
        summary: Optional[str] = None,
        author: Optional[str] = None,
        source_url: Optional[str] = None,
        image_url: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[dict] = None,
        published_at: Optional[datetime] = None,
    ) -> SubscriptionItem:
        """Create or update a subscription item (upsert by external_id)."""
        # Check if item exists
        query = select(SubscriptionItem).where(
            SubscriptionItem.subscription_id == subscription_id,
            SubscriptionItem.external_id == external_id,
        )
        result = await self.db.execute(query)
        item = result.scalar_one_or_none()

        if item:
            # Update existing item
            item.title = title
            item.content = content
            item.summary = summary
            item.author = author
            item.source_url = source_url
            item.image_url = image_url
            item.tags = tags or []
            item.metadata_json = metadata or {}
            item.published_at = published_at
        else:
            # Create new item
            item = SubscriptionItem(
                subscription_id=subscription_id,
                external_id=external_id,
                title=title,
                content=content,
                summary=summary,
                author=author,
                source_url=source_url,
                image_url=image_url,
                tags=tags or [],
                metadata_json=metadata or {},
                published_at=published_at,
            )
            self.db.add(item)

        await self.db.commit()
        await self.db.refresh(item)
        return item

    async def mark_item_as_read(
        self, item_id: int, user_id: int
    ) -> Optional[SubscriptionItem]:
        """Mark an item as read."""
        item = await self.get_item_by_id(item_id, user_id)
        if not item:
            return None

        if not item.read_at:
            item.read_at = datetime.utcnow()
            await self.db.commit()
            await self.db.refresh(item)

        return item

    async def mark_item_as_unread(
        self, item_id: int, user_id: int
    ) -> Optional[SubscriptionItem]:
        """Mark an item as unread."""
        item = await self.get_item_by_id(item_id, user_id)
        if not item:
            return None

        item.read_at = None
        await self.db.commit()
        await self.db.refresh(item)
        return item

    async def toggle_bookmark(
        self, item_id: int, user_id: int
    ) -> Optional[SubscriptionItem]:
        """Toggle item bookmark status."""
        item = await self.get_item_by_id(item_id, user_id)
        if not item:
            return None

        item.bookmarked = not item.bookmarked
        await self.db.commit()
        await self.db.refresh(item)
        return item

    async def delete_item(self, item_id: int, user_id: int) -> bool:
        """Delete an item."""
        item = await self.get_item_by_id(item_id, user_id)
        if not item:
            return False

        await self.db.delete(item)
        await self.db.commit()
        return True

    # Category operations
    async def get_user_categories(self, user_id: int) -> List[SubscriptionCategory]:
        """Get all user's categories."""
        query = (
            select(SubscriptionCategory)
            .where(SubscriptionCategory.user_id == user_id)
            .order_by(SubscriptionCategory.name)
        )
        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_category_by_id(
        self, category_id: int, user_id: int
    ) -> Optional[SubscriptionCategory]:
        """Get category by ID."""
        query = select(SubscriptionCategory).where(
            SubscriptionCategory.id == category_id,
            SubscriptionCategory.user_id == user_id,
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def create_category(
        self,
        user_id: int,
        name: str,
        description: Optional[str] = None,
        color: Optional[str] = None,
    ) -> SubscriptionCategory:
        """Create a new category."""
        category = SubscriptionCategory(
            user_id=user_id, name=name, description=description, color=color
        )
        self.db.add(category)
        await self.db.commit()
        await self.db.refresh(category)
        return category

    async def update_category(
        self, category_id: int, user_id: int, **kwargs
    ) -> Optional[SubscriptionCategory]:
        """Update category."""
        category = await self.get_category_by_id(category_id, user_id)
        if not category:
            return None

        for key, value in kwargs.items():
            if hasattr(category, key) and value is not None:
                setattr(category, key, value)

        await self.db.commit()
        await self.db.refresh(category)
        return category

    async def delete_category(self, category_id: int, user_id: int) -> bool:
        """Delete category."""
        category = await self.get_category_by_id(category_id, user_id)
        if not category:
            return False

        await self.db.delete(category)
        await self.db.commit()
        return True

    # Subscription-Category mapping
    async def add_subscription_to_category(
        self, subscription_id: int, category_id: int
    ) -> bool:
        """Add subscription to category."""
        # Check if mapping already exists
        query = select(SubscriptionCategoryMapping).where(
            SubscriptionCategoryMapping.subscription_id == subscription_id,
            SubscriptionCategoryMapping.category_id == category_id,
        )
        result = await self.db.execute(query)
        existing = result.scalar_one_or_none()

        if existing:
            return True  # Already mapped

        mapping = SubscriptionCategoryMapping(
            subscription_id=subscription_id, category_id=category_id
        )
        self.db.add(mapping)
        await self.db.commit()
        return True

    async def remove_subscription_from_category(
        self, subscription_id: int, category_id: int
    ) -> bool:
        """Remove subscription from category."""
        query = select(SubscriptionCategoryMapping).where(
            SubscriptionCategoryMapping.subscription_id == subscription_id,
            SubscriptionCategoryMapping.category_id == category_id,
        )
        result = await self.db.execute(query)
        mapping = result.scalar_one_or_none()

        if not mapping:
            return False

        await self.db.delete(mapping)
        await self.db.commit()
        return True

    async def get_unread_count(self, user_id: int) -> int:
        """Get total unread items count for user."""
        # Get user's subscription IDs
        sub_query = select(Subscription.id).where(Subscription.user_id == user_id)
        sub_result = await self.db.execute(sub_query)
        sub_ids = [row[0] for row in sub_result.fetchall()]

        if not sub_ids:
            return 0

        # Count unread items
        count_query = select(func.count()).select_from(
            select(SubscriptionItem)
            .where(
                SubscriptionItem.subscription_id.in_(sub_ids),
                SubscriptionItem.read_at.is_(None),
            )
            .subquery()
        )
        return await self.db.scalar(count_query) or 0
