"""Mutation-focused subscription repositories."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select

from app.domains.subscription.models import (
    Subscription,
    SubscriptionCategory,
    SubscriptionCategoryMapping,
    SubscriptionItem,
    SubscriptionStatus,
    UserSubscription,
)
from app.shared.schemas import SubscriptionCreate, SubscriptionUpdate

from .common import SubscriptionRepositoryCommon


class SubscriptionMutationRepository(SubscriptionRepositoryCommon):
    """Write-oriented subscription mutations."""

    async def create_subscription(
        self,
        user_id: int,
        sub_data: SubscriptionCreate,
    ) -> Subscription:
        from app.admin.models import SystemSettings
        from app.domains.subscription.models import UpdateFrequency

        update_frequency = UpdateFrequency.HOURLY.value
        update_time = None
        update_day_of_week = None

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
            title=sub_data.title,
            description=sub_data.description,
            source_type=sub_data.source_type,
            source_url=sub_data.source_url,
            image_url=sub_data.image_url,
            config=sub_data.config,
            fetch_interval=sub_data.fetch_interval,
            status=SubscriptionStatus.ACTIVE,
        )
        self.db.add(sub)
        await self.db.flush()

        user_sub = UserSubscription(
            user_id=user_id,
            subscription_id=sub.id,
            update_frequency=update_frequency,
            update_time=update_time,
            update_day_of_week=update_day_of_week,
        )
        self.db.add(user_sub)

        await self.db.commit()
        await self.db.refresh(sub)
        return sub

    async def update_subscription(
        self,
        user_id: int,
        sub_id: int,
        sub_data: SubscriptionUpdate,
    ) -> Subscription | None:
        sub = await self.get_subscription_by_id(user_id, sub_id)
        if not sub:
            return None

        update_data = sub_data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            if key == "is_active":
                sub.status = SubscriptionStatus.INACTIVE if not value else SubscriptionStatus.ACTIVE
            else:
                setattr(sub, key, value)

        await self.db.commit()
        await self.db.refresh(sub)
        return sub

    async def delete_subscription(self, user_id: int, sub_id: int) -> bool:
        user_sub_query = select(UserSubscription).where(
            UserSubscription.user_id == user_id,
            UserSubscription.subscription_id == sub_id,
        )
        result = await self.db.execute(user_sub_query)
        user_sub = result.scalar_one_or_none()
        if not user_sub:
            return False

        await self.db.delete(user_sub)
        other_subs_query = select(func.count()).select_from(
            select(UserSubscription).where(UserSubscription.subscription_id == sub_id).subquery()
        )
        remaining_count = await self.db.scalar(other_subs_query) or 0
        if remaining_count == 0:
            sub_query = select(Subscription).where(Subscription.id == sub_id)
            sub_result = await self.db.execute(sub_query)
            sub = sub_result.scalar_one_or_none()
            if sub:
                await self.db.delete(sub)

        await self.db.commit()
        return True

    async def update_fetch_status(
        self,
        sub_id: int,
        status: str = SubscriptionStatus.ACTIVE,
        error_message: str | None = None,
        latest_published_at: datetime | None = None,
    ) -> Subscription | None:
        query = select(Subscription).where(Subscription.id == sub_id)
        result = await self.db.execute(query)
        sub = result.scalar_one_or_none()
        if not sub:
            return None

        sub.status = status
        sub.error_message = error_message
        sub.last_fetched_at = datetime.now(timezone.utc)
        if latest_published_at:
            sub.latest_item_published_at = latest_published_at

        await self.db.commit()
        await self.db.refresh(sub)
        return sub

    async def create_or_update_item(
        self,
        subscription_id: int,
        external_id: str,
        title: str,
        content: str | None = None,
        summary: str | None = None,
        author: str | None = None,
        source_url: str | None = None,
        image_url: str | None = None,
        tags: list[str] | None = None,
        metadata: dict | None = None,
        published_at: datetime | None = None,
    ) -> SubscriptionItem:
        query = select(SubscriptionItem).where(
            SubscriptionItem.subscription_id == subscription_id,
            SubscriptionItem.external_id == external_id,
        )
        result = await self.db.execute(query)
        item = result.scalar_one_or_none()
        if item:
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

    async def mark_item_as_read(self, item_id: int, user_id: int) -> SubscriptionItem | None:
        item = await self.get_item_by_id(item_id, user_id)
        if not item:
            return None
        if not item.read_at:
            item.read_at = datetime.now(timezone.utc)
            await self.db.commit()
            await self.db.refresh(item)
        return item

    async def mark_item_as_unread(self, item_id: int, user_id: int) -> SubscriptionItem | None:
        item = await self.get_item_by_id(item_id, user_id)
        if not item:
            return None
        item.read_at = None
        await self.db.commit()
        await self.db.refresh(item)
        return item

    async def toggle_bookmark(self, item_id: int, user_id: int) -> SubscriptionItem | None:
        item = await self.get_item_by_id(item_id, user_id)
        if not item:
            return None
        item.bookmarked = not item.bookmarked
        await self.db.commit()
        await self.db.refresh(item)
        return item

    async def delete_item(self, item_id: int, user_id: int) -> bool:
        item = await self.get_item_by_id(item_id, user_id)
        if not item:
            return False
        await self.db.delete(item)
        await self.db.commit()
        return True

    async def create_category(
        self,
        user_id: int,
        name: str,
        description: str | None = None,
        color: str | None = None,
    ) -> SubscriptionCategory:
        category = SubscriptionCategory(
            user_id=user_id,
            name=name,
            description=description,
            color=color,
        )
        self.db.add(category)
        await self.db.commit()
        await self.db.refresh(category)
        return category

    async def update_category(
        self,
        category_id: int,
        user_id: int,
        **kwargs,
    ) -> SubscriptionCategory | None:
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
        category = await self.get_category_by_id(category_id, user_id)
        if not category:
            return False
        await self.db.delete(category)
        await self.db.commit()
        return True

    async def add_subscription_to_category(self, subscription_id: int, category_id: int) -> bool:
        query = select(SubscriptionCategoryMapping).where(
            SubscriptionCategoryMapping.subscription_id == subscription_id,
            SubscriptionCategoryMapping.category_id == category_id,
        )
        result = await self.db.execute(query)
        existing = result.scalar_one_or_none()
        if existing:
            return True

        mapping = SubscriptionCategoryMapping(
            subscription_id=subscription_id,
            category_id=category_id,
        )
        self.db.add(mapping)
        await self.db.commit()
        return True

    async def remove_subscription_from_category(self, subscription_id: int, category_id: int) -> bool:
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