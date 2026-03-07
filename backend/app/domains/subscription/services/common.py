"""Shared helpers for subscription domain services."""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse
from xml.etree.ElementTree import Element, SubElement

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.subscription.models import Subscription, SubscriptionStatus, UserSubscription
from app.domains.subscription.repositories import SubscriptionRepository
from app.shared.schemas import SubscriptionCreate


class SubscriptionServiceSupport:
    """Provide shared helpers across split subscription services."""

    def __init__(
        self,
        db: AsyncSession,
        user_id: int,
        repo: SubscriptionRepository,
    ):
        self.db = db
        self.user_id = user_id
        self.repo = repo

    async def get_default_schedule_settings(self) -> tuple[str, str | None, int | None]:
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

        return update_frequency, update_time, update_day_of_week

    async def subscribe_or_attach(
        self,
        sub_data: SubscriptionCreate,
        *,
        raise_on_active_duplicate: bool = False,
    ) -> tuple[str, Subscription, str | None]:
        existing = await self.repo.get_duplicate_subscription(
            self.user_id,
            sub_data.source_url,
            sub_data.title,
        )

        if not existing:
            created = await self.repo.create_subscription(self.user_id, sub_data)
            return "success", created, "Subscription created"

        user_sub_result = await self.db.execute(
            select(UserSubscription).where(
                UserSubscription.user_id == self.user_id,
                UserSubscription.subscription_id == existing.id,
            )
        )
        user_sub = user_sub_result.scalar_one_or_none()

        if user_sub:
            if user_sub.is_archived:
                user_sub.is_archived = False
                if not user_sub.update_frequency:
                    (
                        user_sub.update_frequency,
                        user_sub.update_time,
                        user_sub.update_day_of_week,
                    ) = await self.get_default_schedule_settings()
                await self.db.commit()
                await self.db.refresh(existing)
                return "updated", existing, "Subscription restored"

            if existing.status == SubscriptionStatus.ACTIVE:
                if raise_on_active_duplicate:
                    raise ValueError(f"Already subscribed to: {existing.title}")
                return (
                    "skipped",
                    existing,
                    f"Subscription already exists: {existing.title}",
                )

            existing.source_url = sub_data.source_url
            existing.title = sub_data.title
            existing.description = sub_data.description
            existing.status = SubscriptionStatus.ACTIVE
            existing.error_message = None
            existing.updated_at = datetime.now(timezone.utc)
            await self.db.commit()
            await self.db.refresh(existing)
            return "updated", existing, f"Updated existing subscription: {existing.title}"

        (
            update_frequency,
            update_time,
            update_day_of_week,
        ) = await self.get_default_schedule_settings()
        self.db.add(
            UserSubscription(
                user_id=self.user_id,
                subscription_id=existing.id,
                update_frequency=update_frequency,
                update_time=update_time,
                update_day_of_week=update_day_of_week,
            )
        )

        status = "success"
        message = f"Subscribed to existing source: {existing.title}"
        if existing.status != SubscriptionStatus.ACTIVE:
            existing.source_url = sub_data.source_url
            existing.title = sub_data.title
            existing.description = sub_data.description
            existing.status = SubscriptionStatus.ACTIVE
            existing.error_message = None
            existing.updated_at = datetime.now(timezone.utc)
            status = "updated"
            message = f"Updated and subscribed to existing source: {existing.title}"

        await self.db.commit()
        await self.db.refresh(existing)
        return status, existing, message

    def add_subscription_to_opml(self, parent: Element, subscription: Subscription) -> None:
        outline = SubElement(parent, "outline")
        outline.set("text", subscription.title or "Untitled")
        outline.set("title", subscription.title or "Untitled")
        outline.set("xmlUrl", subscription.source_url)

        try:
            parsed = urlparse(subscription.source_url)
            html_url = f"{parsed.scheme}://{parsed.netloc}/"
            outline.set("htmlUrl", html_url)
        except Exception:
            pass

        if subscription.description:
            outline.set("description", subscription.description[:500])