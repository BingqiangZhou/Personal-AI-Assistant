"""Subscription domain services."""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.feed_parser import FeedParseOptions, FeedParser, FeedParserConfig
from app.core.feed_schemas import FeedParseResult, ParseErrorCode
from app.domains.subscription.models import (
    Subscription,
    SubscriptionItem,
    SubscriptionStatus,
)
from app.domains.subscription.repositories import SubscriptionRepository
from app.shared.schemas import (
    PaginatedResponse,
    SubscriptionCreate,
    SubscriptionResponse,
    SubscriptionUpdate,
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
        source_type: Optional[str] = None,
    ) -> PaginatedResponse:
        """List user's subscriptions."""
        items, total = await self.repo.get_user_subscriptions(
            self.user_id, page, size, status, source_type
        )

        response_items = []
        for sub in items:
            # Get item count for this subscription
            count_query = select(func.count()).select_from(
                select(SubscriptionItem)
                .where(SubscriptionItem.subscription_id == sub.id)
                .subquery()
            )
            item_count = await self.db.scalar(count_query) or 0

            response_items.append(
                SubscriptionResponse(
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
                    updated_at=sub.updated_at,
                )
            )

        return PaginatedResponse.create(
            items=response_items,
            total=total,
            page=page,
            size=size
        )

    async def create_subscription(
        self, sub_data: SubscriptionCreate
    ) -> SubscriptionResponse:
        """
        Create a new subscription with enhanced duplicate detection.

        创建新订阅，带有增强的重复检测。

        Duplicate detection logic:
        1. Check by URL (exact match)
        2. Check by title (case-insensitive)

        If duplicate found:
        - If existing status is ACTIVE: skip creation
        - If existing status is ERROR/INACTIVE/PENDING: update URL and reactivate
        """
        # Check for duplicate by URL or title
        existing = await self.repo.get_duplicate_subscription(
            self.user_id, sub_data.source_url, sub_data.title
        )

        if existing:
            # Check if existing subscription is active
            if existing.status == SubscriptionStatus.ACTIVE:
                # Active subscription - skip creation
                raise ValueError(
                    f"Subscription already exists: {existing.title} "
                    f"(status: {existing.status})"
                )

            # Non-active subscription - update URL and reactivate
            logger.info(
                f"Updating non-active subscription: {existing.title} "
                f"(old_url: {existing.source_url}, new_url: {sub_data.source_url}, "
                f"status: {existing.status} -> ACTIVE)"
            )

            # Update the existing subscription
            existing.source_url = sub_data.source_url
            existing.title = sub_data.title  # Also update title in case it changed
            existing.description = sub_data.description
            existing.status = SubscriptionStatus.ACTIVE
            existing.error_message = None  # Clear any previous errors
            existing.updated_at = datetime.utcnow()

            await self.db.commit()
            await self.db.refresh(existing)

            return SubscriptionResponse(
                id=existing.id,
                user_id=existing.user_id,
                title=existing.title,
                description=existing.description,
                source_type=existing.source_type,
                source_url=existing.source_url,
                config=existing.config,
                status=existing.status,
                last_fetched_at=existing.last_fetched_at,
                error_message=existing.error_message,
                fetch_interval=existing.fetch_interval,
                item_count=0,  # Will be updated if needed
                created_at=existing.created_at,
                updated_at=existing.updated_at,
            )

        # No duplicate found - create new subscription
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
            updated_at=sub.updated_at,
        )

    async def create_subscriptions_batch(
        self, subscriptions_data: List[SubscriptionCreate]
    ) -> List[Dict[str, Any]]:
        """
        Batch create subscriptions with enhanced duplicate detection.

        批量创建订阅，带有增强的重复检测。

        Returns results with status:
        - success: New subscription created
        - updated: Existing subscription updated (non-active status)
        - skipped: Existing active subscription (no change)
        - error: Error occurred
        """
        results = []
        for sub_data in subscriptions_data:
            try:
                # Check for duplicate by URL or title
                existing = await self.repo.get_duplicate_subscription(
                    self.user_id, sub_data.source_url, sub_data.title
                )

                if existing:
                    # Check if existing subscription is active
                    if existing.status == SubscriptionStatus.ACTIVE:
                        results.append(
                            {
                                "source_url": sub_data.source_url,
                                "title": sub_data.title,
                                "status": "skipped",
                                "message": f"Subscription already exists: {existing.title}",
                                "existing_id": existing.id,
                            }
                        )
                        continue

                    # Non-active subscription - update URL and reactivate
                    logger.info(
                        f"Updating non-active subscription in batch: {existing.title} "
                        f"(old_url: {existing.source_url}, new_url: {sub_data.source_url})"
                    )

                    existing.source_url = sub_data.source_url
                    existing.title = sub_data.title
                    existing.description = sub_data.description
                    existing.status = SubscriptionStatus.ACTIVE
                    existing.error_message = None
                    existing.updated_at = datetime.utcnow()

                    await self.db.commit()
                    await self.db.refresh(existing)

                    results.append(
                        {
                            "source_url": sub_data.source_url,
                            "title": sub_data.title,
                            "status": "updated",
                            "id": existing.id,
                            "message": f"Updated existing subscription: {existing.title}",
                        }
                    )
                    continue

                # No duplicate - create new subscription
                sub = await self.repo.create_subscription(self.user_id, sub_data)
                results.append(
                    {
                        "source_url": sub_data.source_url,
                        "title": sub_data.title,
                        "status": "success",
                        "id": sub.id,
                    }
                )

            except ValueError as e:
                # Validation errors (like active duplicate)
                results.append(
                    {
                        "source_url": sub_data.source_url,
                        "title": sub_data.title,
                        "status": "skipped",
                        "message": str(e),
                    }
                )
            except Exception as e:
                logger.error(
                    f"Error creating subscription for {sub_data.source_url}: {e}"
                )
                results.append(
                    {
                        "source_url": sub_data.source_url,
                        "title": sub_data.title,
                        "status": "error",
                        "message": str(e),
                    }
                )
        return results

    async def get_subscription(self, sub_id: int) -> Optional[SubscriptionResponse]:
        """Get subscription details."""
        sub = await self.repo.get_subscription_by_id(self.user_id, sub_id)
        if not sub:
            return None

        # Get item count
        from sqlalchemy import func, select

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
            updated_at=sub.updated_at,
        )

    async def update_subscription(
        self, sub_id: int, sub_data: SubscriptionUpdate
    ) -> Optional[SubscriptionResponse]:
        """Update subscription."""
        sub = await self.repo.update_subscription(self.user_id, sub_id, sub_data)
        if not sub:
            return None

        return await self.get_subscription(sub_id)

    async def delete_subscription(self, sub_id: int) -> bool:
        """Delete subscription."""
        return await self.repo.delete_subscription(self.user_id, sub_id)

    async def fetch_subscription(self, sub_id: int) -> Dict[str, Any]:
        """
        Manually trigger subscription fetch (for RSS feeds).

        手动触发订阅获取（RSS 订阅）。

        Uses the enhanced FeedParser component for robust parsing.
        使用增强的 FeedParser 组件进行健壮解析。
        """
        sub = await self.repo.get_subscription_by_id(self.user_id, sub_id)
        if not sub:
            raise ValueError("Subscription not found")

        if sub.source_type != "rss":
            raise ValueError("Only RSS subscriptions support manual fetch")

        # Configure parser
        config = FeedParserConfig(
            max_entries=50,  # Limit to 50 items per fetch
            strip_html=True,
            strict_mode=False,  # Continue on entry errors
            log_raw_feed=False,
        )

        options = FeedParseOptions(strip_html_content=True, include_raw_metadata=False)

        # Parse feed using new FeedParser
        parser = FeedParser(config)
        try:
            result: FeedParseResult = await parser.parse_feed(
                sub.source_url, options=options
            )

            # Check for critical errors
            if not result.success and result.has_errors():
                critical_errors = [
                    e
                    for e in result.errors
                    if e.code
                    in (ParseErrorCode.NETWORK_ERROR, ParseErrorCode.PARSE_ERROR)
                ]
                if critical_errors:
                    error_msgs = "; ".join(e.message for e in critical_errors)
                    await self.repo.update_fetch_status(
                        sub.id, SubscriptionStatus.ERROR, error_msgs
                    )
                    raise ValueError(f"Feed parsing failed: {error_msgs}")

            # Process feed entries
            new_items = 0
            updated_items = 0

            for entry in result.entries:
                try:
                    # Create or update item using parsed entry data
                    item = await self.repo.create_or_update_item(
                        subscription_id=sub.id,
                        external_id=entry.id or entry.link or "",
                        title=entry.title,
                        content=entry.content,
                        summary=entry.summary,
                        author=entry.author,
                        source_url=entry.link,
                        image_url=entry.image_url,
                        tags=entry.tags,
                        published_at=entry.published_at,
                    )

                    # Check if this was a new item (simplified check)
                    if item.created_at == item.updated_at:
                        new_items += 1
                    else:
                        updated_items += 1

                except Exception as e:
                    logger.warning(f"Error processing entry {entry.id}: {e}")
                    if config.strict_mode:
                        raise

            # Update subscription status
            status = SubscriptionStatus.ACTIVE
            error_msg = None

            # Include warnings in error message if any
            if result.has_warnings():
                logger.warning(
                    f"Warnings parsing feed {sub.source_url}: {result.warnings}"
                )
                if result.warnings:
                    error_msg = "; ".join(result.warnings)

            await self.repo.update_fetch_status(sub.id, status, error_msg)

            return {
                "subscription_id": sub.id,
                "status": "success",
                "new_items": new_items,
                "updated_items": updated_items,
                "total_items": new_items + updated_items,
                "warnings": result.warnings if result.has_warnings() else None,
            }

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Error fetching subscription {sub_id}: {e}")
            await self.repo.update_fetch_status(
                sub.id, SubscriptionStatus.ERROR, str(e)
            )
            raise
        finally:
            await parser.close()

    async def fetch_all_subscriptions(self) -> List[Dict[str, Any]]:
        """Fetch all active RSS subscriptions."""
        subs, _ = await self.repo.get_user_subscriptions(
            self.user_id,
            page=1,
            size=100,
            status=SubscriptionStatus.ACTIVE,
            source_type="rss",
        )

        results = []
        for sub in subs:
            try:
                result = await self.fetch_subscription(sub.id)
                results.append(result)
            except Exception as e:
                results.append(
                    {"subscription_id": sub.id, "status": "error", "error": str(e)}
                )

        return results

    # Subscription Item operations
    async def get_subscription_items(
        self,
        sub_id: int,
        page: int = 1,
        size: int = 20,
        unread_only: bool = False,
        bookmarked_only: bool = False,
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
                "created_at": item.created_at.isoformat(),
            }
            for item in items
        ]

        return PaginatedResponse.create(
            items=response_items, total=total, page=page, size=size
        )

    async def get_all_items(
        self,
        page: int = 1,
        size: int = 50,
        unread_only: bool = False,
        bookmarked_only: bool = False,
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
                "created_at": item.created_at.isoformat(),
            }
            for item in items
        ]

        return PaginatedResponse.create(
            items=response_items,
            total=total,
            page=page,
            size=size
        )

    async def mark_item_as_read(self, item_id: int) -> Optional[Dict[str, Any]]:
        """Mark an item as read."""
        item = await self.repo.mark_item_as_read(item_id, self.user_id)
        if not item:
            return None

        return {
            "id": item.id,
            "read_at": item.read_at.isoformat() if item.read_at else None,
        }

    async def mark_item_as_unread(self, item_id: int) -> Optional[Dict[str, Any]]:
        """Mark an item as unread."""
        item = await self.repo.mark_item_as_unread(item_id, self.user_id)
        if not item:
            return None

        return {"id": item.id, "read_at": None}

    async def toggle_bookmark(self, item_id: int) -> Optional[Dict[str, Any]]:
        """Toggle item bookmark status."""
        item = await self.repo.toggle_bookmark(item_id, self.user_id)
        if not item:
            return None

        return {"id": item.id, "bookmarked": item.bookmarked}

    async def delete_item(self, item_id: int) -> bool:
        """Delete an item."""
        return await self.repo.delete_item(item_id, self.user_id)

    async def get_unread_count(self) -> int:
        """Get total unread items count."""
        return await self.repo.get_unread_count(self.user_id)

    # Category operations
    async def list_categories(self) -> List[Dict[str, Any]]:
        """Get all user's categories."""
        categories = await self.repo.get_user_categories(self.user_id)

        return [
            {
                "id": cat.id,
                "name": cat.name,
                "description": cat.description,
                "color": cat.color,
                "created_at": cat.created_at.isoformat(),
            }
            for cat in categories
        ]

    async def create_category(
        self, name: str, description: Optional[str] = None, color: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new category."""
        cat = await self.repo.create_category(self.user_id, name, description, color)

        return {
            "id": cat.id,
            "name": cat.name,
            "description": cat.description,
            "color": cat.color,
            "created_at": cat.created_at.isoformat(),
        }

    async def update_category(
        self, category_id: int, **kwargs
    ) -> Optional[Dict[str, Any]]:
        """Update category."""
        cat = await self.repo.update_category(category_id, self.user_id, **kwargs)
        if not cat:
            return None

        return {
            "id": cat.id,
            "name": cat.name,
            "description": cat.description,
            "color": cat.color,
        }

    async def delete_category(self, category_id: int) -> bool:
        """Delete category."""
        return await self.repo.delete_category(category_id, self.user_id)

    async def add_subscription_to_category(
        self, subscription_id: int, category_id: int
    ) -> bool:
        """Add subscription to category."""
        # Verify ownership
        sub = await self.repo.get_subscription_by_id(self.user_id, subscription_id)
        cat = await self.repo.get_category_by_id(category_id, self.user_id)

        if not sub or not cat:
            return False

        return await self.repo.add_subscription_to_category(
            subscription_id, category_id
        )

    async def remove_subscription_from_category(
        self, subscription_id: int, category_id: int
    ) -> bool:
        """Remove subscription from category."""
        return await self.repo.remove_subscription_from_category(
            subscription_id, category_id
        )
