"""Tests for enhanced subscription duplicate detection."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.subscription.models import SubscriptionStatus
from app.domains.subscription.repositories import SubscriptionRepository
from app.domains.subscription.services import SubscriptionService
from app.shared.schemas import SubscriptionCreate


@pytest.mark.asyncio
class TestDuplicateDetection:
    """Test suite for enhanced duplicate detection."""

    async def test_get_subscription_by_title_case_insensitive(
        self, db_session: AsyncSession, test_user
    ):
        """Test finding subscription by title (case-insensitive)."""
        repo = SubscriptionRepository(db_session)

        # Create a subscription
        sub_data = SubscriptionCreate(
            title="Tech News Daily",
            description="Daily tech news",
            source_type="rss",
            source_url="https://example.com/feed.xml",
        )
        sub = await repo.create_subscription(test_user.id, sub_data)

        # Find with different case
        found = await repo.get_subscription_by_title(test_user.id, "TECH NEWS DAILY")
        assert found is not None
        assert found.id == sub.id

        # Find with partial case change
        found = await repo.get_subscription_by_title(test_user.id, "Tech News daily")
        assert found is not None
        assert found.id == sub.id

    async def test_get_duplicate_subscription_by_url(
        self, db_session: AsyncSession, test_user
    ):
        """Test duplicate detection by URL."""
        repo = SubscriptionRepository(db_session)

        # Create a subscription
        sub_data = SubscriptionCreate(
            title="Tech News",
            description="Tech news feed",
            source_type="rss",
            source_url="https://example.com/feed.xml",
        )
        sub = await repo.create_subscription(test_user.id, sub_data)

        # Check duplicate by URL
        duplicate = await repo.get_duplicate_subscription(
            test_user.id,
            "https://example.com/feed.xml",
            "Different Title",  # Different title
        )
        assert duplicate is not None
        assert duplicate.id == sub.id

    async def test_get_duplicate_subscription_by_title(
        self, db_session: AsyncSession, test_user
    ):
        """Test duplicate detection by title."""
        repo = SubscriptionRepository(db_session)

        # Create a subscription
        sub_data = SubscriptionCreate(
            title="Tech News Daily",
            description="Tech news feed",
            source_type="rss",
            source_url="https://example.com/feed.xml",
        )
        sub = await repo.create_subscription(test_user.id, sub_data)

        # Check duplicate by title
        duplicate = await repo.get_duplicate_subscription(
            test_user.id,
            "https://different.com/feed.xml",  # Different URL
            "Tech News Daily",  # Same title
        )
        assert duplicate is not None
        assert duplicate.id == sub.id

    async def test_create_subscription_skip_active_duplicate(
        self, db_session: AsyncSession, test_user
    ):
        """Test that active duplicates are skipped."""
        service = SubscriptionService(db_session, test_user.id)

        # Create initial subscription
        sub_data = SubscriptionCreate(
            title="Tech News",
            description="Tech news feed",
            source_type="rss",
            source_url="https://example.com/feed.xml",
        )
        await service.create_subscription(sub_data)

        # Try to create duplicate with same URL
        with pytest.raises(ValueError) as exc_info:
            await service.create_subscription(sub_data)
        assert "already exists" in str(exc_info.value)

    async def test_create_subscription_update_inactive_duplicate(
        self, db_session: AsyncSession, test_user
    ):
        """Test that inactive duplicates are updated."""
        service = SubscriptionService(db_session, test_user.id)

        # Create initial subscription with ERROR status
        sub_data = SubscriptionCreate(
            title="Tech News",
            description="Tech news feed",
            source_type="rss",
            source_url="https://old-url.com/feed.xml",
        )
        created = await service.create_subscription(sub_data)

        # Set status to ERROR
        from sqlalchemy import select

        from app.domains.subscription.models import Subscription

        result = await db_session.execute(
            select(Subscription).where(Subscription.id == created.id)
        )
        sub = result.scalar_one_or_none()
        sub.status = SubscriptionStatus.ERROR
        sub.error_message = "Failed to fetch"
        await db_session.commit()

        # Try to create with new URL but same title
        new_data = SubscriptionCreate(
            title="Tech News",
            description="Updated description",
            source_type="rss",
            source_url="https://new-url.com/feed.xml",
        )
        updated = await service.create_subscription(new_data)

        # Should update existing subscription
        assert updated.id == created.id
        assert updated.source_url == "https://new-url.com/feed.xml"
        assert updated.status == SubscriptionStatus.ACTIVE
        assert updated.error_message is None

    async def test_batch_create_with_mixed_scenarios(
        self, db_session: AsyncSession, test_user
    ):
        """Test batch creation with various scenarios."""
        service = SubscriptionService(db_session, test_user.id)

        # Create initial subscriptions
        active_sub = await service.create_subscription(
            SubscriptionCreate(
                title="Active Feed",
                description="Active subscription",
                source_type="rss",
                source_url="https://active.com/feed.xml",
            )
        )

        error_sub = await service.create_subscription(
            SubscriptionCreate(
                title="Error Feed",
                description="Error subscription",
                source_type="rss",
                source_url="https://error.com/feed.xml",
            )
        )

        # Set error_sub to ERROR status
        from sqlalchemy import select

        from app.domains.subscription.models import Subscription

        result = await db_session.execute(
            select(Subscription).where(Subscription.id == error_sub.id)
        )
        sub = result.scalar_one_or_none()
        sub.status = SubscriptionStatus.ERROR
        await db_session.commit()

        # Batch create with mixed scenarios
        batch_data = [
            # 1. Duplicate active (URL match) - should be skipped
            SubscriptionCreate(
                title="Active Feed",
                description="Active subscription",
                source_type="rss",
                source_url="https://active.com/feed.xml",
            ),
            # 2. Duplicate error (title match) - should be updated
            SubscriptionCreate(
                title="Error Feed",
                description="Fixed subscription",
                source_type="rss",
                source_url="https://fixed-error.com/feed.xml",
            ),
            # 3. New subscription - should be created
            SubscriptionCreate(
                title="New Feed",
                description="New subscription",
                source_type="rss",
                source_url="https://new.com/feed.xml",
            ),
        ]

        results = await service.create_subscriptions_batch(batch_data)

        # Verify results
        assert len(results) == 3

        # First should be skipped (active duplicate)
        assert results[0]["status"] == "skipped"
        assert results[0]["source_url"] == "https://active.com/feed.xml"

        # Second should be updated (error duplicate)
        assert results[1]["status"] == "updated"
        assert results[1]["source_url"] == "https://fixed-error.com/feed.xml"
        assert results[1]["id"] == error_sub.id

        # Third should be success (new)
        assert results[2]["status"] == "success"
        assert results[2]["source_url"] == "https://new.com/feed.xml"

    async def test_no_duplicate_for_different_users(
        self, db_session: AsyncSession, test_user, another_user
    ):
        """Test that subscriptions for different users don't conflict."""
        repo = SubscriptionRepository(db_session)

        # Create subscription for user 1
        sub_data = SubscriptionCreate(
            title="Tech News",
            description="Tech news feed",
            source_type="rss",
            source_url="https://example.com/feed.xml",
        )
        await repo.create_subscription(test_user.id, sub_data)

        # User 2 should be able to create same subscription
        user2_sub = await repo.create_subscription(another_user.id, sub_data)
        assert user2_sub is not None

        # Check duplicate for user 1 should find the subscription
        duplicate = await repo.get_duplicate_subscription(
            test_user.id,
            "https://example.com/feed.xml",
            "Tech News",
        )
        assert duplicate is not None

        # Check duplicate for user 2 should find their subscription
        duplicate2 = await repo.get_duplicate_subscription(
            another_user.id,
            "https://example.com/feed.xml",
            "Tech News",
        )
        assert duplicate2 is not None
        assert duplicate2.id != duplicate.id
