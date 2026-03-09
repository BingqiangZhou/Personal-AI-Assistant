"""Test timezone handling for subscription sync.

This test module verifies the fix for the timezone comparison error
that occurred during podcast subscription synchronization.
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.datetime_utils import ensure_timezone_aware_fetch_time
from app.domains.podcast.models import PodcastEpisode
from app.domains.podcast.repositories import PodcastSubscriptionRepository
from app.domains.subscription.models import Subscription


@pytest.mark.asyncio
async def test_update_subscription_fetch_time_preserves_timezone(
    db_session: AsyncSession,
):
    """Test that update_subscription_fetch_time stores timezone-aware datetimes."""
    repo = PodcastSubscriptionRepository(db_session)

    subscription = Subscription(
        source_url="https://example.com/feed.xml",
        source_type="podcast-rss",
        title="Test Podcast",
    )
    db_session.add(subscription)
    await db_session.commit()
    await db_session.refresh(subscription)

    fetch_time = datetime.now(timezone.utc)
    await repo.update_subscription_fetch_time(subscription.id, fetch_time)

    await db_session.refresh(subscription)
    assert subscription.last_fetched_at is not None
    assert subscription.last_fetched_at.tzinfo is not None
    assert subscription.last_fetched_at.tzinfo == timezone.utc


@pytest.mark.asyncio
async def test_episode_published_at_comparison_with_subscription(
    db_session: AsyncSession,
):
    """Test that episode.published_at can be compared with subscription.last_fetched_at."""
    subscription = Subscription(
        source_url="https://example.com/feed.xml",
        source_type="podcast-rss",
        title="Test Podcast",
        last_fetched_at=datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
    )
    db_session.add(subscription)
    await db_session.commit()
    await db_session.refresh(subscription)

    episode = PodcastEpisode(
        subscription_id=subscription.id,
        title="Test Episode",
        audio_url="https://example.com/episode.mp3",
        item_link="https://example.com/episode",
        published_at=datetime(2024, 1, 2, 12, 0, tzinfo=timezone.utc),
    )
    db_session.add(episode)
    await db_session.commit()
    await db_session.refresh(episode)

    # This should NOT raise TypeError
    assert episode.published_at > subscription.last_fetched_at


@pytest.mark.asyncio
async def test_ensure_timezone_aware_fetch_time_with_naive_datetime():
    """Test that ensure_timezone_aware_fetch_time converts naive to aware."""
    naive_time = datetime(2024, 1, 1, 12, 0, 0)
    aware_time = ensure_timezone_aware_fetch_time(naive_time)

    assert aware_time is not None
    assert aware_time.tzinfo is not None
    assert aware_time.tzinfo == timezone.utc


@pytest.mark.asyncio
async def test_ensure_timezone_aware_fetch_time_with_aware_datetime():
    """Test that ensure_timezone_aware_fetch_time preserves aware datetimes."""
    aware_time = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
    result = ensure_timezone_aware_fetch_time(aware_time)

    assert result is not None
    assert result.tzinfo is not None
    assert result.tzinfo == timezone.utc


@pytest.mark.asyncio
async def test_ensure_timezone_aware_fetch_time_with_none():
    """Test that ensure_timezone_aware_fetch_time handles None input."""
    result = ensure_timezone_aware_fetch_time(None)
    assert result is None


@pytest.mark.asyncio
async def test_ensure_timezone_aware_fetch_time_converts_non_utc_to_utc():
    """Test that ensure_timezone_aware_fetch_time converts non-UTC timezones to UTC."""
    from zoneinfo import ZoneInfo

    # Create a datetime in a different timezone
    eastern = ZoneInfo("America/New_York")
    eastern_time = datetime(2024, 1, 1, 12, 0, tzinfo=eastern)

    result = ensure_timezone_aware_fetch_time(eastern_time)

    assert result is not None
    assert result.tzinfo is not None
    assert result.tzinfo == timezone.utc
    # Eastern time is UTC-5 (or -4 during DST), so 12:00 EST becomes ~17:00 UTC
    assert result.hour >= 16  # Account for UTC offset


@pytest.mark.asyncio
async def test_subscription_comparison_scenario_with_new_episodes(
    db_session: AsyncSession,
):
    """Test the actual scenario: new episodes after last fetch should trigger transcription."""
    subscription = Subscription(
        source_url="https://example.com/feed.xml",
        source_type="podcast-rss",
        title="Test Podcast",
        last_fetched_at=datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
    )
    db_session.add(subscription)
    await db_session.commit()
    await db_session.refresh(subscription)

    # Create episodes after the last fetch time
    new_episode = PodcastEpisode(
        subscription_id=subscription.id,
        title="New Episode",
        audio_url="https://example.com/new.mp3",
        item_link="https://example.com/new",
        published_at=datetime(2024, 1, 2, 12, 0, tzinfo=timezone.utc),
    )
    db_session.add(new_episode)

    # Create an episode before the last fetch time
    old_episode = PodcastEpisode(
        subscription_id=subscription.id,
        title="Old Episode",
        audio_url="https://example.com/old.mp3",
        item_link="https://example.com/old",
        published_at=datetime(2023, 12, 31, 12, 0, tzinfo=timezone.utc),
    )
    db_session.add(old_episode)

    await db_session.commit()
    await db_session.refresh(new_episode)
    await db_session.refresh(old_episode)

    # New episode should be after last fetch
    assert new_episode.published_at > subscription.last_fetched_at

    # Old episode should be before last fetch
    assert old_episode.published_at < subscription.last_fetched_at
