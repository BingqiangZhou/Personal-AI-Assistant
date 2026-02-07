"""Handlers for subscription sync background tasks."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import and_, select

from app.domains.podcast.integration.secure_rss_parser import SecureRSSParser
from app.domains.podcast.repositories import PodcastRepository
from app.domains.podcast.services.sync_service import PodcastSyncService
from app.domains.subscription.models import (
    Subscription,
    SubscriptionStatus,
    UserSubscription,
)


logger = logging.getLogger(__name__)


async def refresh_all_podcast_feeds_handler(session) -> dict:
    """Refresh all active podcast-rss subscriptions due by user schedule."""
    repo = PodcastRepository(session)

    sub_stmt = select(Subscription).where(
        and_(
            Subscription.source_type == "podcast-rss",
            Subscription.status == SubscriptionStatus.ACTIVE.value,
        )
    )
    sub_rows = await session.execute(sub_stmt)
    all_subscriptions = list(sub_rows.scalars().all())

    user_sub_stmt = (
        select(UserSubscription)
        .join(Subscription, UserSubscription.subscription_id == Subscription.id)
        .where(
            and_(
                Subscription.source_type == "podcast-rss",
                Subscription.status == SubscriptionStatus.ACTIVE.value,
                UserSubscription.is_archived == False,  # noqa: E712
            )
        )
    )
    user_sub_rows = await session.execute(user_sub_stmt)
    user_subscriptions = list(user_sub_rows.scalars().all())

    subscriptions_to_update: set[int] = set()
    for item in user_subscriptions:
        if item.should_update_now():
            subscriptions_to_update.add(item.subscription_id)

    if subscriptions_to_update:
        target_ids = subscriptions_to_update
    else:
        target_ids = {sub.id for sub in all_subscriptions}

    refreshed_count = 0
    new_episodes_count = 0

    for subscription_id in target_ids:
        subscription = next(
            (sub for sub in all_subscriptions if sub.id == subscription_id),
            None,
        )
        if subscription is None:
            continue

        # Use any subscriber as execution user context; fall back to admin user id.
        user_sub = next(
            (us for us in user_subscriptions if us.subscription_id == subscription_id),
            None,
        )
        user_id = user_sub.user_id if user_sub else 1
        parser = SecureRSSParser(user_id)

        try:
            success, feed, error = await parser.fetch_and_parse_feed(subscription.source_url)
            if not success:
                logger.error(
                    "Failed refreshing subscription %s (%s): %s",
                    subscription.id,
                    subscription.title,
                    error,
                )
                continue

            sync_service = PodcastSyncService(session, user_id)
            new_episodes = 0

            for episode in feed.episodes:
                saved_episode, is_new = await repo.create_or_update_episode(
                    subscription_id=subscription.id,
                    title=episode.title,
                    description=episode.description,
                    audio_url=episode.audio_url,
                    published_at=episode.published_at,
                    audio_duration=episode.duration,
                    transcript_url=episode.transcript_url,
                    item_link=episode.link,
                    metadata={
                        "feed_title": feed.title,
                        "refreshed_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
                if is_new:
                    new_episodes += 1
                    await sync_service.trigger_transcription(saved_episode.id)

            await repo.update_subscription_fetch_time(subscription.id, feed.last_fetched)

            refreshed_count += 1
            new_episodes_count += new_episodes
            if new_episodes:
                logger.info(
                    "Refreshed subscription %s (%s), %s new episodes",
                    subscription.id,
                    subscription.title,
                    new_episodes,
                )
        except Exception:
            logger.exception("Unexpected failure during refresh for subscription %s", subscription_id)

    return {
        "status": "success",
        "refreshed_subscriptions": refreshed_count,
        "new_episodes": new_episodes_count,
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }
