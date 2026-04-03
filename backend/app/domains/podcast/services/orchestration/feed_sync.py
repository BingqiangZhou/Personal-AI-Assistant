"""Feed sync orchestrator -- RSS feed refresh and OPML episode parsing."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

import aiohttp
from sqlalchemy import and_, select
from sqlalchemy.orm import joinedload

from app.core.config import settings
from app.core.database import worker_db_session
from app.core.datetime_utils import ensure_timezone_aware_fetch_time
from app.domains.podcast.integration.secure_rss_parser import SecureRSSParser
from app.domains.podcast.repositories import PodcastSubscriptionRepository
from app.domains.subscription.models import (
    Subscription,
    SubscriptionStatus,
    UserSubscription,
)

from .base import BaseOrchestrator


logger = logging.getLogger(__name__)


class FeedSyncOrchestrator(BaseOrchestrator):
    """Orchestrate RSS feed refresh and OPML episode parsing tasks."""

    _refresh_batch_size = 100

    async def refresh_all_podcast_feeds(self) -> dict:
        refreshed_count = 0
        new_episodes_count = 0
        pending_transcription_episode_ids: list[int] = []
        next_subscription_id = 0
        concurrency = max(1, settings.RSS_REFRESH_CONCURRENCY)

        while True:
            candidates, next_subscription_id = await self._load_due_refresh_candidates(
                after_subscription_id=next_subscription_id,
                limit=self._refresh_batch_size,
            )
            if not candidates and next_subscription_id is None:
                break
            if not candidates:
                continue

            batch_result = await self._refresh_due_subscription_batch(
                candidates,
                concurrency=concurrency,
            )
            refreshed_count += batch_result["refreshed_subscriptions"]
            new_episodes_count += batch_result["new_episodes"]
            pending_transcription_episode_ids.extend(
                batch_result["transcription_episode_ids"],
            )

            if next_subscription_id is None:
                break

        if pending_transcription_episode_ids:
            from app.domains.podcast.services.orchestration.transcription import (
                TranscriptionOrchestrator,
            )

            transcription = TranscriptionOrchestrator(self.session)
            workflow = transcription.build_transcription_workflow()
            dispatch_result = await workflow.dispatch_pending_transcriptions(
                pending_transcription_episode_ids,
            )
            logger.info(
                "Feed refresh transcription dispatch completed: checked=%s dispatched=%s skipped=%s failed=%s",
                dispatch_result["checked"],
                dispatch_result["dispatched"],
                dispatch_result["skipped"],
                dispatch_result["failed"],
            )

        return {
            "status": "success",
            "refreshed_subscriptions": refreshed_count,
            "new_episodes": new_episodes_count,
            "processed_at": datetime.now(UTC).isoformat(),
        }

    async def _load_due_refresh_candidates(
        self,
        *,
        after_subscription_id: int,
        limit: int,
    ) -> tuple[list[dict[str, Any]], int | None]:
        sub_stmt = (
            select(Subscription)
            .where(
                and_(
                    Subscription.source_type == "podcast-rss",
                    Subscription.status == SubscriptionStatus.ACTIVE.value,
                    Subscription.id > after_subscription_id,
                ),
            )
            .order_by(Subscription.id.asc())
            .limit(limit)
        )
        sub_rows = await self.session.execute(sub_stmt)
        subscriptions = list(sub_rows.scalars().all())
        if not subscriptions:
            return [], None

        subscription_ids = [subscription.id for subscription in subscriptions]
        user_sub_stmt = (
            select(UserSubscription)
            .options(joinedload(UserSubscription.subscription))
            .where(
                and_(
                    UserSubscription.subscription_id.in_(subscription_ids),
                    UserSubscription.is_archived.is_(False),
                ),
            )
            .order_by(UserSubscription.subscription_id.asc(), UserSubscription.id.asc())
        )
        user_sub_rows = await self.session.execute(user_sub_stmt)
        user_subscriptions = list(user_sub_rows.scalars().all())

        due_candidates: list[dict[str, Any]] = []
        seen_subscription_ids: set[int] = set()
        for user_subscription in user_subscriptions:
            if user_subscription.subscription_id in seen_subscription_ids:
                continue
            if not user_subscription.should_update_now():
                continue

            seen_subscription_ids.add(user_subscription.subscription_id)
            due_candidates.append(
                {
                    "subscription_id": user_subscription.subscription_id,
                    "user_id": user_subscription.user_id,
                },
            )

        next_cursor = subscriptions[-1].id if len(subscriptions) >= limit else None
        return due_candidates, next_cursor

    async def _refresh_due_subscription_batch(
        self,
        candidates: list[dict[str, Any]],
        *,
        concurrency: int,
    ) -> dict[str, Any]:
        semaphore = asyncio.Semaphore(concurrency)
        timeout = aiohttp.ClientTimeout(total=60, connect=10)
        connector = aiohttp.TCPConnector(limit=concurrency, limit_per_host=concurrency)
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
            ),
        }

        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers,
        ) as http_session:

            async def _run_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
                async with semaphore:
                    return await self._refresh_single_subscription(
                        candidate,
                        http_session=http_session,
                    )

            results = await asyncio.gather(
                *[_run_candidate(candidate) for candidate in candidates],
                return_exceptions=True,
            )

        refreshed_subscriptions = 0
        new_episodes = 0
        transcription_episode_ids: list[int] = []
        for candidate, result in zip(candidates, results, strict=False):
            if isinstance(result, Exception):
                logger.exception(
                    "Unexpected failure during refresh for subscription %s",
                    candidate["subscription_id"],
                    exc_info=result,
                )
                continue

            refreshed_subscriptions += result["refreshed"]
            new_episodes += result["new_episodes"]
            transcription_episode_ids.extend(result["transcription_episode_ids"])

        return {
            "refreshed_subscriptions": refreshed_subscriptions,
            "new_episodes": new_episodes,
            "transcription_episode_ids": transcription_episode_ids,
        }

    async def _refresh_single_subscription(
        self,
        candidate: dict[str, Any],
        *,
        http_session: aiohttp.ClientSession,
    ) -> dict[str, Any]:
        subscription_id = int(candidate["subscription_id"])
        user_id = int(candidate["user_id"])

        async with worker_db_session("celery-feed-refresh-subscription") as session:
            repo = PodcastSubscriptionRepository(session)
            subscription = await repo.get_subscription_by_id_direct(subscription_id)
            if subscription is None:
                return {
                    "refreshed": 0,
                    "new_episodes": 0,
                    "transcription_episode_ids": [],
                }

            parser = SecureRSSParser(user_id=user_id, shared_session=http_session)
            try:
                success, feed, error = await parser.fetch_and_parse_feed(
                    subscription.source_url,
                    max_episodes=settings.PODCAST_EPISODE_BATCH_SIZE,
                    newer_than=subscription.last_fetched_at,
                )
                if not success or feed is None:
                    logger.error(
                        "Failed refreshing subscription %s (%s): %s",
                        subscription.id,
                        subscription.title,
                        error,
                    )
                    return {
                        "refreshed": 0,
                        "new_episodes": 0,
                        "transcription_episode_ids": [],
                    }

                refreshed_at = datetime.now(UTC).isoformat()
                episodes_payload = [
                    {
                        "title": episode.title,
                        "description": episode.description,
                        "audio_url": episode.audio_url,
                        "published_at": episode.published_at,
                        "audio_duration": episode.duration,
                        "transcript_url": episode.transcript_url,
                        "item_link": episode.link,
                        "metadata": {
                            "feed_title": feed.title,
                            "refreshed_at": refreshed_at,
                        },
                    }
                    for episode in feed.episodes
                ]
                _, new_episode_rows = await repo.create_or_update_episodes_batch(
                    subscription_id=subscription.id,
                    episodes_data=episodes_payload,
                )

                last_fetched = ensure_timezone_aware_fetch_time(
                    subscription.last_fetched_at,
                )
                transcription_episode_ids: list[int] = []
                for saved_episode in new_episode_rows:
                    published_at = ensure_timezone_aware_fetch_time(
                        saved_episode.published_at,
                    )
                    if last_fetched and published_at and published_at > last_fetched:
                        transcription_episode_ids.append(saved_episode.id)

                await repo.update_subscription_fetch_time(
                    subscription.id,
                    feed.last_fetched,
                )

                if new_episode_rows:
                    logger.info(
                        "Refreshed subscription %s (%s), %s new episodes",
                        subscription.id,
                        subscription.title,
                        len(new_episode_rows),
                    )

                return {
                    "refreshed": 1,
                    "new_episodes": len(new_episode_rows),
                    "transcription_episode_ids": transcription_episode_ids,
                }
            finally:
                await parser.close()

    async def process_opml_subscription_episodes(
        self,
        *,
        subscription_id: int,
        user_id: int,
        source_url: str,
    ) -> dict:
        repo = PodcastSubscriptionRepository(self.session)
        parser = SecureRSSParser(user_id)

        try:
            success, feed, error = await parser.fetch_and_parse_feed(source_url)
            if not success:
                logger.warning(
                    "OPML background parse failed for subscription=%s, url=%s: %s",
                    subscription_id,
                    source_url,
                    error,
                )
                return {
                    "status": "error",
                    "subscription_id": subscription_id,
                    "source_url": source_url,
                    "error": error,
                }

            episodes_payload = [
                {
                    "title": episode.title,
                    "description": episode.description,
                    "audio_url": episode.audio_url,
                    "published_at": episode.published_at,
                    "audio_duration": episode.duration,
                    "transcript_url": episode.transcript_url,
                    "item_link": episode.link,
                    "metadata": {
                        "feed_title": feed.title,
                        "imported_via_opml": True,
                        "opml_background_parsed_at": datetime.now(
                            UTC,
                        ).isoformat(),
                    },
                }
                for episode in feed.episodes
            ]

            _, new_episodes = await repo.create_or_update_episodes_batch(
                subscription_id=subscription_id,
                episodes_data=episodes_payload,
            )

            metadata = {
                "author": feed.author,
                "language": feed.language,
                "categories": feed.categories,
                "explicit": feed.explicit,
                "image_url": feed.image_url,
                "podcast_type": feed.podcast_type,
                "link": feed.link,
                "total_episodes": len(feed.episodes),
                "platform": feed.platform,
            }
            await repo.update_subscription_metadata(subscription_id, metadata)
            await repo.update_subscription_fetch_time(
                subscription_id,
                feed.last_fetched,
            )

            return {
                "status": "success",
                "subscription_id": subscription_id,
                "source_url": source_url,
                "processed_episodes": len(episodes_payload),
                "new_episodes": len(new_episodes),
            }
        finally:
            await parser.close()
