"""Handlers for OPML-import episode parsing tasks."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.domains.podcast.integration.secure_rss_parser import SecureRSSParser
from app.domains.podcast.repositories import PodcastRepository


logger = logging.getLogger(__name__)


async def process_opml_subscription_episodes_handler(
    session,
    *,
    subscription_id: int,
    user_id: int,
    source_url: str,
) -> dict:
    """
    Parse and upsert episodes for one OPML subscription in background.

    Important status rule:
    - This handler must not mutate existing ``podcast_episodes.status``.
    - New rows are initialized to ``pending_summary`` by repository layer.
    """
    repo = PodcastRepository(session)
    parser = SecureRSSParser(user_id)

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

    episodes_payload: list[dict] = []
    for episode in feed.episodes:
        episodes_payload.append(
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
                    "opml_background_parsed_at": datetime.now(timezone.utc).isoformat(),
                },
            }
        )

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
    await repo.update_subscription_fetch_time(subscription_id, feed.last_fetched)

    return {
        "status": "success",
        "subscription_id": subscription_id,
        "source_url": source_url,
        "processed_episodes": len(episodes_payload),
        "new_episodes": len(new_episodes),
    }

