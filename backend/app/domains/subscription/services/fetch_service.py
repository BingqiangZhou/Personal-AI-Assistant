"""Feed fetching workflows for subscriptions."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from app.domains.subscription.models import SubscriptionStatus
from app.domains.subscription.parsers.feed_parser import (
    FeedParseOptions,
    FeedParser,
    FeedParserConfig,
)
from app.domains.subscription.parsers.feed_schemas import FeedParseResult, ParseErrorCode

from .common import SubscriptionServiceSupport


logger = logging.getLogger(__name__)


class SubscriptionFetchService:
    """Handle feed parsing and item upsert workflows."""

    def __init__(self, support: SubscriptionServiceSupport):
        self.support = support
        self.user_id = support.user_id
        self.repo = support.repo

    async def fetch_subscription(self, sub_id: int) -> dict[str, Any]:
        sub = await self.repo.get_subscription_by_id(self.user_id, sub_id)
        if not sub:
            raise ValueError("Subscription not found")
        if sub.source_type != "rss":
            raise ValueError("Only RSS subscriptions support manual fetch")

        config = FeedParserConfig(
            max_entries=50,
            strip_html=True,
            strict_mode=False,
            log_raw_feed=False,
        )
        options = FeedParseOptions(strip_html_content=True, include_raw_metadata=False)
        parser = FeedParser(config)

        try:
            result: FeedParseResult = await parser.parse_feed(sub.source_url, options=options)
            if not result.success and result.has_errors():
                critical_errors = [
                    error
                    for error in result.errors
                    if error.code in (ParseErrorCode.NETWORK_ERROR, ParseErrorCode.PARSE_ERROR)
                ]
                if critical_errors:
                    error_msgs = "; ".join(error.message for error in critical_errors)
                    await self.repo.update_fetch_status(sub.id, SubscriptionStatus.ERROR, error_msgs)
                    raise ValueError(f"Feed parsing failed: {error_msgs}")

            new_items = 0
            updated_items = 0
            latest_published_at: datetime | None = None

            for entry in result.entries:
                try:
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
                    if item.created_at == item.updated_at:
                        new_items += 1
                    else:
                        updated_items += 1

                    if entry.published_at and (
                        latest_published_at is None or entry.published_at > latest_published_at
                    ):
                        latest_published_at = entry.published_at
                except Exception as exc:
                    logger.warning("Error processing entry %s: %s", entry.id, exc)
                    if config.strict_mode:
                        raise

            status = SubscriptionStatus.ACTIVE
            error_msg = None
            if result.has_warnings():
                logger.warning("Warnings parsing feed %s: %s", sub.source_url, result.warnings)
                if result.warnings:
                    error_msg = "; ".join(result.warnings)

            await self.repo.update_fetch_status(sub.id, status, error_msg, latest_published_at)
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
        except Exception as exc:
            logger.error("Error fetching subscription %s: %s", sub_id, exc)
            await self.repo.update_fetch_status(sub.id, SubscriptionStatus.ERROR, str(exc))
            raise
        finally:
            await parser.close()

    async def fetch_all_subscriptions(self) -> list[dict[str, Any]]:
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
                results.append(await self.fetch_subscription(sub.id))
            except Exception as exc:
                results.append({"subscription_id": sub.id, "status": "error", "error": str(exc)})
        return results