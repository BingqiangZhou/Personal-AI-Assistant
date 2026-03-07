"""Admin service helpers for subscription management pages and actions."""

import asyncio
import html
import logging
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import HTTPException
from sqlalchemy import and_, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.audit import log_admin_action
from app.admin.models import SystemSettings
from app.domains.podcast.services.subscription_service import PodcastSubscriptionService
from app.domains.subscription.models import (
    Subscription,
    SubscriptionStatus,
    UpdateFrequency,
    UserSubscription,
)
from app.domains.subscription.services import SubscriptionService
from app.domains.user.models import User
from app.shared.schemas import SubscriptionCreate


logger = logging.getLogger(__name__)


class AdminSubscriptionsService:
    """Build admin subscription page context and execute admin actions."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_page_context(
        self,
        *,
        page: int,
        per_page: int,
        status_filter: str | None,
        search_query: str | None,
        user_filter: str | None,
    ) -> dict:
        query = (
            select(Subscription, func.count(UserSubscription.id).label("subscriber_count"))
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .group_by(Subscription.id)
        )

        if status_filter and status_filter in {"active", "inactive", "error", "pending"}:
            status_map = {
                "active": SubscriptionStatus.ACTIVE,
                "inactive": SubscriptionStatus.INACTIVE,
                "error": SubscriptionStatus.ERROR,
                "pending": SubscriptionStatus.PENDING,
            }
            query = query.where(Subscription.status == status_map[status_filter])

        if search_query and search_query.strip():
            query = query.where(Subscription.title.ilike(f"%{search_query.strip()}%"))

        if user_filter and user_filter.strip():
            user_query = select(User.id).where(User.username.ilike(f"%{user_filter.strip()}%"))
            user_result = await self.db.execute(user_query)
            user_ids = [row[0] for row in user_result.fetchall()]
            if user_ids:
                query = query.where(UserSubscription.user_id.in_(user_ids))
            else:
                return self._empty_context(
                    page=page,
                    per_page=per_page,
                    status_filter=status_filter,
                    search_query=search_query,
                    user_filter=user_filter,
                )

        count_query = select(func.count()).select_from(query.subquery())
        total_count_result = await self.db.execute(count_query)
        total_count = total_count_result.scalar() or 0

        total_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1
        offset = (page - 1) * per_page
        result = await self.db.execute(
            query.order_by(Subscription.created_at.desc()).limit(per_page).offset(offset)
        )
        subscriptions = result.all()

        next_update_by_subscription = await self._load_next_update_map(subscriptions)
        frequency_defaults = await self._load_frequency_defaults(total_count)

        return {
            "subscriptions": subscriptions,
            "page": page,
            "per_page": per_page,
            "total_count": total_count,
            "total_pages": total_pages,
            "default_frequency": frequency_defaults["default_frequency"],
            "default_update_time": frequency_defaults["default_update_time"],
            "default_day_of_week": frequency_defaults["default_day_of_week"],
            "status_filter": status_filter or "",
            "search_query": search_query or "",
            "user_filter": user_filter or "",
            "next_update_by_subscription": next_update_by_subscription,
        }

    async def _load_next_update_map(self, subscriptions) -> dict[int, object]:
        next_update_by_subscription: dict[int, object] = {}
        if not subscriptions:
            return next_update_by_subscription

        subscription_ids = [sub_row[0].id for sub_row in subscriptions]
        user_sub_rows = (
            await self.db.execute(
                select(UserSubscription)
                .where(
                    UserSubscription.subscription_id.in_(subscription_ids),
                    not UserSubscription.is_archived,
                )
                .order_by(
                    UserSubscription.subscription_id,
                    UserSubscription.updated_at.desc(),
                    UserSubscription.id.desc(),
                )
            )
        ).scalars().all()

        for user_sub in user_sub_rows:
            if user_sub.subscription_id not in next_update_by_subscription:
                next_update_by_subscription[user_sub.subscription_id] = (
                    user_sub.computed_next_update_at
                )

        return next_update_by_subscription

    async def _load_frequency_defaults(self, total_count: int) -> dict[str, object]:
        defaults = {
            "default_frequency": UpdateFrequency.HOURLY.value,
            "default_update_time": "00:00",
            "default_day_of_week": 1,
        }
        if total_count <= 0:
            return defaults

        freq_result = await self.db.execute(
            select(
                UserSubscription.update_frequency,
                UserSubscription.update_time,
                UserSubscription.update_day_of_week,
            )
            .where(UserSubscription.update_frequency.isnot(None))
            .group_by(
                UserSubscription.update_frequency,
                UserSubscription.update_time,
                UserSubscription.update_day_of_week,
            )
            .order_by(func.count().desc())
            .limit(1)
        )
        row = freq_result.first()
        if not row:
            return defaults

        defaults["default_frequency"] = row[0] or UpdateFrequency.HOURLY.value
        defaults["default_update_time"] = row[1] or "00:00"
        defaults["default_day_of_week"] = row[2] or 1
        return defaults

    def _empty_context(
        self,
        *,
        page: int,
        per_page: int,
        status_filter: str | None,
        search_query: str | None,
        user_filter: str | None,
    ) -> dict:
        return {
            "subscriptions": [],
            "page": page,
            "per_page": per_page,
            "total_count": 0,
            "total_pages": 0,
            "default_frequency": UpdateFrequency.HOURLY.value,
            "default_update_time": "00:00",
            "default_day_of_week": 1,
            "status_filter": status_filter or "",
            "search_query": search_query or "",
            "user_filter": user_filter or "",
            "next_update_by_subscription": {},
        }

    async def update_frequency(
        self,
        *,
        request,
        user,
        update_frequency: str,
        update_time: str | None,
        update_day: int | None,
    ) -> dict:
        if update_frequency not in [
            UpdateFrequency.HOURLY.value,
            UpdateFrequency.DAILY.value,
            UpdateFrequency.WEEKLY.value,
        ]:
            raise HTTPException(status_code=400, detail="Invalid update frequency")

        if update_frequency in [UpdateFrequency.DAILY.value, UpdateFrequency.WEEKLY.value]:
            if not update_time:
                raise HTTPException(
                    status_code=400,
                    detail="Update time is required for DAILY and WEEKLY frequency",
                )
            try:
                hour, minute = map(int, update_time.split(":"))
                if not (0 <= hour <= 23 and 0 <= minute <= 59):
                    raise ValueError
            except (ValueError, AttributeError) as err:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid time format. Use HH:MM",
                ) from err

        day_of_week = None
        if update_frequency == UpdateFrequency.WEEKLY.value:
            if not update_day or not (1 <= update_day <= 7):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid day of week. Must be 1-7",
                )
            day_of_week = update_day

        settings_data = {
            "update_frequency": update_frequency,
            "update_time": (
                update_time
                if update_frequency
                in [UpdateFrequency.DAILY.value, UpdateFrequency.WEEKLY.value]
                else None
            ),
            "update_day_of_week": (
                day_of_week if update_frequency == UpdateFrequency.WEEKLY.value else None
            ),
        }

        setting_result = await self.db.execute(
            select(SystemSettings).where(SystemSettings.key == "rss.frequency_settings")
        )
        setting = setting_result.scalar_one_or_none()
        if setting:
            setting.value = settings_data
        else:
            self.db.add(
                SystemSettings(
                    key="rss.frequency_settings",
                    value=settings_data,
                    description="RSS subscription update frequency settings",
                    category="subscription",
                )
            )

        user_subscriptions = (
            await self.db.execute(
                select(UserSubscription)
                .join(Subscription, Subscription.id == UserSubscription.subscription_id)
                .where(Subscription.source_type.in_(["rss", "podcast-rss"]))
            )
        ).scalars().all()

        update_count = 0
        for user_sub in user_subscriptions:
            user_sub.update_frequency = settings_data["update_frequency"]
            user_sub.update_time = settings_data["update_time"]
            user_sub.update_day_of_week = settings_data["update_day_of_week"]
            update_count += 1

        await self.db.commit()
        await log_admin_action(
            db=self.db,
            user_id=user.id,
            username=user.username,
            action="update",
            resource_type="subscription_frequency",
            resource_name=f"All user subscriptions ({update_count})",
            details=settings_data,
            request=request,
        )
        return {
            "success": True,
            "message": f"Updated frequency settings for {update_count} user subscriptions",
        }

    async def edit_subscription(
        self,
        *,
        request,
        user,
        sub_id: int,
        title: str | None,
        source_url: str | None,
    ) -> dict | None:
        result = await self.db.execute(select(Subscription).where(Subscription.id == sub_id))
        subscription = result.scalar_one_or_none()
        if not subscription:
            return None

        if title is not None:
            subscription.title = title
        if source_url is not None:
            subscription.source_url = source_url

        from app.domains.subscription.parsers.feed_parser import (
            FeedParserConfig,
            parse_feed_url,
        )

        config = FeedParserConfig(
            max_entries=10,
            strip_html=True,
            strict_mode=False,
            log_raw_feed=False,
        )

        try:
            test_result = await parse_feed_url(subscription.source_url, config=config)
            if test_result and test_result.success and test_result.entries:
                subscription.status = SubscriptionStatus.ACTIVE
                subscription.error_message = None
            else:
                subscription.status = SubscriptionStatus.ERROR
                subscription.error_message = (
                    test_result.errors[0]
                    if test_result and test_result.errors
                    else "No entries found or invalid feed"
                )
        except Exception as exc:  # noqa: BLE001
            subscription.status = SubscriptionStatus.ERROR
            subscription.error_message = str(exc)

        await self.db.commit()
        await self.db.refresh(subscription)
        await log_admin_action(
            db=self.db,
            user_id=user.id,
            username=user.username,
            action="update",
            resource_type="subscription",
            resource_id=sub_id,
            resource_name=subscription.title,
            details={
                "title": title,
                "source_url": source_url,
                "status": subscription.status,
                "error_message": subscription.error_message,
            },
            request=request,
        )
        return {
            "success": True,
            "status": subscription.status,
            "error_message": subscription.error_message,
        }

    async def test_subscription_url(self, *, source_url: str, username: str) -> tuple[dict, int]:
        from app.domains.subscription.parsers.feed_parser import (
            FeedParseOptions,
            FeedParser,
            FeedParserConfig,
        )

        config = FeedParserConfig(
            max_entries=10000,
            strip_html=True,
            strict_mode=False,
            log_raw_feed=False,
        )
        options = FeedParseOptions(strip_html_content=True, include_raw_metadata=False)
        parser = FeedParser(config)
        start_time = time.time()
        try:
            result = await parser.parse_feed(source_url, options=options)
            response_time_ms = int((time.time() - start_time) * 1000)
            if not result.success or result.has_errors():
                error_messages = [err.message for err in result.errors] if result.errors else []
                return {
                    "success": False,
                    "message": f"RSS feed test failed: {error_messages[0] if error_messages else 'Failed to parse feed'}",
                    "error_message": error_messages[0] if error_messages else "Failed to parse feed",
                }, 400

            logger.info("RSS feed test successful for %s by user %s", source_url, username)
            return {
                "success": True,
                "message": "RSS feed test successful",
                "feed_title": result.feed_info.title or "Untitled",
                "feed_description": result.feed_info.description or "",
                "entry_count": len(result.entries),
                "response_time_ms": response_time_ms,
            }, 200
        finally:
            await parser.close()

    async def test_all_subscriptions(self, *, request, user) -> dict:
        from app.domains.subscription.parsers.feed_parser import (
            FeedParserConfig,
            parse_feed_url,
        )

        result = await self.db.execute(
            select(Subscription).order_by(Subscription.created_at.desc())
        )
        subscriptions = result.scalars().all()
        if not subscriptions:
            return {
                "success": True,
                "message": "娌℃湁RSS璁㈤槄闇€瑕佹祴璇?",
                "total_count": 0,
                "success_count": 0,
                "failed_count": 0,
                "disabled_count": 0,
                "failed_items": [],
            }

        config = FeedParserConfig(
            max_entries=10,
            strip_html=True,
            strict_mode=False,
            log_raw_feed=False,
        )

        async def test_single_subscription(subscription: Subscription, timeout: int = 15):
            try:
                start_time = time.time()
                result = await asyncio.wait_for(
                    parse_feed_url(subscription.source_url, config=config),
                    timeout=timeout,
                )
                response_time_ms = int((time.time() - start_time) * 1000)
                if result and result.success and result.entries:
                    return {
                        "id": subscription.id,
                        "title": subscription.title,
                        "source_url": subscription.source_url,
                        "success": True,
                        "response_time_ms": response_time_ms,
                    }
                error_msg = (
                    result.errors[0]
                    if result and result.errors
                    else "No entries found or invalid feed"
                )
                return {
                    "id": subscription.id,
                    "title": subscription.title,
                    "source_url": subscription.source_url,
                    "success": False,
                    "error": error_msg,
                }
            except asyncio.TimeoutError:
                return {
                    "id": subscription.id,
                    "title": subscription.title,
                    "source_url": subscription.source_url,
                    "success": False,
                    "error": f"Timeout after {timeout} seconds",
                }
            except Exception as exc:  # noqa: BLE001
                return {
                    "id": subscription.id,
                    "title": subscription.title,
                    "source_url": subscription.source_url,
                    "success": False,
                    "error": str(exc),
                }

        semaphore = asyncio.Semaphore(5)

        async def test_with_semaphore(subscription):
            async with semaphore:
                return await test_single_subscription(subscription)

        test_results = await asyncio.gather(
            *[test_with_semaphore(sub) for sub in subscriptions],
            return_exceptions=True,
        )

        success_count = 0
        failed_count = 0
        disabled_count = 0
        failed_items = []
        subscriptions_to_disable: list[int] = []

        for i, result in enumerate(test_results):
            if isinstance(result, Exception):
                subscription = subscriptions[i]
                failed_count += 1
                failed_items.append(
                    {
                        "id": subscription.id,
                        "title": subscription.title,
                        "source_url": subscription.source_url,
                        "error": f"Unexpected error: {result}",
                    }
                )
                if subscription.status == SubscriptionStatus.ACTIVE:
                    subscriptions_to_disable.append(subscription.id)
                continue
            if result["success"]:
                success_count += 1
            else:
                failed_count += 1
                failed_items.append(
                    {
                        "id": result["id"],
                        "title": result["title"],
                        "source_url": result["source_url"],
                        "error": result["error"],
                    }
                )
                subscription = subscriptions[i]
                if subscription.status == SubscriptionStatus.ACTIVE:
                    subscriptions_to_disable.append(subscription.id)

        if subscriptions_to_disable:
            await self.db.execute(
                update(Subscription)
                .where(Subscription.id.in_(subscriptions_to_disable))
                .values(status=SubscriptionStatus.ERROR)
            )
            await self.db.commit()
            disabled_count = len(subscriptions_to_disable)

        total_count = len(subscriptions)
        await log_admin_action(
            db=self.db,
            user_id=user.id,
            username=user.username,
            action="test_all",
            resource_type="subscription",
            resource_name="All RSS subscriptions",
            details={
                "total_count": total_count,
                "success_count": success_count,
                "failed_count": failed_count,
                "disabled_count": disabled_count,
            },
            request=request,
        )
        return {
            "success": True,
            "message": f"娴嬭瘯瀹屾垚: {success_count}/{total_count} 閫氳繃, {failed_count} 澶辫触, {disabled_count} 宸茬鐢?",
            "total_count": total_count,
            "success_count": success_count,
            "failed_count": failed_count,
            "disabled_count": disabled_count,
            "failed_items": failed_items,
        }

    async def delete_subscription(self, *, request, user, sub_id: int) -> dict | None:
        result = await self.db.execute(select(Subscription).where(Subscription.id == sub_id))
        subscription = result.scalar_one_or_none()
        if not subscription:
            return None

        resource_name = subscription.title
        if subscription.source_type == "podcast-rss":
            from app.domains.podcast.models import (
                PodcastConversation,
                PodcastEpisode,
                PodcastPlaybackState,
                TranscriptionTask,
            )

            ep_result = await self.db.execute(
                select(PodcastEpisode.id).where(PodcastEpisode.subscription_id == sub_id)
            )
            episode_ids = [row[0] for row in ep_result.fetchall()]
            if episode_ids:
                await self.db.execute(
                    delete(PodcastConversation).where(
                        PodcastConversation.episode_id.in_(episode_ids)
                    )
                )
                await self.db.execute(
                    delete(PodcastPlaybackState).where(
                        PodcastPlaybackState.episode_id.in_(episode_ids)
                    )
                )
                await self.db.execute(
                    delete(TranscriptionTask).where(
                        TranscriptionTask.episode_id.in_(episode_ids)
                    )
                )
            await self.db.execute(
                delete(PodcastEpisode).where(PodcastEpisode.subscription_id == sub_id)
            )

        await self.db.execute(delete(Subscription).where(Subscription.id == sub_id))
        await self.db.commit()
        await log_admin_action(
            db=self.db,
            user_id=user.id,
            username=user.username,
            action="delete",
            resource_type="subscription",
            resource_id=sub_id,
            resource_name=resource_name,
            request=request,
        )
        return {"success": True}

    async def refresh_subscription(self, *, request, user, sub_id: int) -> dict | None:
        result = await self.db.execute(select(Subscription).where(Subscription.id == sub_id))
        subscription = result.scalar_one_or_none()
        if not subscription:
            return None

        subscription.last_fetched_at = datetime.now(timezone.utc)
        await self.db.commit()
        await self.db.refresh(subscription)
        await log_admin_action(
            db=self.db,
            user_id=user.id,
            username=user.username,
            action="update",
            resource_type="subscription",
            resource_id=sub_id,
            resource_name=subscription.title,
            details={"action": "refresh"},
            request=request,
        )
        return {"success": True}

    async def batch_refresh_subscriptions(self, *, request, user) -> None:
        body = await request.json()
        ids = body.get("ids", [])
        if not ids:
            raise HTTPException(status_code=400, detail="No subscription IDs provided")
        ids = [int(id_) for id_ in ids]

        result = await self.db.execute(
            select(Subscription).where(Subscription.id.in_(ids))
        )
        subscriptions = result.scalars().all()
        for subscription in subscriptions:
            subscription.last_fetched_at = datetime.now(timezone.utc)

        await self.db.commit()
        await log_admin_action(
            db=self.db,
            user_id=user.id,
            username=user.username,
            action="batch_refresh",
            resource_type="subscription",
            details={"count": len(subscriptions), "ids": ids},
            request=request,
        )

    async def batch_toggle_subscriptions(self, *, request, user) -> None:
        body = await request.json()
        ids = body.get("ids", [])
        if not ids:
            raise HTTPException(status_code=400, detail="No subscription IDs provided")
        ids = [int(id_) for id_ in ids]

        result = await self.db.execute(
            select(Subscription).where(Subscription.id.in_(ids))
        )
        subscriptions = result.scalars().all()
        for subscription in subscriptions:
            subscription.is_active = not subscription.is_active

        await self.db.commit()
        await log_admin_action(
            db=self.db,
            user_id=user.id,
            username=user.username,
            action="batch_toggle",
            resource_type="subscription",
            details={"count": len(subscriptions), "ids": ids},
            request=request,
        )

    async def batch_delete_subscriptions(self, *, request, user) -> None:
        body = await request.json()
        ids = body.get("ids", [])
        if not ids:
            raise HTTPException(status_code=400, detail="No subscription IDs provided")
        ids = [int(id_) for id_ in ids]

        result = await self.db.execute(
            select(Subscription).where(Subscription.id.in_(ids))
        )
        subscriptions = result.scalars().all()

        from app.domains.podcast.models import (
            PodcastConversation,
            PodcastEpisode,
            PodcastPlaybackState,
            TranscriptionTask,
        )

        for subscription in subscriptions:
            sub_id = subscription.id
            if subscription.source_type == "podcast-rss":
                ep_result = await self.db.execute(
                    select(PodcastEpisode.id).where(PodcastEpisode.subscription_id == sub_id)
                )
                episode_ids = [row[0] for row in ep_result.fetchall()]
                if episode_ids:
                    await self.db.execute(
                        delete(PodcastConversation).where(
                            PodcastConversation.episode_id.in_(episode_ids)
                        )
                    )
                    await self.db.execute(
                        delete(PodcastPlaybackState).where(
                            PodcastPlaybackState.episode_id.in_(episode_ids)
                        )
                    )
                    await self.db.execute(
                        delete(TranscriptionTask).where(
                            TranscriptionTask.episode_id.in_(episode_ids)
                        )
                    )
                await self.db.execute(
                    delete(PodcastEpisode).where(PodcastEpisode.subscription_id == sub_id)
                )
            await self.db.execute(delete(Subscription).where(Subscription.id == sub_id))

        await self.db.commit()
        await log_admin_action(
            db=self.db,
            user_id=user.id,
            username=user.username,
            action="batch_delete",
            resource_type="subscription",
            details={"count": len(subscriptions), "ids": ids},
            request=request,
        )

    async def export_subscriptions_opml(self, *, request, user) -> tuple[str, str]:
        service = SubscriptionService(self.db, user_id=user.id)
        opml_content = await service.generate_opml_content(user_id=None)
        await log_admin_action(
            db=self.db,
            user_id=user.id,
            username=user.username,
            action="export_opml",
            resource_type="subscription",
            details={"format": "opml", "filename": "stella.opml"},
            request=request,
        )
        return opml_content, "stella.opml"

    async def import_subscriptions_opml(
        self,
        *,
        request,
        user,
        opml_content: str,
    ) -> tuple[dict, int]:
        from app.domains.podcast.tasks.opml_import import (
            process_opml_subscription_episodes,
        )

        max_title_length = 255
        max_description_length = 2000

        def normalize_feed_url(feed_url: str) -> str:
            url = feed_url.strip()
            if url.startswith("feed://"):
                return f"https://{url[len('feed://'):]}"
            return url

        async def parse_outline_element(outline: ET.Element) -> SubscriptionCreate | None:
            xml_url = normalize_feed_url(outline.get("xmlUrl", ""))
            if not xml_url:
                return None

            title = outline.get("title") or outline.get("text") or ""
            description = outline.get("description") or ""
            if title:
                title = html.unescape(title)
            if description:
                description = html.unescape(description)
            if not title:
                try:
                    parsed = urlparse(xml_url)
                    title = parsed.netloc or xml_url
                except Exception:
                    title = xml_url

            if not xml_url.startswith(("http://", "https://")):
                return None

            title = title.strip()[:max_title_length]
            description = description.strip()[:max_description_length] if description else ""
            return SubscriptionCreate(
                source_url=xml_url,
                title=title,
                source_type="podcast-rss",
                description=description,
                image_url=None,
            )

        async def parse_opml_with_etree(content: str) -> list[SubscriptionCreate]:
            subscriptions: list[SubscriptionCreate] = []
            root = ET.fromstring(content)
            namespaces = {"opml": "http://opml.org/spec2", "": ""}
            body = root.find(".//opml:body", namespaces) or root.find(".//body")
            if body is None:
                return []
            for outline in body.iter():
                tag_name = outline.tag.split("}")[1] if "}" in outline.tag else outline.tag
                if tag_name == "outline":
                    sub_data = await parse_outline_element(outline)
                    if sub_data:
                        subscriptions.append(sub_data)
            return subscriptions

        async def parse_opml_with_regex(content: str) -> list[SubscriptionCreate]:
            subscriptions: list[SubscriptionCreate] = []

            def extract_attr(tag: str, attr_name: str) -> str:
                pattern = rf'{attr_name}\s*=\s*(["\'])([^\1]*?)\1(?=\s|/?>)'
                match = re.search(pattern, tag, re.IGNORECASE)
                return match.group(2) if match else ""

            outline_pattern = re.compile(
                r"<outline\s+[^>]*?xmlUrl\s*=\s*[\"'][^\"']+[\"'][^>]*?/?>",
                re.IGNORECASE,
            )

            for match in outline_pattern.finditer(content):
                tag = match.group(0)
                xml_url = normalize_feed_url(extract_attr(tag, "xmlUrl"))
                if not xml_url or not xml_url.startswith(("http://", "https://")):
                    continue

                title = extract_attr(tag, "title") or extract_attr(tag, "text")
                description = extract_attr(tag, "description")
                if title:
                    title = html.unescape(title)
                if description:
                    description = html.unescape(description)
                if not title:
                    try:
                        parsed = urlparse(xml_url)
                        title = parsed.netloc or xml_url
                    except Exception:
                        title = xml_url

                subscriptions.append(
                    SubscriptionCreate(
                        source_url=xml_url,
                        title=title.strip()[:max_title_length],
                        source_type="podcast-rss",
                        description=(
                            description.strip()[:max_description_length]
                            if description
                            else ""
                        ),
                        image_url=None,
                    )
                )
            return subscriptions

        try:
            subscriptions_data = await parse_opml_with_etree(opml_content)
        except ET.ParseError:
            subscriptions_data = await parse_opml_with_regex(opml_content)

        unique_subscriptions: list[SubscriptionCreate] = []
        seen_urls: set[str] = set()
        for sub in subscriptions_data:
            if sub.source_url in seen_urls:
                continue
            seen_urls.add(sub.source_url)
            unique_subscriptions.append(sub)
        subscriptions_data = unique_subscriptions

        if not subscriptions_data:
            return {
                "success": False,
                "message": "No valid RSS subscriptions found in OPML file",
            }, 400

        podcast_service = PodcastSubscriptionService(self.db, user_id=user.id)
        import_started_at = datetime.now(timezone.utc).isoformat()

        results = []
        success_count = 0
        updated_count = 0
        skipped_count = 0
        error_count = 0
        queued_episode_tasks = 0
        total_episodes_created = 0

        for sub_data in subscriptions_data:
            try:
                existing = await podcast_service.repo.get_subscription_by_url(
                    user.id, sub_data.source_url
                )
                if existing:
                    skipped_count += 1
                    results.append(
                        {
                            "source_url": sub_data.source_url,
                            "title": sub_data.title,
                            "status": "skipped",
                            "id": existing.id,
                            "message": f"Subscription already exists: {existing.title}",
                        }
                    )
                    continue

                global_existing_stmt = select(Subscription.id).where(
                    and_(
                        Subscription.source_url == sub_data.source_url,
                        Subscription.source_type == "podcast-rss",
                    )
                )
                global_existing_result = await self.db.execute(global_existing_stmt)
                existed_globally = global_existing_result.scalar_one_or_none() is not None

                subscription = await podcast_service.repo.create_or_update_subscription(
                    user_id=user.id,
                    feed_url=sub_data.source_url,
                    title=sub_data.title,
                    description=sub_data.description,
                    custom_name=None,
                    metadata={
                        "imported_via_opml": True,
                        "opml_imported_at": import_started_at,
                    },
                )

                task = process_opml_subscription_episodes.delay(
                    subscription_id=subscription.id,
                    user_id=user.id,
                    source_url=sub_data.source_url,
                )
                queued_episode_tasks += 1

                status = "updated" if existed_globally else "success"
                if existed_globally:
                    updated_count += 1
                else:
                    success_count += 1

                results.append(
                    {
                        "source_url": sub_data.source_url,
                        "title": sub_data.title,
                        "status": status,
                        "id": subscription.id,
                        "message": "Subscription imported. Episode parsing queued in background.",
                        "background_task_id": task.id,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                error_count += 1
                results.append(
                    {
                        "source_url": sub_data.source_url,
                        "title": sub_data.title,
                        "status": "error",
                        "message": str(exc),
                    }
                )

        await log_admin_action(
            db=self.db,
            user_id=user.id,
            username=user.username,
            action="import_opml",
            resource_type="subscription",
            details={
                "total": len(subscriptions_data),
                "success": success_count,
                "updated": updated_count,
                "skipped": skipped_count,
                "errors": error_count,
                "total_episodes_created": total_episodes_created,
                "queued_episode_tasks": queued_episode_tasks,
            },
            request=request,
        )

        return {
            "success": True,
            "message": (
                f"Import completed: {success_count} added, {updated_count} updated, "
                f"{skipped_count} skipped, {error_count} failed. "
                f"Episode parsing is running in background for {queued_episode_tasks} subscriptions."
            ),
            "results": {
                "total": len(subscriptions_data),
                "success": success_count,
                "updated": updated_count,
                "skipped": skipped_count,
                "errors": error_count,
                "total_episodes_created": total_episodes_created,
                "queued_episode_tasks": queued_episode_tasks,
            },
            "details": results,
        }, 200
