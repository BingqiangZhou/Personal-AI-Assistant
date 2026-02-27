"""
鎾鏁版嵁璁块棶灞?- Podcast Repository
"""

import logging
from collections.abc import Mapping
from datetime import date, datetime, timedelta, timezone
from inspect import isawaitable
from time import perf_counter
from typing import Any

from sqlalchemy import and_, case, desc, func, or_, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import attributes, joinedload

from app.core.datetime_utils import sanitize_published_date
from app.core.redis import PodcastRedis
from app.domains.podcast.models import (
    PodcastEpisode,
    PodcastPlaybackState,
    PodcastQueue,
    PodcastQueueItem,
    PodcastDailyReport,
)
from app.domains.subscription.models import Subscription, UserSubscription
from app.domains.user.models import User


logger = logging.getLogger(__name__)


class PodcastRepository:
    """
    鎾鏁版嵁鎸佷箙鍖栨搷浣?
    """

    def __init__(self, db: AsyncSession, redis: PodcastRedis | None = None):
        self.db = db
        self.redis = redis or PodcastRedis()
        self._queue_position_step = 1024
        self._queue_position_compaction_threshold = 1_000_000

    @staticmethod
    def _active_user_subscription_filters(user_id: int) -> tuple[Any, Any]:
        """Common filter for active user-subscription mappings."""
        return (
            UserSubscription.user_id == user_id,
            UserSubscription.is_archived.is_(False),
        )

    @staticmethod
    def _podcast_source_type_filter() -> Any:
        return Subscription.source_type.in_(["podcast-rss", "rss"])

    # === 璁㈤槄绠＄悊 ===

    async def create_or_update_subscription(
        self,
        user_id: int,
        feed_url: str,
        title: str,
        description: str = "",
        custom_name: str | None = None,
        metadata: dict | None = None,
    ) -> Subscription:
        """
        鍒涘缓鎴栨洿鏂版挱瀹㈣闃?

        With many-to-many relationship:
        1. Check if subscription exists globally by URL
        2. If exists and user already subscribed: update the subscription
        3. If exists but user not subscribed: create UserSubscription mapping
        4. If not exists: create both Subscription and UserSubscription
        """
        from app.admin.models import SystemSettings
        from app.domains.subscription.models import UpdateFrequency

        # 鏌ユ壘鐜版湁璁㈤槄锛堝叏灞€鏌ユ壘锛?
        stmt = select(Subscription).where(
            and_(
                Subscription.source_url == feed_url,
                Subscription.source_type == "podcast-rss",
            )
        )
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()

        # Get global RSS frequency settings
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

        if subscription:
            # Check if user is already subscribed
            user_sub_stmt = select(UserSubscription).where(
                and_(
                    UserSubscription.user_id == user_id,
                    UserSubscription.subscription_id == subscription.id,
                )
            )
            user_sub_result = await self.db.execute(user_sub_stmt)
            user_sub = user_sub_result.scalar_one_or_none()

            if not user_sub:
                # Create UserSubscription mapping
                user_sub = UserSubscription(
                    user_id=user_id,
                    subscription_id=subscription.id,
                    update_frequency=update_frequency,
                    update_time=update_time,
                    update_day_of_week=update_day_of_week,
                )
                self.db.add(user_sub)
            elif user_sub.is_archived:
                # Unarchive if it was archived
                user_sub.is_archived = False

            # 鏇存柊璁㈤槄鍏冩暟鎹?
            subscription.title = custom_name or title
            subscription.description = description
            subscription.updated_at = datetime.now(timezone.utc)
            # 鏇存柊鍏冩暟鎹?- 浣跨敤鏂板瓧鍏稿璞＄‘淇?SQLAlchemy 妫€娴嬪埌鍙樻洿
            if metadata:
                # NEW: Also store image_url in the direct column
                if "image_url" in metadata:
                    subscription.image_url = metadata.get("image_url")
                existing_config = dict(subscription.config or {})
                # 鍚堝苟鏂版棫鍏冩暟鎹紝淇濈暀鍘熸湁鐨勫叾浠栭厤缃?
                existing_config.update(metadata)
                subscription.config = existing_config
                # 鏄惧紡鏍囪瀛楁宸蹭慨鏀癸紝纭繚 JSON 鍒楀彉鏇磋鎸佷箙鍖?
                attributes.flag_modified(subscription, "config")
        else:
            # 鍒涘缓鏂拌闃咃紙鏃爑ser_id锛?
            subscription = Subscription(
                source_url=feed_url,
                source_type="podcast-rss",  # 鍖哄垎鍘熺敓RSS鍜屾挱瀹SS
                title=custom_name or title,
                description=description,
                status="active",
                fetch_interval=3600,  # 榛樿1灏忔椂锛堢锛?
                image_url=(metadata or {}).get(
                    "image_url"
                ),  # NEW: Also store in direct column
                config=metadata or {},
            )
            self.db.add(subscription)
            await self.db.flush()  # Get the ID

            # Create UserSubscription mapping
            user_sub = UserSubscription(
                user_id=user_id,
                subscription_id=subscription.id,
                update_frequency=update_frequency,
                update_time=update_time,
                update_day_of_week=update_day_of_week,
            )
            self.db.add(user_sub)

        await self.db.commit()
        await self.db.refresh(subscription)
        return subscription

    async def get_user_subscriptions(self, user_id: int) -> list[Subscription]:
        """Get all podcast subscriptions for a user."""
        stmt = (
            select(Subscription)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                    self._podcast_source_type_filter(),
                )
            )
            .order_by(Subscription.created_at.desc())
        )

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_subscription_by_id(
        self, user_id: int, sub_id: int
    ) -> Subscription | None:
        """鑾峰彇鐗瑰畾璁㈤槄"""
        stmt = (
            select(Subscription)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                    Subscription.id == sub_id,
                    self._podcast_source_type_filter(),
                )
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_subscription_by_url(
        self, user_id: int, feed_url: str
    ) -> Subscription | None:
        """閫氳繃URL鑾峰彇璁㈤槄"""
        stmt = (
            select(Subscription)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                    Subscription.source_url == feed_url,
                    self._podcast_source_type_filter(),
                )
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_subscription_by_id_direct(
        self, subscription_id: int
    ) -> Subscription | None:
        """
        Get subscription by ID directly, without user subscription filtering.
        This is used by background tasks that need to access subscriptions globally.
        """
        stmt = select(Subscription).where(
            and_(
                Subscription.id == subscription_id,
                Subscription.source_type.in_(["podcast-rss", "rss"]),
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    # === 鍗曢泦绠＄悊 ===

    async def create_or_update_episode(
        self,
        subscription_id: int,
        title: str,
        description: str,
        audio_url: str,
        published_at: datetime,
        audio_duration: int | None = None,
        transcript_url: str | None = None,
        item_link: str | None = None,
        metadata: dict | None = None,
    ) -> PodcastEpisode:
        """
        鍒涘缓鎴栨洿鏂版挱瀹㈠崟闆?
        浣跨敤item_link浣滀负鍞竴鏍囪瘑
        """
        # 棣栧厛灏濊瘯鎸?item_link 鏌ユ壘
        stmt = select(PodcastEpisode).where(PodcastEpisode.item_link == item_link)
        result = await self.db.execute(stmt)
        episode = result.scalar_one_or_none()

        if episode:
            # 鎵惧埌锛屾洿鏂板瓧娈?
            episode.title = title
            episode.description = description
            episode.audio_url = audio_url
            episode.published_at = sanitize_published_date(published_at)
            episode.audio_duration = audio_duration
            episode.transcript_url = transcript_url
            episode.updated_at = datetime.now(timezone.utc)
            # Also update subscription_id if different (handles duplicate subscriptions)
            if episode.subscription_id != subscription_id:
                episode.subscription_id = subscription_id
            if metadata:
                current_metadata = episode.metadata_json or {}
                episode.metadata_json = {**current_metadata, **metadata}
            is_new = False
        else:
            # 涓嶅瓨鍦紝鍒涘缓鏂拌褰?
            episode = PodcastEpisode(
                subscription_id=subscription_id,
                title=title,
                description=description,
                audio_url=audio_url,
                published_at=sanitize_published_date(published_at),
                audio_duration=audio_duration,
                transcript_url=transcript_url,
                item_link=item_link,
                status="pending_summary",  # 绛夊緟AI鎬荤粨
                metadata_json=metadata or {},
            )
            self.db.add(episode)
            is_new = True

        await self.db.commit()
        await self.db.refresh(episode)

        # 缂撳瓨鍓嶅嚑澶?episode metadata
        if is_new or episode.ai_summary:
            await self._cache_episode_metadata(episode)

        return episode, is_new

    async def create_or_update_episodes_batch(
        self,
        subscription_id: int,
        episodes_data: list[dict[str, Any]],
    ) -> tuple[list[PodcastEpisode], list[PodcastEpisode]]:
        """
        Batch upsert episodes with a single commit.

        Status rule:
        - New episodes are initialized as ``pending_summary``.
        - Existing episode status is never overwritten.
        """
        if not episodes_data:
            return [], []

        item_links = list(
            {data["item_link"] for data in episodes_data if data.get("item_link")}
        )
        existing_by_item_link: dict[str, PodcastEpisode] = {}

        if item_links:
            existing_stmt = select(PodcastEpisode).where(
                PodcastEpisode.item_link.in_(item_links)
            )
            existing_result = await self.db.execute(existing_stmt)
            existing_episodes = list(existing_result.scalars().all())
            existing_by_item_link = {
                episode.item_link: episode
                for episode in existing_episodes
                if episode.item_link
            }

        processed_episodes: list[PodcastEpisode] = []
        new_episodes: list[PodcastEpisode] = []
        now = datetime.now(timezone.utc)

        for data in episodes_data:
            title = data.get("title") or "Untitled"
            description = data.get("description") or ""
            audio_url = data.get("audio_url") or ""
            transcript_url = data.get("transcript_url")
            audio_duration = data.get("audio_duration")
            item_link = data.get("item_link")
            metadata = data.get("metadata") or {}
            published_at_raw = data.get("published_at") or now
            published_at = sanitize_published_date(published_at_raw)

            episode = existing_by_item_link.get(item_link) if item_link else None
            if episode:
                episode.title = title
                episode.description = description
                episode.audio_url = audio_url
                episode.published_at = published_at
                episode.audio_duration = audio_duration
                episode.transcript_url = transcript_url
                episode.updated_at = now
                if episode.subscription_id != subscription_id:
                    episode.subscription_id = subscription_id
                if metadata:
                    current_metadata = episode.metadata_json or {}
                    episode.metadata_json = {**current_metadata, **metadata}
                processed_episodes.append(episode)
                continue

            new_episode = PodcastEpisode(
                subscription_id=subscription_id,
                title=title,
                description=description,
                audio_url=audio_url,
                published_at=published_at,
                audio_duration=audio_duration,
                transcript_url=transcript_url,
                item_link=item_link,
                status="pending_summary",
                metadata_json=metadata,
            )
            self.db.add(new_episode)
            processed_episodes.append(new_episode)
            new_episodes.append(new_episode)

        await self.db.commit()

        for episode in new_episodes:
            await self.db.refresh(episode)
            await self._cache_episode_metadata(episode)

        return processed_episodes, new_episodes

    async def get_unsummarized_episodes(
        self, subscription_id: int | None = None
    ) -> list[PodcastEpisode]:
        """Get episodes that are pending AI summaries."""
        stmt = select(PodcastEpisode).where(
            and_(
                PodcastEpisode.ai_summary.is_(None),
                PodcastEpisode.status == "pending_summary",
            )
        )
        if subscription_id:
            stmt = stmt.where(PodcastEpisode.subscription_id == subscription_id)

        stmt = stmt.order_by(PodcastEpisode.published_at.desc())
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_subscription_episodes(
        self, subscription_id: int, limit: int = 20
    ) -> list[PodcastEpisode]:
        """Get episodes for one subscription."""
        stmt = (
            select(PodcastEpisode)
            .options(joinedload(PodcastEpisode.subscription))
            .where(PodcastEpisode.subscription_id == subscription_id)
            .order_by(desc(PodcastEpisode.published_at))
            .limit(limit)
        )

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def count_subscription_episodes(self, subscription_id: int) -> int:
        """Count episodes for a subscription using efficient COUNT query."""
        stmt = select(func.count(PodcastEpisode.id)).where(
            PodcastEpisode.subscription_id == subscription_id
        )
        result = await self.db.execute(stmt)
        return result.scalar() or 0

    async def get_episode_by_id(
        self, episode_id: int, user_id: int | None = None
    ) -> PodcastEpisode | None:
        """鑾峰彇鍗曢泦璇︽儏"""
        stmt = (
            select(PodcastEpisode)
            .options(joinedload(PodcastEpisode.subscription))
            .where(PodcastEpisode.id == episode_id)
        )
        if user_id:
            # 纭繚鏄鐢ㄦ埛鐨勮闃?- use UserSubscription join
            stmt = (
                stmt.join(Subscription)
                .join(
                    UserSubscription,
                    UserSubscription.subscription_id == Subscription.id,
                )
                .where(
                    and_(
                        *self._active_user_subscription_filters(user_id),
                    )
                )
            )

        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_episode_by_item_link(
        self, subscription_id: int, item_link: str
    ) -> PodcastEpisode | None:
        """閫氳繃item_link鏌ユ壘鍗曢泦"""
        stmt = select(PodcastEpisode).where(
            and_(
                PodcastEpisode.subscription_id == subscription_id,
                PodcastEpisode.item_link == item_link,
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    # === AI鎬荤粨鐩稿叧 ===

    async def update_ai_summary(
        self,
        episode_id: int,
        summary: str,
        version: str = "v1",
        confidence: float | None = None,
        transcript_used: bool = False,
    ) -> PodcastEpisode:
        """鏇存柊AI鎬荤粨"""
        episode = await self.get_episode_by_id(episode_id)
        if not episode:
            raise ValueError(f"Episode {episode_id} not found")

        episode.ai_summary = summary
        episode.summary_version = version
        episode.status = "summarized"
        if confidence:
            episode.ai_confidence_score = confidence

        metadata = episode.metadata_json or {}
        metadata["transcript_used"] = transcript_used
        metadata["summarized_at"] = datetime.now(timezone.utc).isoformat()
        episode.metadata = metadata

        await self.db.commit()
        await self.db.refresh(episode)

        # 鏇存柊缂撳瓨
        await self.redis.set_ai_summary(episode_id, summary, version)

        return episode

    async def mark_summary_failed(self, episode_id: int, error: str) -> None:
        """鏍囪鎬荤粨澶辫触"""
        episode = await self.get_episode_by_id(episode_id)
        if episode:
            episode.status = "summary_failed"
            metadata = episode.metadata_json or {}
            metadata["summary_error"] = error
            metadata["failed_at"] = datetime.now(timezone.utc).isoformat()
            episode.metadata_json = metadata
            await self.db.commit()

    # === 鎾斁鐘舵€佺鐞?===

    async def get_playback_state(
        self, user_id: int, episode_id: int
    ) -> PodcastPlaybackState | None:
        """Get playback state for one user and episode."""
        stmt = select(PodcastPlaybackState).where(
            and_(
                PodcastPlaybackState.user_id == user_id,
                PodcastPlaybackState.episode_id == episode_id,
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_playback_states_batch(
        self, user_id: int, episode_ids: list[int]
    ) -> dict[int, PodcastPlaybackState]:
        """
        Batch fetch playback states for multiple episodes.

        Returns a dictionary mapping episode_id to PodcastPlaybackState.
        Episodes without a playback state will not be in the dictionary.
        """
        if not episode_ids:
            return {}

        stmt = select(PodcastPlaybackState).where(
            and_(
                PodcastPlaybackState.user_id == user_id,
                PodcastPlaybackState.episode_id.in_(episode_ids),
            )
        )
        result = await self.db.execute(stmt)
        states = result.scalars().all()

        # Create a dictionary mapping episode_id to state
        return {state.episode_id: state for state in states}

    async def get_user_default_playback_rate(self, user_id: int) -> float:
        """Get user's global default playback rate."""
        stmt = select(User.default_playback_rate).where(User.id == user_id)
        result = await self.db.execute(stmt)
        value = result.scalar_one_or_none()
        return float(value) if value is not None else 1.0

    async def get_subscription_playback_rate_preference(
        self,
        user_id: int,
        subscription_id: int,
    ) -> float | None:
        """Get user-specific playback rate preference for a subscription."""
        stmt = select(UserSubscription.playback_rate_preference).where(
            and_(
                *self._active_user_subscription_filters(user_id),
                UserSubscription.subscription_id == subscription_id,
            )
        )
        result = await self.db.execute(stmt)
        value = result.scalar_one_or_none()
        return float(value) if value is not None else None

    async def get_effective_playback_rate(
        self,
        user_id: int,
        subscription_id: int | None = None,
    ) -> dict[str, Any]:
        """Get effective playback rate with priority: subscription > global > default."""
        global_rate = await self.get_user_default_playback_rate(user_id)
        subscription_rate: float | None = None
        source = "global"
        effective_rate = global_rate

        if subscription_id is not None:
            subscription_rate = await self.get_subscription_playback_rate_preference(
                user_id=user_id,
                subscription_id=subscription_id,
            )
            if subscription_rate is not None:
                source = "subscription"
                effective_rate = subscription_rate
            elif global_rate == 1.0:
                source = "default"
        elif global_rate == 1.0:
            source = "default"

        return {
            "global_playback_rate": global_rate,
            "subscription_playback_rate": subscription_rate,
            "effective_playback_rate": effective_rate,
            "source": source,
        }

    async def apply_playback_rate_preference(
        self,
        user_id: int,
        playback_rate: float,
        apply_to_subscription: bool,
        subscription_id: int | None = None,
    ) -> dict[str, Any]:
        """Apply global or subscription playback-rate preference."""
        if apply_to_subscription:
            if subscription_id is None:
                raise ValueError("SUBSCRIPTION_ID_REQUIRED")

            stmt = select(UserSubscription).where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                    UserSubscription.subscription_id == subscription_id,
                )
            )
            result = await self.db.execute(stmt)
            user_sub = result.scalar_one_or_none()
            if user_sub is None:
                raise ValueError("SUBSCRIPTION_NOT_FOUND")

            user_sub.playback_rate_preference = playback_rate
            await self.db.commit()
            return await self.get_effective_playback_rate(user_id, subscription_id)

        user_stmt = select(User).where(User.id == user_id)
        user_result = await self.db.execute(user_stmt)
        user = user_result.scalar_one_or_none()
        if user is None:
            raise ValueError("USER_NOT_FOUND")

        user.default_playback_rate = playback_rate

        if subscription_id is not None:
            sub_stmt = select(UserSubscription).where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                    UserSubscription.subscription_id == subscription_id,
                )
            )
            sub_result = await self.db.execute(sub_stmt)
            user_sub = sub_result.scalar_one_or_none()
            if user_sub is None:
                raise ValueError("SUBSCRIPTION_NOT_FOUND")
            user_sub.playback_rate_preference = None

        await self.db.commit()
        return await self.get_effective_playback_rate(user_id, subscription_id)

    async def get_episodes_counts_batch(
        self, subscription_ids: list[int]
    ) -> dict[int, int]:
        """
        Batch fetch episode counts for multiple subscriptions.

        鎵归噺鑾峰彇澶氫釜璁㈤槄鐨勫墽闆嗚鏁?

        Args:
            subscription_ids: List of subscription IDs

        Returns:
            Dictionary mapping subscription_id to episode count
        """
        if not subscription_ids:
            return {}

        # Use GROUP BY to count episodes for all subscriptions in one query
        stmt = (
            select(PodcastEpisode.subscription_id, func.count(PodcastEpisode.id))
            .where(PodcastEpisode.subscription_id.in_(subscription_ids))
            .group_by(PodcastEpisode.subscription_id)
        )

        result = await self.db.execute(stmt)
        return {row[0]: row[1] for row in result.all()}

    async def get_subscription_episodes_batch(
        self, subscription_ids: list[int], limit_per_subscription: int = 3
    ) -> dict[int, list[PodcastEpisode]]:
        """
        Batch fetch recent episodes for multiple subscriptions.

        鎵归噺鑾峰彇澶氫釜璁㈤槄鐨勬渶鏂板墽闆?

        Args:
            subscription_ids: List of subscription IDs
            limit_per_subscription: Number of recent episodes per subscription

        Returns:
            Dictionary mapping subscription_id to list of episodes
        """
        if not subscription_ids:
            return {}

        # Get all episodes for these subscriptions, ordered by published_at
        stmt = (
            select(PodcastEpisode)
            .where(PodcastEpisode.subscription_id.in_(subscription_ids))
            .order_by(desc(PodcastEpisode.published_at))
        )

        result = await self.db.execute(stmt)
        all_episodes = result.scalars().all()

        # Group episodes by subscription_id and limit per subscription
        episodes_by_sub = {}
        for ep in all_episodes:
            if ep.subscription_id not in episodes_by_sub:
                episodes_by_sub[ep.subscription_id] = []

            if len(episodes_by_sub[ep.subscription_id]) < limit_per_subscription:
                episodes_by_sub[ep.subscription_id].append(ep)

        return episodes_by_sub

    async def update_playback_progress(
        self,
        user_id: int,
        episode_id: int,
        position: int,
        is_playing: bool = False,
        playback_rate: float = 1.0,
    ) -> PodcastPlaybackState:
        """鏇存柊鎾斁杩涘害"""
        state = await self.get_playback_state(user_id, episode_id)

        if state:
            state.current_position = position
            state.is_playing = is_playing
            state.playback_rate = playback_rate
            if is_playing:
                state.play_count += 1
            state.last_updated_at = datetime.now(timezone.utc)
        else:
            state = PodcastPlaybackState(
                user_id=user_id,
                episode_id=episode_id,
                current_position=position,
                is_playing=is_playing,
                playback_rate=playback_rate,
                play_count=1 if is_playing else 0,
                last_updated_at=datetime.now(timezone.utc),
            )
            self.db.add(state)

        await self.db.commit()
        await self.db.refresh(state)

        # 涔熺紦瀛樺埌Redis浣滀负蹇€熻鍙?
        if self.redis:
            await self.redis.set_user_progress(user_id, episode_id, position / 100)

        return state

    # === 缁熻涓庣紦瀛樿緟鍔?===

    # === Queue management ===

    async def get_or_create_queue(self, user_id: int) -> PodcastQueue:
        """Get or create a per-user podcast queue."""
        stmt = select(PodcastQueue).where(PodcastQueue.user_id == user_id)
        result = await self.db.execute(stmt)
        queue = result.scalar_one_or_none()
        if queue:
            return queue

        queue = PodcastQueue(user_id=user_id, revision=0)
        self.db.add(queue)
        await self.db.flush()
        return queue

    async def get_queue_with_items(self, user_id: int) -> PodcastQueue:
        """Get queue and all items with related episode data."""
        queue = await self.get_or_create_queue(user_id)
        stmt = (
            select(PodcastQueue)
            .options(
                joinedload(PodcastQueue.items)
                .joinedload(PodcastQueueItem.episode)
                .joinedload(PodcastEpisode.subscription),
                joinedload(PodcastQueue.current_episode),
            )
            .where(PodcastQueue.id == queue.id)
        )
        result = await self.db.execute(stmt)
        return result.unique().scalar_one()

    @staticmethod
    def _sorted_queue_items(queue: PodcastQueue) -> list[PodcastQueueItem]:
        return sorted(queue.items, key=lambda item: (item.position, item.id))

    def _queue_needs_compaction(self, items: list[PodcastQueueItem]) -> bool:
        if not items:
            return False

        head_position = items[0].position
        tail_position = items[-1].position
        threshold = self._queue_position_compaction_threshold
        return head_position <= -threshold or tail_position >= threshold

    async def _rewrite_queue_positions(
        self,
        items: list[PodcastQueueItem],
        *,
        start: int = 0,
        step: int | None = None,
    ) -> None:
        """Rewrite positions in two phases to avoid unique(position) conflicts."""
        if not items:
            return

        position_step = step or self._queue_position_step
        temp_base = self._queue_position_compaction_threshold + (
            len(items) * position_step
        )
        for idx, item in enumerate(items):
            item.position = temp_base + idx
        await self.db.flush()

        for idx, item in enumerate(items):
            item.position = start + (idx * position_step)
        await self.db.flush()

    @staticmethod
    def _touch_queue(queue: PodcastQueue) -> None:
        queue.revision = (queue.revision or 0) + 1
        queue.updated_at = datetime.now(timezone.utc)

    async def _ensure_current_at_head(
        self,
        queue: PodcastQueue,
        ordered_items: list[PodcastQueueItem],
    ) -> bool:
        """Enforce queue invariant: current_episode_id always points to head item."""
        if not ordered_items:
            if queue.current_episode_id is not None:
                queue.current_episode_id = None
                return True
            return False

        current_id = queue.current_episode_id
        if current_id is None:
            queue.current_episode_id = ordered_items[0].episode_id
            return True

        current_item = next(
            (item for item in ordered_items if item.episode_id == current_id),
            None,
        )
        if current_item is None:
            queue.current_episode_id = ordered_items[0].episode_id
            return True

        head_item = ordered_items[0]
        if current_item.id == head_item.id:
            return False

        current_item.position = head_item.position - self._queue_position_step
        await self.db.flush()
        return True

    def _queue_operation_log(
        self,
        operation: str,
        *,
        user_id: int,
        queue_size: int,
        revision_before: int,
        revision_after: int,
        elapsed_ms: float,
    ) -> None:
        logger.debug(
            "[Queue] operation=%s user_id=%s queue_size=%s revision_before=%s revision_after=%s elapsed_ms=%.2f",
            operation,
            user_id,
            queue_size,
            revision_before,
            revision_after,
            elapsed_ms,
        )

    async def add_or_move_to_tail(
        self,
        user_id: int,
        episode_id: int,
        max_items: int = 500,
    ) -> PodcastQueue:
        """Add episode into queue, or move existing one to the tail."""
        started_at = perf_counter()
        queue = await self.get_queue_with_items(user_id)
        revision_before = queue.revision or 0
        ordered_items = self._sorted_queue_items(queue)
        existing = next(
            (item for item in ordered_items if item.episode_id == episode_id),
            None,
        )
        changed = False

        if existing is None and len(ordered_items) >= max_items:
            raise ValueError("QUEUE_LIMIT_EXCEEDED")

        tail_position = ordered_items[-1].position if ordered_items else 0

        if existing is not None:
            if (
                queue.current_episode_id != episode_id
                and existing.position != tail_position
            ):
                existing.position = tail_position + self._queue_position_step
                await self.db.flush()
                changed = True
        else:
            self.db.add(
                PodcastQueueItem(
                    queue_id=queue.id,
                    episode_id=episode_id,
                    position=tail_position + self._queue_position_step
                    if ordered_items
                    else 0,
                )
            )
            await self.db.flush()
            changed = True

        ordered_items = self._sorted_queue_items(queue)
        if await self._ensure_current_at_head(queue, ordered_items):
            changed = True

        ordered_items = self._sorted_queue_items(queue)
        if self._queue_needs_compaction(ordered_items):
            await self._rewrite_queue_positions(
                ordered_items,
                step=self._queue_position_step,
            )
            changed = True

        if changed:
            self._touch_queue(queue)
            await self.db.commit()

        self._queue_operation_log(
            "add_or_move_to_tail",
            user_id=user_id,
            queue_size=len(self._sorted_queue_items(queue)),
            revision_before=revision_before,
            revision_after=queue.revision or revision_before,
            elapsed_ms=(perf_counter() - started_at) * 1000,
        )
        return await self.get_queue_with_items(user_id)

    async def remove_item(self, user_id: int, episode_id: int) -> PodcastQueue:
        """Remove queue item by episode id. Idempotent."""
        started_at = perf_counter()
        queue = await self.get_queue_with_items(user_id)
        revision_before = queue.revision or 0
        ordered_items = self._sorted_queue_items(queue)

        target = next(
            (item for item in ordered_items if item.episode_id == episode_id),
            None,
        )
        if not target:
            return queue

        await self.db.delete(target)
        await self.db.flush()
        ordered_items = self._sorted_queue_items(queue)
        changed = True

        if queue.current_episode_id == episode_id:
            queue.current_episode_id = (
                ordered_items[0].episode_id if ordered_items else None
            )

        if await self._ensure_current_at_head(queue, ordered_items):
            changed = True

        ordered_items = self._sorted_queue_items(queue)
        if self._queue_needs_compaction(ordered_items):
            await self._rewrite_queue_positions(
                ordered_items,
                step=self._queue_position_step,
            )
            changed = True

        if changed:
            self._touch_queue(queue)
            await self.db.commit()
            # expire_on_commit=False means the identity map is stale after commit.
            # Expire the queue so get_queue_with_items re-fetches fresh items.
            self.db.expire(queue)

        self._queue_operation_log(
            "remove_item",
            user_id=user_id,
            queue_size=len(self._sorted_queue_items(queue)),
            revision_before=revision_before,
            revision_after=queue.revision or revision_before,
            elapsed_ms=(perf_counter() - started_at) * 1000,
        )
        return await self.get_queue_with_items(user_id)

    async def activate_episode(
        self,
        user_id: int,
        episode_id: int,
        max_items: int = 500,
    ) -> PodcastQueue:
        """Ensure episode in queue, move to head, and set as current in one transaction."""
        started_at = perf_counter()
        queue = await self.get_queue_with_items(user_id)
        revision_before = queue.revision or 0
        ordered_items = self._sorted_queue_items(queue)
        existing = next(
            (item for item in ordered_items if item.episode_id == episode_id),
            None,
        )
        changed = False

        if existing is None and len(ordered_items) >= max_items:
            raise ValueError("QUEUE_LIMIT_EXCEEDED")

        if existing is None:
            head_position = ordered_items[0].position if ordered_items else 0
            self.db.add(
                PodcastQueueItem(
                    queue_id=queue.id,
                    episode_id=episode_id,
                    position=head_position - self._queue_position_step
                    if ordered_items
                    else 0,
                )
            )
            await self.db.flush()
            changed = True
            ordered_items = self._sorted_queue_items(queue)
        else:
            head_item = ordered_items[0] if ordered_items else None
            if head_item is not None and existing.id != head_item.id:
                existing.position = head_item.position - self._queue_position_step
                await self.db.flush()
                changed = True
                ordered_items = self._sorted_queue_items(queue)

        if queue.current_episode_id != episode_id:
            queue.current_episode_id = episode_id
            changed = True

        if await self._ensure_current_at_head(queue, ordered_items):
            changed = True

        ordered_items = self._sorted_queue_items(queue)
        if self._queue_needs_compaction(ordered_items):
            await self._rewrite_queue_positions(
                ordered_items,
                step=self._queue_position_step,
            )
            changed = True

        if changed:
            self._touch_queue(queue)
            await self.db.commit()

        self._queue_operation_log(
            "activate_episode",
            user_id=user_id,
            queue_size=len(self._sorted_queue_items(queue)),
            revision_before=revision_before,
            revision_after=queue.revision or revision_before,
            elapsed_ms=(perf_counter() - started_at) * 1000,
        )
        return await self.get_queue_with_items(user_id)

    async def reorder_items(
        self, user_id: int, ordered_episode_ids: list[int]
    ) -> PodcastQueue:
        """Reorder queue items. Payload must exactly match existing item set."""
        started_at = perf_counter()
        queue = await self.get_queue_with_items(user_id)
        revision_before = queue.revision or 0
        ordered_items = self._sorted_queue_items(queue)

        current_ids = [item.episode_id for item in ordered_items]
        if len(set(ordered_episode_ids)) != len(ordered_episode_ids):
            raise ValueError("INVALID_REORDER_PAYLOAD")
        if set(current_ids) != set(ordered_episode_ids):
            raise ValueError("INVALID_REORDER_PAYLOAD")
        if len(current_ids) != len(ordered_episode_ids):
            raise ValueError("INVALID_REORDER_PAYLOAD")

        changed = current_ids != ordered_episode_ids
        desired_current = ordered_episode_ids[0] if ordered_episode_ids else None
        if changed:
            item_map = {item.episode_id: item for item in ordered_items}
            reordered_items = [
                item_map[episode_id] for episode_id in ordered_episode_ids
            ]
            await self._rewrite_queue_positions(
                reordered_items,
                step=self._queue_position_step,
            )

        if queue.current_episode_id != desired_current:
            queue.current_episode_id = desired_current
            changed = True

        if changed:
            self._touch_queue(queue)
            await self.db.commit()

        self._queue_operation_log(
            "reorder_items",
            user_id=user_id,
            queue_size=len(current_ids),
            revision_before=revision_before,
            revision_after=queue.revision or revision_before,
            elapsed_ms=(perf_counter() - started_at) * 1000,
        )
        return await self.get_queue_with_items(user_id)

    async def set_current(self, user_id: int, episode_id: int) -> PodcastQueue:
        """Set current queue episode and move it to queue head."""
        started_at = perf_counter()
        queue = await self.get_queue_with_items(user_id)
        revision_before = queue.revision or 0
        ordered_items = self._sorted_queue_items(queue)
        target = next(
            (item for item in ordered_items if item.episode_id == episode_id),
            None,
        )
        if target is None:
            raise ValueError("EPISODE_NOT_IN_QUEUE")

        changed = False
        head_item = ordered_items[0] if ordered_items else None
        if head_item is not None and target.id != head_item.id:
            target.position = head_item.position - self._queue_position_step
            await self.db.flush()
            changed = True

        if queue.current_episode_id != episode_id:
            queue.current_episode_id = episode_id
            changed = True

        ordered_items = self._sorted_queue_items(queue)
        if await self._ensure_current_at_head(queue, ordered_items):
            changed = True

        ordered_items = self._sorted_queue_items(queue)
        if self._queue_needs_compaction(ordered_items):
            await self._rewrite_queue_positions(
                ordered_items,
                step=self._queue_position_step,
            )
            changed = True

        if changed:
            self._touch_queue(queue)
            await self.db.commit()

        self._queue_operation_log(
            "set_current",
            user_id=user_id,
            queue_size=len(self._sorted_queue_items(queue)),
            revision_before=revision_before,
            revision_after=queue.revision or revision_before,
            elapsed_ms=(perf_counter() - started_at) * 1000,
        )
        return await self.get_queue_with_items(user_id)

    async def complete_current(self, user_id: int) -> PodcastQueue:
        """Complete current item: remove it and advance to the next item."""
        started_at = perf_counter()
        queue = await self.get_queue_with_items(user_id)
        revision_before = queue.revision or 0
        ordered_items = self._sorted_queue_items(queue)

        if not ordered_items:
            return queue

        target_index = 0
        if queue.current_episode_id is not None:
            current_index = next(
                (
                    idx
                    for idx, item in enumerate(ordered_items)
                    if item.episode_id == queue.current_episode_id
                ),
                None,
            )
            if current_index is not None:
                target_index = current_index

        target = ordered_items[target_index]
        next_episode_id: int | None = None
        if len(ordered_items) > 1:
            next_index = target_index + 1
            if next_index < len(ordered_items):
                next_episode_id = ordered_items[next_index].episode_id

        await self.db.delete(target)
        await self.db.flush()
        ordered_items = self._sorted_queue_items(queue)
        if next_episode_id is None and ordered_items:
            next_episode_id = ordered_items[0].episode_id
        elif next_episode_id is not None and all(
            item.episode_id != next_episode_id for item in ordered_items
        ):
            next_episode_id = ordered_items[0].episode_id if ordered_items else None
        queue.current_episode_id = next_episode_id
        changed = True

        if await self._ensure_current_at_head(queue, ordered_items):
            changed = True

        ordered_items = self._sorted_queue_items(queue)
        if self._queue_needs_compaction(ordered_items):
            await self._rewrite_queue_positions(
                ordered_items,
                step=self._queue_position_step,
            )
            changed = True

        if changed:
            self._touch_queue(queue)
            await self.db.commit()

        self._queue_operation_log(
            "complete_current",
            user_id=user_id,
            queue_size=len(self._sorted_queue_items(queue)),
            revision_before=revision_before,
            revision_after=queue.revision or revision_before,
            elapsed_ms=(perf_counter() - started_at) * 1000,
        )
        return queue

    async def _cache_episode_metadata(self, episode: PodcastEpisode):
        """缂撳瓨episode鍏冩暟鎹埌Redis"""
        if not self.redis:
            return

        metadata = {
            "id": str(episode.id),
            "title": episode.title,
            "audio_url": episode.audio_url,
            "duration": str(episode.audio_duration or 0),
            "has_summary": "yes" if episode.ai_summary else "no",
        }

        await self.redis.set_episode_metadata(episode.id, metadata)

    # === 鏂板鏂规硶鏀寔鍒嗛〉銆佹悳绱€佺粺璁＄瓑 ===

    async def get_user_subscriptions_paginated(
        self, user_id: int, page: int = 1, size: int = 20, filters: dict | None = None
    ) -> tuple[list[Subscription], int]:
        """鍒嗛〉鑾峰彇鐢ㄦ埛璁㈤槄"""
        query = (
            select(Subscription)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                    self._podcast_source_type_filter(),
                )
            )
        )

        # 搴旂敤杩囨护鍣?
        if filters and filters.status:
            query = query.where(Subscription.status == filters.status)

        # 璁＄畻鎬绘暟
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()

        # 搴旂敤鎺掑簭鍜屽垎椤?
        query = query.order_by(Subscription.created_at.desc())
        query = query.offset((page - 1) * size).limit(size)

        result = await self.db.execute(query)
        subscriptions = list(result.scalars().all())

        return subscriptions, total

    async def get_episodes_paginated(
        self, user_id: int, page: int = 1, size: int = 20, filters: dict | None = None
    ) -> tuple[list[PodcastEpisode], int]:
        """鍒嗛〉鑾峰彇鐢ㄦ埛鎾鍗曢泦"""
        query = (
            select(PodcastEpisode)
            .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .options(joinedload(PodcastEpisode.subscription))
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                )
            )
        )

        # 搴旂敤杩囨护鍣?
        if filters:
            if filters.subscription_id:
                query = query.where(
                    PodcastEpisode.subscription_id == filters.subscription_id
                )
            if filters.has_summary is not None:
                if filters.has_summary:
                    query = query.where(PodcastEpisode.ai_summary.isnot(None))
                else:
                    query = query.where(PodcastEpisode.ai_summary.is_(None))
            if filters.is_played is not None:
                # 鎾斁鐘舵€侀渶瑕丣OIN鎾斁璁板綍琛?
                if filters.is_played:
                    # 宸叉挱鏀撅細鎾斁杩涘害瓒呰繃90%
                    query = query.join(PodcastPlaybackState).where(
                        PodcastPlaybackState.current_position
                        >= PodcastEpisode.audio_duration * 0.9
                    )
                else:
                    # 鏈挱鏀炬垨鏈惉瀹?
                    query = query.outerjoin(PodcastPlaybackState).where(
                        or_(
                            PodcastPlaybackState.id.is_(None),
                            PodcastPlaybackState.current_position
                            < PodcastEpisode.audio_duration * 0.9,
                        )
                    )

        # 璁＄畻鎬绘暟
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()

        # 搴旂敤鎺掑簭鍜屽垎椤?
        query = query.order_by(
            PodcastEpisode.published_at.desc(),
            PodcastEpisode.id.desc(),
        )
        query = query.offset((page - 1) * size).limit(size)

        result = await self.db.execute(query)
        episodes = list(result.scalars().all())

        return episodes, total

    @staticmethod
    def _feed_count_cache_key(user_id: int) -> str:
        return f"podcast:feed:count:{user_id}"

    async def _get_feed_total_count(self, user_id: int) -> int:
        cache_key = self._feed_count_cache_key(user_id)
        cached_total = await self.redis.cache_get(cache_key)
        if cached_total is not None:
            try:
                return int(cached_total)
            except (TypeError, ValueError):
                logger.warning("Invalid cached feed total count for user %s", user_id)

        count_query = (
            select(func.count(PodcastEpisode.id))
            .select_from(PodcastEpisode)
            .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                )
            )
        )
        total_result = await self.db.execute(count_query)
        total = int(total_result.scalar() or 0)
        await self.redis.cache_set(cache_key, str(total), ttl=30)
        return total

    def _build_feed_lightweight_base_query(self, user_id: int):
        return (
            select(
                PodcastEpisode.id.label("id"),
                PodcastEpisode.subscription_id.label("subscription_id"),
                Subscription.title.label("subscription_title"),
                Subscription.image_url.label("subscription_image_url"),
                Subscription.config.label("subscription_config"),
                PodcastEpisode.title.label("title"),
                PodcastEpisode.description.label("description"),
                PodcastEpisode.ai_summary.label("ai_summary"),
                PodcastEpisode.audio_url.label("audio_url"),
                PodcastEpisode.audio_duration.label("audio_duration"),
                PodcastEpisode.audio_file_size.label("audio_file_size"),
                PodcastEpisode.published_at.label("published_at"),
                PodcastEpisode.image_url.label("image_url"),
                PodcastEpisode.item_link.label("item_link"),
                PodcastEpisode.transcript_url.label("transcript_url"),
                PodcastEpisode.summary_version.label("summary_version"),
                PodcastEpisode.ai_confidence_score.label("ai_confidence_score"),
                PodcastEpisode.play_count.label("play_count"),
                PodcastEpisode.season.label("season"),
                PodcastEpisode.episode_number.label("episode_number"),
                PodcastEpisode.explicit.label("explicit"),
                PodcastEpisode.status.label("status"),
                PodcastEpisode.metadata_json.label("metadata"),
                PodcastEpisode.created_at.label("created_at"),
                PodcastEpisode.updated_at.label("updated_at"),
                PodcastPlaybackState.current_position.label("playback_position"),
                PodcastPlaybackState.is_playing.label("is_playing"),
                PodcastPlaybackState.playback_rate.label("playback_rate"),
                PodcastPlaybackState.last_updated_at.label("last_played_at"),
            )
            .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .outerjoin(
                PodcastPlaybackState,
                and_(
                    PodcastPlaybackState.episode_id == PodcastEpisode.id,
                    PodcastPlaybackState.user_id == user_id,
                ),
            )
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                )
            )
        )

    def _build_feed_lightweight_item(self, row: Mapping[str, Any]) -> dict[str, Any]:
        row_data = dict(row)
        subscription_config = row_data.pop("subscription_config", None)
        subscription_image_url = self._normalize_optional_image_url(
            row_data.get("subscription_image_url")
        )
        config_image_url = None
        if isinstance(subscription_config, dict):
            config_image_url = self._normalize_optional_image_url(
                subscription_config.get("image_url")
            )
        effective_subscription_image = config_image_url or subscription_image_url

        playback_position = row_data.get("playback_position")
        audio_duration = row_data.get("audio_duration")
        is_played = bool(
            playback_position
            and audio_duration
            and playback_position >= audio_duration * 0.9
        )
        image_url = self._normalize_optional_image_url(row_data.get("image_url"))
        if image_url is None:
            image_url = effective_subscription_image

        return {
            "id": row_data["id"],
            "subscription_id": row_data["subscription_id"],
            "subscription_title": row_data.get("subscription_title"),
            "subscription_image_url": effective_subscription_image,
            "title": row_data["title"],
            "description": row_data.get("description"),
            "audio_url": row_data["audio_url"],
            "audio_duration": row_data.get("audio_duration"),
            "audio_file_size": row_data.get("audio_file_size"),
            "published_at": row_data["published_at"],
            "image_url": image_url,
            "item_link": row_data.get("item_link"),
            "transcript_url": row_data.get("transcript_url"),
            "transcript_content": None,
            "ai_summary": row_data.get("ai_summary"),
            "summary_version": row_data.get("summary_version"),
            "ai_confidence_score": row_data.get("ai_confidence_score"),
            "play_count": row_data.get("play_count") or 0,
            "last_played_at": row_data.get("last_played_at"),
            "season": row_data.get("season"),
            "episode_number": row_data.get("episode_number"),
            "explicit": bool(row_data.get("explicit", False)),
            "status": row_data.get("status") or "published",
            "metadata": row_data.get("metadata") or {},
            "playback_position": playback_position,
            "is_playing": bool(row_data.get("is_playing", False)),
            "playback_rate": float(row_data.get("playback_rate") or 1.0),
            "is_played": is_played,
            "created_at": row_data["created_at"],
            "updated_at": row_data.get("updated_at"),
        }

    async def get_feed_lightweight_page_paginated(
        self,
        user_id: int,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        total = await self._get_feed_total_count(user_id)
        query = self._build_feed_lightweight_base_query(user_id)
        query = query.order_by(
            desc(PodcastEpisode.published_at),
            desc(PodcastEpisode.id),
        )
        query = query.offset((page - 1) * size).limit(size)

        result = await self.db.execute(query)
        rows = result.mappings().all()
        items = [self._build_feed_lightweight_item(row) for row in rows]
        return items, total

    async def get_feed_lightweight_cursor_paginated(
        self,
        user_id: int,
        size: int = 20,
        cursor_published_at: datetime | None = None,
        cursor_episode_id: int | None = None,
    ) -> tuple[list[dict[str, Any]], int, bool, tuple[datetime, int] | None]:
        total = await self._get_feed_total_count(user_id)
        query = self._build_feed_lightweight_base_query(user_id)

        if cursor_published_at is not None and cursor_episode_id is not None:
            query = query.where(
                or_(
                    PodcastEpisode.published_at < cursor_published_at,
                    and_(
                        PodcastEpisode.published_at == cursor_published_at,
                        PodcastEpisode.id < cursor_episode_id,
                    ),
                )
            )

        query = query.order_by(
            desc(PodcastEpisode.published_at),
            desc(PodcastEpisode.id),
        ).limit(size + 1)

        result = await self.db.execute(query)
        rows = result.mappings().all()

        has_more = len(rows) > size
        trimmed_rows = rows[:size]
        items = [self._build_feed_lightweight_item(row) for row in trimmed_rows]
        next_cursor_values: tuple[datetime, int] | None = None
        if has_more and trimmed_rows:
            tail = trimmed_rows[-1]
            next_cursor_values = (tail["published_at"], tail["id"])

        return items, total, has_more, next_cursor_values

    async def get_feed_cursor_paginated(
        self,
        user_id: int,
        size: int = 20,
        cursor_published_at: datetime | None = None,
        cursor_episode_id: int | None = None,
    ) -> tuple[list[PodcastEpisode], int, bool, tuple[datetime, int] | None]:
        """Keyset-pagination feed query for better deep-page performance."""
        query = (
            select(PodcastEpisode)
            .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .options(joinedload(PodcastEpisode.subscription))
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                )
            )
        )

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar() or 0

        if cursor_published_at is not None and cursor_episode_id is not None:
            query = query.where(
                or_(
                    PodcastEpisode.published_at < cursor_published_at,
                    and_(
                        PodcastEpisode.published_at == cursor_published_at,
                        PodcastEpisode.id < cursor_episode_id,
                    ),
                )
            )

        query = query.order_by(
            desc(PodcastEpisode.published_at),
            desc(PodcastEpisode.id),
        ).limit(size + 1)

        result = await self.db.execute(query)
        rows = list(result.scalars().all())

        has_more = len(rows) > size
        episodes = rows[:size]
        next_cursor_values: tuple[datetime, int] | None = None
        if has_more and episodes:
            tail = episodes[-1]
            next_cursor_values = (tail.published_at, tail.id)

        return episodes, total, has_more, next_cursor_values

    async def get_playback_history_paginated(
        self,
        user_id: int,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[PodcastEpisode], int]:
        """Get user playback/view history ordered by latest activity."""
        query = (
            select(PodcastEpisode)
            .join(
                PodcastPlaybackState,
                and_(
                    PodcastPlaybackState.episode_id == PodcastEpisode.id,
                    PodcastPlaybackState.user_id == user_id,
                ),
            )
            .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .options(joinedload(PodcastEpisode.subscription))
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                )
            )
        )

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar() or 0

        query = query.order_by(
            PodcastPlaybackState.last_updated_at.desc(),
            PodcastEpisode.id.desc(),
        )
        query = query.offset((page - 1) * size).limit(size)

        result = await self.db.execute(query)
        episodes = list(result.unique().scalars().all())
        return episodes, total

    async def get_playback_history_cursor_paginated(
        self,
        user_id: int,
        size: int = 20,
        cursor_last_updated_at: datetime | None = None,
        cursor_episode_id: int | None = None,
    ) -> tuple[list[PodcastEpisode], int, bool, tuple[datetime, int] | None]:
        """Keyset-pagination playback history query ordered by latest activity."""
        query = (
            select(
                PodcastEpisode,
                PodcastPlaybackState.last_updated_at.label("last_updated_at"),
            )
            .join(
                PodcastPlaybackState,
                and_(
                    PodcastPlaybackState.episode_id == PodcastEpisode.id,
                    PodcastPlaybackState.user_id == user_id,
                ),
            )
            .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .options(joinedload(PodcastEpisode.subscription))
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                )
            )
        )

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar() or 0

        if cursor_last_updated_at is not None and cursor_episode_id is not None:
            query = query.where(
                or_(
                    PodcastPlaybackState.last_updated_at < cursor_last_updated_at,
                    and_(
                        PodcastPlaybackState.last_updated_at == cursor_last_updated_at,
                        PodcastEpisode.id < cursor_episode_id,
                    ),
                )
            )

        query = query.order_by(
            desc(PodcastPlaybackState.last_updated_at),
            desc(PodcastEpisode.id),
        ).limit(size + 1)

        result = await self.db.execute(query)
        rows = list(result.all())

        has_more = len(rows) > size
        trimmed_rows = rows[:size]
        episodes = [row[0] for row in trimmed_rows]

        next_cursor_values: tuple[datetime, int] | None = None
        if has_more and trimmed_rows:
            tail_episode, tail_last_updated_at = trimmed_rows[-1]
            next_cursor_values = (tail_last_updated_at, tail_episode.id)

        return episodes, total, has_more, next_cursor_values

    async def get_playback_history_lite_paginated(
        self,
        user_id: int,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        """Get lightweight playback history for profile history page."""
        query = (
            select(
                PodcastEpisode.id.label("id"),
                PodcastEpisode.subscription_id.label("subscription_id"),
                Subscription.title.label("subscription_title"),
                Subscription.image_url.label("subscription_image_url"),
                Subscription.config.label("subscription_config"),
                PodcastEpisode.title.label("title"),
                PodcastEpisode.image_url.label("image_url"),
                PodcastEpisode.audio_duration.label("audio_duration"),
                PodcastPlaybackState.current_position.label("playback_position"),
                PodcastPlaybackState.last_updated_at.label("last_played_at"),
                PodcastEpisode.published_at.label("published_at"),
            )
            .join(
                PodcastPlaybackState,
                and_(
                    PodcastPlaybackState.episode_id == PodcastEpisode.id,
                    PodcastPlaybackState.user_id == user_id,
                ),
            )
            .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                )
            )
        )

        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.db.execute(count_query)
        total = total_result.scalar() or 0

        query = query.order_by(PodcastPlaybackState.last_updated_at.desc())
        query = query.offset((page - 1) * size).limit(size)

        result = await self.db.execute(query)
        rows = result.mappings().all()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            subscription_config = item.pop("subscription_config", None)

            config_image_url = None
            if isinstance(subscription_config, dict):
                config_image_url = self._normalize_optional_image_url(
                    subscription_config.get("image_url")
                )

            subscription_image_url = self._normalize_optional_image_url(
                item.get("subscription_image_url")
            )
            item["subscription_image_url"] = config_image_url or subscription_image_url
            items.append(item)

        return items, total

    @staticmethod
    def _normalize_optional_image_url(value: Any) -> str | None:
        """Normalize image URL values and treat blank strings as missing."""
        if not isinstance(value, str):
            return None
        normalized = value.strip()
        return normalized or None

    async def search_episodes(
        self,
        user_id: int,
        query: str,
        search_in: str = "all",
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[PodcastEpisode], int]:
        """Search episodes with trgm-friendly ranking and deterministic ordering."""
        keyword = query.strip()
        if not keyword:
            return [], 0

        like_pattern = f"%{keyword}%"
        bind: Any = None
        try:
            bind = self.db.get_bind()
            if isawaitable(bind):
                bind = await bind
        except Exception:
            bind = getattr(self.db, "bind", None)
        is_postgresql = bool(bind and bind.dialect.name == "postgresql")

        def _coalesced_text(column: Any) -> Any:
            return func.coalesce(column, "")

        def _build_text_match_condition(column: Any, enable_pg_trgm: bool) -> Any:
            coalesced = _coalesced_text(column)
            ilike_condition = coalesced.ilike(like_pattern)
            if not enable_pg_trgm:
                return ilike_condition
            # Prefer pg_trgm operator for index-friendly matching on PostgreSQL.
            return or_(coalesced.op("%")(keyword), ilike_condition)

        def _build_relevance_term(
            column: Any, weight: float, enable_pg_trgm: bool
        ) -> Any:
            coalesced = _coalesced_text(column)
            if enable_pg_trgm:
                return func.similarity(coalesced, keyword) * weight
            # SQLite/MySQL fallback without pg_trgm similarity().
            return case((coalesced.ilike(like_pattern), weight), else_=0.0)

        async def _execute_search(
            enable_pg_trgm: bool,
        ) -> tuple[list[PodcastEpisode], int]:
            search_conditions: list[Any] = []
            relevance_terms: list[Any] = []

            if search_in in {"title", "all"}:
                search_conditions.append(
                    _build_text_match_condition(PodcastEpisode.title, enable_pg_trgm)
                )
                relevance_terms.append(
                    _build_relevance_term(PodcastEpisode.title, 1.0, enable_pg_trgm)
                )
            if search_in in {"description", "all"}:
                search_conditions.append(
                    _build_text_match_condition(
                        PodcastEpisode.description, enable_pg_trgm
                    )
                )
                relevance_terms.append(
                    _build_relevance_term(
                        PodcastEpisode.description, 0.7, enable_pg_trgm
                    )
                )
            if search_in in {"summary", "all"}:
                search_conditions.append(
                    _build_text_match_condition(
                        PodcastEpisode.ai_summary, enable_pg_trgm
                    )
                )
                relevance_terms.append(
                    _build_relevance_term(
                        PodcastEpisode.ai_summary, 0.9, enable_pg_trgm
                    )
                )

            if not search_conditions:
                search_conditions.append(
                    _build_text_match_condition(PodcastEpisode.title, enable_pg_trgm)
                )
                relevance_terms.append(
                    _build_relevance_term(PodcastEpisode.title, 1.0, enable_pg_trgm)
                )

            relevance_score = relevance_terms[0]
            for term in relevance_terms[1:]:
                relevance_score = relevance_score + term
            relevance_score = relevance_score.label("relevance_score")

            base_query = (
                select(PodcastEpisode, relevance_score)
                .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
                .join(
                    UserSubscription,
                    UserSubscription.subscription_id == Subscription.id,
                )
                .options(joinedload(PodcastEpisode.subscription))
                .where(
                    and_(
                        *self._active_user_subscription_filters(user_id),
                        or_(*search_conditions),
                    )
                )
            )

            count_query = select(func.count()).select_from(base_query.subquery())
            total_result = await self.db.execute(count_query)
            total = total_result.scalar() or 0

            paged_query = (
                base_query.order_by(
                    desc(relevance_score),
                    desc(PodcastEpisode.published_at),
                    desc(PodcastEpisode.id),
                )
                .offset((page - 1) * size)
                .limit(size)
            )
            result = await self.db.execute(paged_query)
            episodes = [row[0] for row in result.unique().all()]
            return episodes, total

        try:
            return await _execute_search(enable_pg_trgm=is_postgresql)
        except DBAPIError as exc:
            message = str(getattr(exc, "orig", exc)).lower()
            pg_trgm_error = (
                "similarity(" in message
                or "operator does not exist" in message
                or "pg_trgm" in message
            )
            if is_postgresql and pg_trgm_error:
                logger.warning(
                    "pg_trgm unavailable for search query; fallback to ILIKE path: %s",
                    exc,
                )
                await self.db.rollback()
                return await _execute_search(enable_pg_trgm=False)
            raise

    async def update_subscription_fetch_time(
        self, subscription_id: int, fetch_time: datetime | None = None
    ):
        """Update the last fetch timestamp for a subscription."""
        stmt = select(Subscription).where(Subscription.id == subscription_id)
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()

        if subscription:
            # 绉婚櫎鏃跺尯淇℃伅浠ュ尮閰嶆暟鎹簱鐨凾IMESTAMP WITHOUT TIME ZONE
            time_to_set = sanitize_published_date(
                fetch_time or datetime.now(timezone.utc)
            )
            subscription.last_fetched_at = time_to_set
            await self.db.commit()

    async def update_subscription_metadata(self, subscription_id: int, metadata: dict):
        """鏇存柊璁㈤槄鐨勫厓鏁版嵁閰嶇疆"""
        stmt = select(Subscription).where(Subscription.id == subscription_id)
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()

        if subscription:
            # 鍚堝苟鐜版湁閰嶇疆鍜屾柊鍏冩暟鎹?- 浣跨敤鏂板瓧鍏稿璞＄‘淇?SQLAlchemy 妫€娴嬪埌鍙樻洿
            current_config = dict(subscription.config or {})
            current_config.update(metadata)
            subscription.config = current_config
            # 鏄惧紡鏍囪瀛楁宸蹭慨鏀癸紝纭繚 JSON 鍒楀彉鏇磋鎸佷箙鍖?
            attributes.flag_modified(subscription, "config")
            subscription.updated_at = datetime.now(timezone.utc)
            await self.db.commit()

    async def get_recently_played(
        self, user_id: int, limit: int = 5
    ) -> list[dict[str, Any]]:
        """鑾峰彇鏈€杩戞挱鏀剧殑鍗曢泦"""
        stmt = (
            select(
                PodcastEpisode,
                PodcastPlaybackState.current_position,
                PodcastPlaybackState.last_updated_at,
            )
            .join(PodcastPlaybackState)
            .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .options(joinedload(PodcastEpisode.subscription))
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                    PodcastPlaybackState.last_updated_at
                    >= datetime.now(timezone.utc) - timedelta(days=7),
                )
            )
            .order_by(PodcastPlaybackState.last_updated_at.desc())
            .limit(limit)
        )

        result = await self.db.execute(stmt)
        rows = result.unique().all()

        recently_played = []
        for episode, position, last_played in rows:
            sub_title = episode.subscription.title if episode.subscription else None
            recently_played.append(
                {
                    "episode_id": episode.id,
                    "title": episode.title,
                    "subscription_title": sub_title,
                    "position": position,
                    "last_played": last_played,
                    "duration": episode.audio_duration,
                }
            )

        return recently_played

    async def get_liked_episodes(
        self, user_id: int, limit: int = 20
    ) -> list[PodcastEpisode]:
        """鑾峰彇鐢ㄦ埛鍠滄鐨勫崟闆嗭紙鎾斁瀹屾垚鐜囬珮鐨勶級"""
        # 鎾斁瀹屾垚鐜?> 80% 鐨勫崟闆?
        stmt = (
            select(PodcastEpisode)
            .join(PodcastPlaybackState)
            .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                    PodcastEpisode.audio_duration > 0,
                    PodcastPlaybackState.current_position
                    >= PodcastEpisode.audio_duration * 0.8,
                )
            )
            .order_by(PodcastPlaybackState.play_count.desc())
            .limit(limit)
        )

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_recent_play_dates(self, user_id: int, days: int = 30) -> set[date]:
        """鑾峰彇鏈€杩戞挱鏀剧殑鏃ユ湡闆嗗悎"""
        stmt = (
            select(PodcastPlaybackState.last_updated_at)
            .where(
                and_(
                    PodcastPlaybackState.user_id == user_id,
                    PodcastPlaybackState.last_updated_at
                    >= datetime.now(timezone.utc) - timedelta(days=days),
                )
            )
            .distinct()
        )

        result = await self.db.execute(stmt)
        dates = set()
        for (last_updated,) in result:
            dates.add(last_updated.date())

        return dates

    async def get_profile_stats_aggregated(self, user_id: int) -> dict[str, Any]:
        """Get lightweight profile statistics with played episodes count."""
        sub_count_stmt = (
            select(func.count(Subscription.id))
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                )
            )
        )
        sub_count_result = await self.db.execute(sub_count_stmt)
        total_subscriptions = sub_count_result.scalar() or 0

        episode_stats_stmt = select(
            func.count(PodcastEpisode.id).label("total_episodes"),
            func.sum(case((PodcastEpisode.ai_summary.isnot(None), 1), else_=0)).label(
                "summaries_generated"
            ),
            func.sum(case((PodcastEpisode.ai_summary.is_(None), 1), else_=0)).label(
                "pending_summaries"
            ),
            func.count(func.distinct(PodcastPlaybackState.episode_id)).label(
                "played_episodes"
            ),
        ).select_from(
            PodcastEpisode.__table__.join(
                Subscription.__table__,
                PodcastEpisode.subscription_id == Subscription.id,
            )
            .join(
                UserSubscription.__table__,
                and_(
                    UserSubscription.subscription_id == Subscription.id,
                    *self._active_user_subscription_filters(user_id),
                ),
            )
            .outerjoin(
                PodcastPlaybackState.__table__,
                and_(
                    PodcastPlaybackState.episode_id == PodcastEpisode.id,
                    PodcastPlaybackState.user_id == user_id,
                ),
            )
        )
        episode_stats_result = await self.db.execute(episode_stats_stmt)
        episode_stats = episode_stats_result.one()

        latest_report_stmt = (
            select(PodcastDailyReport.report_date)
            .where(PodcastDailyReport.user_id == user_id)
            .order_by(PodcastDailyReport.report_date.desc())
            .limit(1)
        )
        latest_report_result = await self.db.execute(latest_report_stmt)
        latest_report_date = latest_report_result.scalar_one_or_none()

        return {
            "total_subscriptions": total_subscriptions,
            "total_episodes": episode_stats.total_episodes or 0,
            "summaries_generated": episode_stats.summaries_generated or 0,
            "pending_summaries": episode_stats.pending_summaries or 0,
            "played_episodes": episode_stats.played_episodes or 0,
            "latest_daily_report_date": latest_report_date.isoformat() if latest_report_date else None,
        }

    async def get_user_stats_aggregated(self, user_id: int) -> dict[str, Any]:
        """
        Get aggregated user statistics using efficient single-query approach.

        Replaces the O(n*m) nested loop implementation with aggregate queries.
        """
        # Count total subscriptions via UserSubscription
        sub_count_stmt = (
            select(func.count(Subscription.id))
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                )
            )
        )
        sub_count_result = await self.db.execute(sub_count_stmt)
        total_subscriptions = sub_count_result.scalar() or 0

        # Aggregate episode statistics
        episode_stats_stmt = select(
            func.count(PodcastEpisode.id).label("total_episodes"),
            func.sum(case((PodcastEpisode.ai_summary.isnot(None), 1), else_=0)).label(
                "summaries_generated"
            ),
            func.sum(case((PodcastEpisode.ai_summary.is_(None), 1), else_=0)).label(
                "pending_summaries"
            ),
            func.coalesce(func.sum(PodcastPlaybackState.current_position), 0).label(
                "total_playtime"
            ),
        ).select_from(
            PodcastEpisode.__table__.join(
                Subscription.__table__,
                PodcastEpisode.subscription_id == Subscription.id,
            )
            .join(
                UserSubscription.__table__,
                and_(
                    UserSubscription.subscription_id == Subscription.id,
                    *self._active_user_subscription_filters(user_id),
                ),
            )
            .outerjoin(
                PodcastPlaybackState.__table__,
                and_(
                    PodcastPlaybackState.episode_id == PodcastEpisode.id,
                    PodcastPlaybackState.user_id == user_id,
                ),
            )
        )

        episode_stats_result = await self.db.execute(episode_stats_stmt)
        episode_stats = episode_stats_result.one()

        # Check for active subscriptions
        active_check_stmt = (
            select(func.count(Subscription.id))
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    *self._active_user_subscription_filters(user_id),
                    Subscription.status == "active",
                )
            )
        )
        active_check_result = await self.db.execute(active_check_stmt)
        has_active_plus = (active_check_result.scalar() or 0) > 0

        return {
            "total_subscriptions": total_subscriptions,
            "total_episodes": episode_stats.total_episodes or 0,
            "total_playtime": episode_stats.total_playtime or 0,
            "summaries_generated": episode_stats.summaries_generated or 0,
            "pending_summaries": episode_stats.pending_summaries or 0,
            "has_active_plus": has_active_plus,
        }
