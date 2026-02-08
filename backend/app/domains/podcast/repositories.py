"""
播客数据访问层 - Podcast Repository
"""

import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import attributes, joinedload

from app.core.datetime_utils import sanitize_published_date
from app.core.redis import PodcastRedis
from app.domains.podcast.models import PodcastEpisode, PodcastPlaybackState
from app.domains.subscription.models import Subscription, UserSubscription


logger = logging.getLogger(__name__)


class PodcastRepository:
    """
    播客数据持久化操作
    """

    def __init__(self, db: AsyncSession, redis: PodcastRedis | None = None):
        self.db = db
        self.redis = redis or PodcastRedis()

    # === 订阅管理 ===

    async def create_or_update_subscription(
        self,
        user_id: int,
        feed_url: str,
        title: str,
        description: str = "",
        custom_name: str | None = None,
        metadata: dict | None = None
    ) -> Subscription:
        """
        创建或更新播客订阅

        With many-to-many relationship:
        1. Check if subscription exists globally by URL
        2. If exists and user already subscribed: update the subscription
        3. If exists but user not subscribed: create UserSubscription mapping
        4. If not exists: create both Subscription and UserSubscription
        """
        from app.admin.models import SystemSettings
        from app.domains.subscription.models import UpdateFrequency

        # 查找现有订阅（全局查找）
        stmt = select(Subscription).where(
            and_(
                Subscription.source_url == feed_url,
                Subscription.source_type == "podcast-rss"
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
            update_frequency = setting.value.get("update_frequency", UpdateFrequency.HOURLY.value)
            update_time = setting.value.get("update_time")
            update_day_of_week = setting.value.get("update_day_of_week")

        if subscription:
            # Check if user is already subscribed
            user_sub_stmt = select(UserSubscription).where(
                and_(
                    UserSubscription.user_id == user_id,
                    UserSubscription.subscription_id == subscription.id
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

            # 更新订阅元数据
            subscription.title = custom_name or title
            subscription.description = description
            subscription.updated_at = datetime.now(timezone.utc)
            # 更新元数据 - 使用新字典对象确保 SQLAlchemy 检测到变更
            if metadata:
                existing_config = dict(subscription.config or {})
                # 合并新旧元数据，保留原有的其他配置
                existing_config.update(metadata)
                subscription.config = existing_config
                # 显式标记字段已修改，确保 JSON 列变更被持久化
                attributes.flag_modified(subscription, 'config')
        else:
            # 创建新订阅（无user_id）
            subscription = Subscription(
                source_url=feed_url,
                source_type="podcast-rss",  # 区分原生RSS和播客RSS
                title=custom_name or title,
                description=description,
                status="active",
                fetch_interval=3600,  # 默认1小时（秒）
                config=metadata or {}
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
        """获取用户所有播客订阅"""
        stmt = (
            select(Subscription)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    UserSubscription.user_id == user_id,
                    UserSubscription.is_archived == False,
                    Subscription.source_type.in_(["podcast-rss", "rss"])
                )
            )
            .order_by(Subscription.created_at.desc())
        )

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_subscription_by_id(self, user_id: int, sub_id: int) -> Subscription | None:
        """获取特定订阅"""
        stmt = (
            select(Subscription)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    UserSubscription.user_id == user_id,
                    UserSubscription.is_archived == False,
                    Subscription.id == sub_id,
                    Subscription.source_type.in_(["podcast-rss", "rss"])
                )
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_subscription_by_url(self, user_id: int, feed_url: str) -> Subscription | None:
        """通过URL获取订阅"""
        stmt = (
            select(Subscription)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    UserSubscription.user_id == user_id,
                    UserSubscription.is_archived == False,
                    Subscription.source_url == feed_url,
                    Subscription.source_type.in_(["podcast-rss", "rss"])
                )
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_subscription_by_id_direct(self, subscription_id: int) -> Subscription | None:
        """
        Get subscription by ID directly, without user subscription filtering.
        This is used by background tasks that need to access subscriptions globally.
        """
        stmt = select(Subscription).where(
            and_(
                Subscription.id == subscription_id,
                Subscription.source_type.in_(["podcast-rss", "rss"])
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    # === 单集管理 ===

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
        metadata: dict | None = None
    ) -> PodcastEpisode:
        """
        创建或更新播客单集
        使用item_link作为唯一标识
        """
        # 首先尝试按 item_link 查找
        stmt = select(PodcastEpisode).where(
            PodcastEpisode.item_link == item_link
        )
        result = await self.db.execute(stmt)
        episode = result.scalar_one_or_none()

        if episode:
            # 找到，更新字段
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
                episode.metadata_json = {**episode.metadata_json, **metadata}
            is_new = False
        else:
            # 不存在，创建新记录
            episode = PodcastEpisode(
                subscription_id=subscription_id,
                title=title,
                description=description,
                audio_url=audio_url,
                published_at=sanitize_published_date(published_at),
                audio_duration=audio_duration,
                transcript_url=transcript_url,
                item_link=item_link,
                status="pending_summary",  # 等待AI总结
                metadata=metadata or {}
            )
            self.db.add(episode)
            is_new = True

        await self.db.commit()
        await self.db.refresh(episode)

        # 缓存前几天 episode metadata
        if is_new or episode.ai_summary:
            await self._cache_episode_metadata(episode)

        return episode, is_new

    async def get_unsummarized_episodes(self, subscription_id: int | None = None) -> list[PodcastEpisode]:
        """获取待AI总结的单集"""
        stmt = select(PodcastEpisode).where(
            and_(
                PodcastEpisode.ai_summary.is_(None),
                PodcastEpisode.status == "pending_summary"
            )
        )
        if subscription_id:
            stmt = stmt.where(PodcastEpisode.subscription_id == subscription_id)

        stmt = stmt.order_by(PodcastEpisode.published_at.desc())
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_subscription_episodes(self, subscription_id: int, limit: int = 20) -> list[PodcastEpisode]:
        """获取订阅的所有单集"""
        stmt = select(PodcastEpisode).options(
            joinedload(PodcastEpisode.subscription)
        ).where(
            PodcastEpisode.subscription_id == subscription_id
        ).order_by(desc(PodcastEpisode.published_at)).limit(limit)

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def count_subscription_episodes(self, subscription_id: int) -> int:
        """Count episodes for a subscription using efficient COUNT query."""
        stmt = select(func.count(PodcastEpisode.id)).where(
            PodcastEpisode.subscription_id == subscription_id
        )
        result = await self.db.execute(stmt)
        return result.scalar() or 0

    async def get_episode_by_id(self, episode_id: int, user_id: int | None = None) -> PodcastEpisode | None:
        """获取单集详情"""
        stmt = select(PodcastEpisode).options(
            joinedload(PodcastEpisode.subscription)
        ).where(PodcastEpisode.id == episode_id)
        if user_id:
            # 确保是该用户的订阅 - use UserSubscription join
            stmt = stmt.join(Subscription).join(
                UserSubscription,
                UserSubscription.subscription_id == Subscription.id
            ).where(
                and_(
                    UserSubscription.user_id == user_id,
                    UserSubscription.is_archived == False
                )
            )

        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_episode_by_item_link(self, subscription_id: int, item_link: str) -> PodcastEpisode | None:
        """通过item_link查找单集"""
        stmt = select(PodcastEpisode).where(
            and_(
                PodcastEpisode.subscription_id == subscription_id,
                PodcastEpisode.item_link == item_link
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    # === AI总结相关 ===

    async def update_ai_summary(
        self,
        episode_id: int,
        summary: str,
        version: str = "v1",
        confidence: float | None = None,
        transcript_used: bool = False
    ) -> PodcastEpisode:
        """更新AI总结"""
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

        # 更新缓存
        await self.redis.set_ai_summary(episode_id, summary, version)

        return episode

    async def mark_summary_failed(self, episode_id: int, error: str) -> None:
        """标记总结失败"""
        episode = await self.get_episode_by_id(episode_id)
        if episode:
            episode.status = "summary_failed"
            metadata = episode.metadata_json or {}
            metadata["summary_error"] = error
            metadata["failed_at"] = datetime.now(timezone.utc).isoformat()
            episode.metadata_json = metadata
            await self.db.commit()

    # === 播放状态管理 ===

    async def get_playback_state(self, user_id: int, episode_id: int) -> PodcastPlaybackState | None:
        """获取用户播放状态"""
        stmt = select(PodcastPlaybackState).where(
            and_(
                PodcastPlaybackState.user_id == user_id,
                PodcastPlaybackState.episode_id == episode_id
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_playback_states_batch(
        self,
        user_id: int,
        episode_ids: list[int]
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
                PodcastPlaybackState.episode_id.in_(episode_ids)
            )
        )
        result = await self.db.execute(stmt)
        states = result.scalars().all()

        # Create a dictionary mapping episode_id to state
        return {state.episode_id: state for state in states}

    async def get_episodes_counts_batch(
        self,
        subscription_ids: list[int]
    ) -> dict[int, int]:
        """
        Batch fetch episode counts for multiple subscriptions.

        批量获取多个订阅的剧集计数

        Args:
            subscription_ids: List of subscription IDs

        Returns:
            Dictionary mapping subscription_id to episode count
        """
        if not subscription_ids:
            return {}

        # Use GROUP BY to count episodes for all subscriptions in one query
        stmt = select(
            PodcastEpisode.subscription_id,
            func.count(PodcastEpisode.id)
        ).where(
            PodcastEpisode.subscription_id.in_(subscription_ids)
        ).group_by(PodcastEpisode.subscription_id)

        result = await self.db.execute(stmt)
        return {row[0]: row[1] for row in result.all()}

    async def get_subscription_episodes_batch(
        self,
        subscription_ids: list[int],
        limit_per_subscription: int = 3
    ) -> dict[int, list[PodcastEpisode]]:
        """
        Batch fetch recent episodes for multiple subscriptions.

        批量获取多个订阅的最新剧集

        Args:
            subscription_ids: List of subscription IDs
            limit_per_subscription: Number of recent episodes per subscription

        Returns:
            Dictionary mapping subscription_id to list of episodes
        """
        if not subscription_ids:
            return {}

        # Get all episodes for these subscriptions, ordered by published_at
        stmt = select(PodcastEpisode).where(
            PodcastEpisode.subscription_id.in_(subscription_ids)
        ).order_by(desc(PodcastEpisode.published_at))

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
        playback_rate: float = 1.0
    ) -> PodcastPlaybackState:
        """更新播放进度"""
        state = await self.get_playback_state(user_id, episode_id)

        if state:
            state.current_position = position
            state.is_playing = is_playing
            state.playback_rate = playback_rate
            if is_playing:
                state.play_count += 1
            state.timestamp = datetime.now(timezone.utc)
        else:
            state = PodcastPlaybackState(
                user_id=user_id,
                episode_id=episode_id,
                current_position=position,
                is_playing=is_playing,
                playback_rate=playback_rate,
                play_count=1 if is_playing else 0
            )
            self.db.add(state)

        await self.db.commit()
        await self.db.refresh(state)

        # 也缓存到Redis作为快速读取
        if self.redis:
            await self.redis.set_user_progress(user_id, episode_id, position / 100)

        return state

    # === 统计与缓存辅助 ===

    async def _cache_episode_metadata(self, episode: PodcastEpisode):
        """缓存episode元数据到Redis"""
        if not self.redis:
            return

        metadata = {
            "id": str(episode.id),
            "title": episode.title,
            "audio_url": episode.audio_url,
            "duration": str(episode.audio_duration or 0),
            "has_summary": "yes" if episode.ai_summary else "no"
        }

        await self.redis.set_episode_metadata(episode.id, metadata)

    # === 新增方法支持分页、搜索、统计等 ===

    async def get_user_subscriptions_paginated(
        self,
        user_id: int,
        page: int = 1,
        size: int = 20,
        filters: dict | None = None
    ) -> tuple[list[Subscription], int]:
        """分页获取用户订阅"""
        query = (
            select(Subscription)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    UserSubscription.user_id == user_id,
                    UserSubscription.is_archived == False,
                    Subscription.source_type.in_(["podcast-rss", "rss"])
                )
            )
        )

        # 应用过滤器
        if filters:
            if filters.status:
                query = query.where(Subscription.status == filters.status)

        # 计算总数
        count_query = select(func.count()).select_from(
            query.subquery()
        )
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()

        # 应用排序和分页
        query = query.order_by(Subscription.created_at.desc())
        query = query.offset((page - 1) * size).limit(size)

        result = await self.db.execute(query)
        subscriptions = list(result.scalars().all())

        return subscriptions, total

    async def get_episodes_paginated(
        self,
        user_id: int,
        page: int = 1,
        size: int = 20,
        filters: dict | None = None
    ) -> tuple[list[PodcastEpisode], int]:
        """分页获取用户播客单集"""
        query = (
            select(PodcastEpisode)
            .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .options(joinedload(PodcastEpisode.subscription))
            .where(
                and_(
                    UserSubscription.user_id == user_id,
                    UserSubscription.is_archived == False
                )
            )
        )

        # 应用过滤器
        if filters:
            if filters.subscription_id:
                query = query.where(PodcastEpisode.subscription_id == filters.subscription_id)
            if filters.has_summary is not None:
                if filters.has_summary:
                    query = query.where(PodcastEpisode.ai_summary.isnot(None))
                else:
                    query = query.where(PodcastEpisode.ai_summary.is_(None))
            if filters.is_played is not None:
                # 播放状态需要JOIN播放记录表
                if filters.is_played:
                    # 已播放：播放进度超过90%
                    query = query.join(PodcastPlaybackState).where(
                        PodcastPlaybackState.current_position >= PodcastEpisode.audio_duration * 0.9
                    )
                else:
                    # 未播放或未听完
                    query = query.outerjoin(PodcastPlaybackState).where(
                        or_(
                            PodcastPlaybackState.id.is_(None),
                            PodcastPlaybackState.current_position < PodcastEpisode.audio_duration * 0.9
                        )
                    )

        # 计算总数
        count_query = select(func.count()).select_from(
            query.subquery()
        )
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()

        # 应用排序和分页
        query = query.order_by(PodcastEpisode.published_at.desc())
        query = query.offset((page - 1) * size).limit(size)

        result = await self.db.execute(query)
        episodes = list(result.scalars().all())

        return episodes, total

    async def search_episodes(
        self,
        user_id: int,
        query: str,
        search_in: str = "all",
        page: int = 1,
        size: int = 20
    ) -> tuple[list[PodcastEpisode], int]:
        """搜索播客单集"""
        # 构建搜索条件
        search_conditions = []

        if search_in in ["title", "all"]:
            search_conditions.append(PodcastEpisode.title.ilike(f"%{query}%"))
        if search_in in ["description", "all"]:
            search_conditions.append(PodcastEpisode.description.ilike(f"%{query}%"))
        if search_in in ["summary", "all"]:
            search_conditions.append(PodcastEpisode.ai_summary.ilike(f"%{query}%"))

        base_query = (
            select(PodcastEpisode)
            .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .options(joinedload(PodcastEpisode.subscription))
            .where(
                and_(
                    UserSubscription.user_id == user_id,
                    UserSubscription.is_archived == False,
                    or_(*search_conditions)
                )
            )
        )

        # 使用全文搜索（如果PostgreSQL支持）
        # 这里简化为使用ILIKE，实际可以优化为使用PostgreSQL的全文搜索

        # 计算总数
        count_query = select(func.count()).select_from(
            base_query.subquery()
        )
        total_result = await self.db.execute(count_query)
        total = total_result.scalar()

        # 应用排序（按相关度和发布时间）
        # 简化实现：只按发布时间排序
        query = base_query.order_by(PodcastEpisode.published_at.desc())
        query = query.offset((page - 1) * size).limit(size)

        result = await self.db.execute(query)
        episodes = list(result.scalars().all())

        return episodes, total

    async def update_subscription_fetch_time(self, subscription_id: int, fetch_time: datetime | None = None):
        """更新订阅的最后抓取时间"""
        stmt = select(Subscription).where(Subscription.id == subscription_id)
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()

        if subscription:
            # 移除时区信息以匹配数据库的TIMESTAMP WITHOUT TIME ZONE
            time_to_set = sanitize_published_date(fetch_time or datetime.now(timezone.utc))
            subscription.last_fetched_at = time_to_set
            await self.db.commit()

    async def update_subscription_metadata(self, subscription_id: int, metadata: dict):
        """更新订阅的元数据配置"""
        stmt = select(Subscription).where(Subscription.id == subscription_id)
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()

        if subscription:
            # 合并现有配置和新元数据 - 使用新字典对象确保 SQLAlchemy 检测到变更
            current_config = dict(subscription.config or {})
            current_config.update(metadata)
            subscription.config = current_config
            # 显式标记字段已修改，确保 JSON 列变更被持久化
            attributes.flag_modified(subscription, 'config')
            subscription.updated_at = datetime.now(timezone.utc)
            await self.db.commit()

    async def get_recently_played(
        self,
        user_id: int,
        limit: int = 5
    ) -> list[dict[str, Any]]:
        """获取最近播放的单集"""
        stmt = (
            select(
                PodcastEpisode,
                PodcastPlaybackState.current_position,
                PodcastPlaybackState.last_updated_at
            )
            .join(PodcastPlaybackState)
            .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    UserSubscription.user_id == user_id,
                    UserSubscription.is_archived == False,
                    PodcastPlaybackState.last_updated_at >= datetime.now(timezone.utc) - timedelta(days=7)
                )
            )
            .order_by(PodcastPlaybackState.last_updated_at.desc())
            .limit(limit)
        )

        result = await self.db.execute(stmt)
        rows = result.all()

        recently_played = []
        for episode, position, last_played in rows:
            recently_played.append({
                "episode_id": episode.id,
                "title": episode.title,
                "subscription_title": episode.subscription.title,
                "position": position,
                "last_played": last_played,
                "duration": episode.audio_duration
            })

        return recently_played

    async def get_liked_episodes(
        self,
        user_id: int,
        limit: int = 20
    ) -> list[PodcastEpisode]:
        """获取用户喜欢的单集（播放完成率高的）"""
        # 播放完成率 > 80% 的单集
        stmt = (
            select(PodcastEpisode)
            .join(PodcastPlaybackState)
            .join(Subscription, PodcastEpisode.subscription_id == Subscription.id)
            .join(UserSubscription, UserSubscription.subscription_id == Subscription.id)
            .where(
                and_(
                    UserSubscription.user_id == user_id,
                    UserSubscription.is_archived == False,
                    PodcastEpisode.audio_duration > 0,
                    PodcastPlaybackState.current_position >= PodcastEpisode.audio_duration * 0.8
                )
            )
            .order_by(PodcastPlaybackState.play_count.desc())
            .limit(limit)
        )

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_recent_play_dates(
        self,
        user_id: int,
        days: int = 30
    ) -> set[date]:
        """获取最近播放的日期集合"""
        stmt = select(PodcastPlaybackState.last_updated_at).where(
            and_(
                PodcastPlaybackState.user_id == user_id,
                PodcastPlaybackState.last_updated_at >= datetime.now(timezone.utc) - timedelta(days=days)
            )
        ).distinct()

        result = await self.db.execute(stmt)
        dates = set()
        for (last_updated,) in result:
            dates.add(last_updated.date())

        return dates

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
                    UserSubscription.user_id == user_id,
                    UserSubscription.is_archived == False
                )
            )
        )
        sub_count_result = await self.db.execute(sub_count_stmt)
        total_subscriptions = sub_count_result.scalar() or 0

        # Aggregate episode statistics
        episode_stats_stmt = select(
            func.count(PodcastEpisode.id).label('total_episodes'),
            func.sum(
                case(
                    (PodcastEpisode.ai_summary.isnot(None), 1),
                    else_=0
                )
            ).label('summaries_generated'),
            func.sum(
                case(
                    (PodcastEpisode.ai_summary.is_(None), 1),
                    else_=0
                )
            ).label('pending_summaries'),
            func.coalesce(
                func.sum(PodcastPlaybackState.current_position),
                0
            ).label('total_playtime')
        ).select_from(
            PodcastEpisode.__table__.join(
                Subscription.__table__,
                PodcastEpisode.subscription_id == Subscription.id
            ).join(
                UserSubscription.__table__,
                and_(
                    UserSubscription.subscription_id == Subscription.id,
                    UserSubscription.user_id == user_id,
                    UserSubscription.is_archived == False
                )
            ).outerjoin(
                PodcastPlaybackState.__table__,
                and_(
                    PodcastPlaybackState.episode_id == PodcastEpisode.id,
                    PodcastPlaybackState.user_id == user_id
                )
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
                    UserSubscription.user_id == user_id,
                    UserSubscription.is_archived == False,
                    Subscription.status == "active"
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
            "has_active_plus": has_active_plus
        }
