"""
播客数据访问层 - Podcast Repository
"""

from typing import List, Optional, Tuple, Dict, Any, Set
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc, func, or_, text
from datetime import datetime, date, timedelta

from app.domains.podcast.models import PodcastEpisode, PodcastPlaybackState
from app.domains.subscription.models import Subscription, SubscriptionItem
from app.core.redis import PodcastRedis


class PodcastRepository:
    """
    播客数据持久化操作
    """

    def __init__(self, db: AsyncSession, redis: Optional[PodcastRedis] = None):
        self.db = db
        self.redis = redis or PodcastRedis()

    # === 订阅管理 ===

    async def create_or_update_subscription(
        self,
        user_id: int,
        feed_url: str,
        title: str,
        description: str = "",
        custom_name: Optional[str] = None
    ) -> Subscription:
        """
        创建或更新播客订阅
        """
        # 查找现有订阅
        stmt = select(Subscription).where(
            and_(
                Subscription.user_id == user_id,
                Subscription.source_url == feed_url
            )
        )
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()

        if subscription:
            # 更新
            subscription.title = custom_name or title
            subscription.description = description
            subscription.updated_at = datetime.utcnow()
        else:
            # 创建新订阅
            subscription = Subscription(
                user_id=user_id,
                source_url=feed_url,
                source_type="podcast-rss",  # 区分原生RSS和播客RSS
                title=custom_name or title,
                description=description,
                status="active",
                refresh_interval_minutes=60  # 默认1小时
            )
            self.db.add(subscription)

        await self.db.commit()
        await self.db.refresh(subscription)
        return subscription

    async def get_user_subscriptions(self, user_id: int) -> List[Subscription]:
        """获取用户所有播客订阅"""
        stmt = select(Subscription).where(
            and_(
                Subscription.user_id == user_id,
                Subscription.source_type == "podcast-rss"
            )
        ).order_by(Subscription.created_at.desc())

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_subscription_by_id(self, user_id: int, sub_id: int) -> Optional[Subscription]:
        """获取特定订阅"""
        stmt = select(Subscription).where(
            and_(
                Subscription.user_id == user_id,
                Subscription.id == sub_id,
                Subscription.source_type == "podcast-rss"
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    # === 单集管理 ===

    async def create_or_update_episode(
        self,
        subscription_id: int,
        guid: str,
        title: str,
        description: str,
        audio_url: str,
        published_at: datetime,
        audio_duration: Optional[int] = None,
        transcript_url: Optional[str] = None,
        metadata: Optional[dict] = None
    ) -> PodcastEpisode:
        """
        创建或更新播客单集
        使用guid唯一标识（RSS标准）
        """
        # 查找现有
        stmt = select(PodcastEpisode).where(
            and_(
                PodcastEpisode.subscription_id == subscription_id,
                PodcastEpisode.guid == guid
            )
        )
        result = await self.db.execute(stmt)
        episode = result.scalar_one_or_none()

        if episode:
            episode.title = title
            episode.description = description
            episode.audio_url = audio_url
            episode.published_at = published_at
            episode.audio_duration = audio_duration
            episode.transcript_url = transcript_url
            episode.updated_at = datetime.utcnow()
            if metadata:
                episode.metadata_json = {**episode.metadata_json, **metadata}
            is_new = False
        else:
            episode = PodcastEpisode(
                subscription_id=subscription_id,
                guid=guid,
                title=title,
                description=description,
                audio_url=audio_url,
                published_at=published_at,
                audio_duration=audio_duration,
                transcript_url=transcript_url,
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

    async def get_unsummarized_episodes(self, subscription_id: Optional[int] = None) -> List[PodcastEpisode]:
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

    async def get_subscription_episodes(self, subscription_id: int, limit: int = 20) -> List[PodcastEpisode]:
        """获取订阅的所有单集"""
        stmt = select(PodcastEpisode).where(
            PodcastEpisode.subscription_id == subscription_id
        ).order_by(desc(PodcastEpisode.published_at)).limit(limit)

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_episode_by_id(self, episode_id: int, user_id: Optional[int] = None) -> Optional[PodcastEpisode]:
        """获取单集详情"""
        stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode_id)
        if user_id:
            # 确保是该用户的订阅
            from app.domains.subscription.models import Subscription
            stmt = stmt.join(Subscription).where(Subscription.user_id == user_id)

        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_episode_by_guid(self, subscription_id: int, guid: str) -> Optional[PodcastEpisode]:
        """通过GUID查找单集"""
        stmt = select(PodcastEpisode).where(
            and_(
                PodcastEpisode.subscription_id == subscription_id,
                PodcastEpisode.guid == guid
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
        confidence: Optional[float] = None,
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
        metadata["summarized_at"] = datetime.utcnow().isoformat()
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
            metadata["failed_at"] = datetime.utcnow().isoformat()
            episode.metadata_json = metadata
            await self.db.commit()

    # === 播放状态管理 ===

    async def get_playback_state(self, user_id: int, episode_id: int) -> Optional[PodcastPlaybackState]:
        """获取用户播放状态"""
        stmt = select(PodcastPlaybackState).where(
            and_(
                PodcastPlaybackState.user_id == user_id,
                PodcastPlaybackState.episode_id == episode_id
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

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
            state.timestamp = datetime.utcnow()
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
        filters: Optional[dict] = None
    ) -> Tuple[List[Subscription], int]:
        """分页获取用户订阅"""
        query = select(Subscription).where(
            and_(
                Subscription.user_id == user_id,
                Subscription.source_type == "podcast-rss"
            )
        )

        # 应用过滤器
        if filters:
            if filters.get("category_id"):
                # TODO: 实现分类过滤
                pass
            if filters.get("status"):
                query = query.where(Subscription.status == filters["status"])

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
        filters: Optional[dict] = None
    ) -> Tuple[List[PodcastEpisode], int]:
        """分页获取用户播客单集"""
        query = select(PodcastEpisode).join(Subscription).where(
            Subscription.user_id == user_id
        )

        # 应用过滤器
        if filters:
            if filters.get("subscription_id"):
                query = query.where(PodcastEpisode.subscription_id == filters["subscription_id"])
            if filters.get("has_summary") is not None:
                if filters["has_summary"]:
                    query = query.where(PodcastEpisode.ai_summary.isnot(None))
                else:
                    query = query.where(PodcastEpisode.ai_summary.is_(None))
            if filters.get("is_played") is not None:
                # 播放状态需要JOIN播放记录表
                if filters["is_played"]:
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
    ) -> Tuple[List[PodcastEpisode], int]:
        """搜索播客单集"""
        # 构建搜索条件
        search_conditions = []

        if search_in in ["title", "all"]:
            search_conditions.append(PodcastEpisode.title.ilike(f"%{query}%"))
        if search_in in ["description", "all"]:
            search_conditions.append(PodcastEpisode.description.ilike(f"%{query}%"))
        if search_in in ["summary", "all"]:
            search_conditions.append(PodcastEpisode.ai_summary.ilike(f"%{query}%"))

        base_query = select(PodcastEpisode).join(Subscription).where(
            and_(
                Subscription.user_id == user_id,
                or_(*search_conditions)
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

    async def update_subscription_categories(
        self,
        subscription_id: int,
        category_ids: List[int]
    ):
        """更新订阅的分类关联"""
        # TODO: 实现订阅与分类的多对多关系更新
        # 这需要创建PodcastCategory模型和相关映射表
        pass

    async def update_subscription_fetch_time(self, subscription_id: int):
        """更新订阅的最后抓取时间"""
        stmt = select(Subscription).where(Subscription.id == subscription_id)
        result = await self.db.execute(stmt)
        subscription = result.scalar_one_or_none()

        if subscription:
            subscription.last_fetched_at = datetime.utcnow()
            await self.db.commit()

    async def get_recently_played(
        self,
        user_id: int,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """获取最近播放的单集"""
        stmt = select(
            PodcastEpisode,
            PodcastPlaybackState.current_position,
            PodcastPlaybackState.last_updated_at
        ).join(PodcastPlaybackState).join(Subscription).where(
            and_(
                Subscription.user_id == user_id,
                PodcastPlaybackState.last_updated_at >= datetime.utcnow() - timedelta(days=7)
            )
        ).order_by(PodcastPlaybackState.last_updated_at.desc()).limit(limit)

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
    ) -> List[PodcastEpisode]:
        """获取用户喜欢的单集（播放完成率高的）"""
        # 播放完成率 > 80% 的单集
        stmt = select(PodcastEpisode).join(PodcastPlaybackState).join(Subscription).where(
            and_(
                Subscription.user_id == user_id,
                PodcastEpisode.audio_duration > 0,
                PodcastPlaybackState.current_position >= PodcastEpisode.audio_duration * 0.8
            )
        ).order_by(PodcastPlaybackState.play_count.desc()).limit(limit)

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_recent_play_dates(
        self,
        user_id: int,
        days: int = 30
    ) -> Set[date]:
        """获取最近播放的日期集合"""
        stmt = select(PodcastPlaybackState.last_updated_at).where(
            and_(
                PodcastPlaybackState.user_id == user_id,
                PodcastPlaybackState.last_updated_at >= datetime.utcnow() - timedelta(days=days)
            )
        ).distinct()

        result = await self.db.execute(stmt)
        dates = set()
        for (last_updated,) in result:
            dates.add(last_updated.date())

        return dates

    async def get_subscription_episodes(
        self,
        subscription_id: int,
        limit: Optional[int] = 20
    ) -> List[PodcastEpisode]:
        """获取订阅的单集列表"""
        query = select(PodcastEpisode).where(
            PodcastEpisode.subscription_id == subscription_id
        ).order_by(PodcastEpisode.published_at.desc())

        if limit:
            query = query.limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())
