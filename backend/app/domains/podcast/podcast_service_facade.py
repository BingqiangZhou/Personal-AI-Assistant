"""
播客业务逻辑服务 - Podcast Services (Backward Compatible Facade)

This module provides backward compatibility by maintaining the original PodcastService interface
while delegating to the new specialized services.

本模块通过保持原始 PodcastService 接口同时委托给新的专业化服务来提供向后兼容性。
"""

import logging
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.podcast.models import PodcastEpisode
from app.domains.podcast.services import (
    PodcastEpisodeService,
    PodcastPlaybackService,
    PodcastSearchService,
    PodcastSubscriptionService,
    PodcastSummaryService,
    PodcastSyncService,
)
from app.domains.subscription.models import Subscription


logger = logging.getLogger(__name__)


class PodcastService:
    """
    播客核心服务 - 统一接口

    This is a backward-compatible facade that delegates to specialized services.
    这是向后兼容的外观模式，委托给专业化服务。

    For new code, consider using the specialized services directly:
    - PodcastSubscriptionService: add/remove/list subscriptions
    - PodcastEpisodeService: list/get episodes
    - PodcastPlaybackService: playback progress management
    - PodcastSummaryService: AI summary generation
    - PodcastSearchService: search and recommendations

    对于新代码，建议直接使用专业化服务。
    """

    def __init__(self, db: AsyncSession, user_id: int):
        """
        Initialize podcast service with specialized sub-services.

        Args:
            db: Database session
            user_id: Current user ID
        """
        self.db = db
        self.user_id = user_id

        # Initialize specialized services
        self.subscription_service = PodcastSubscriptionService(db, user_id)
        self.episode_service = PodcastEpisodeService(db, user_id)
        self.playback_service = PodcastPlaybackService(db, user_id)
        self.summary_service = PodcastSummaryService(db, user_id)
        self.search_service = PodcastSearchService(db, user_id)
        self.sync_service = PodcastSyncService(db, user_id)

        # For backward compatibility, maintain reference to repo
        from app.domains.podcast.repositories import PodcastRepository
        self.repo = PodcastRepository(db)

    # === 订阅管理 (Subscription Management) ===

    async def add_subscription(
        self,
        feed_url: str,
        category_ids: Optional[list[int]] = None
    ) -> tuple[Subscription, list[PodcastEpisode]]:
        """添加播客订阅 - Delegates to SubscriptionService"""
        return await self.subscription_service.add_subscription(feed_url, category_ids)

    async def add_subscriptions_batch(
        self,
        subscriptions_data: list
    ) -> list[dict[str, Any]]:
        """批量添加播客订阅 - Delegates to SubscriptionService"""
        return await self.subscription_service.add_subscriptions_batch(subscriptions_data)

    async def list_subscriptions(
        self,
        filters: Optional[dict] = None,
        page: int = 1,
        size: int = 20
    ) -> tuple[list[dict], int]:
        """列出用户的所有播客订阅 - Delegates to SubscriptionService"""
        return await self.subscription_service.list_subscriptions(filters, page, size)

    async def get_subscription_details(self, subscription_id: int) -> Optional[dict]:
        """获取订阅详情及单集列表 - Delegates to SubscriptionService"""
        return await self.subscription_service.get_subscription_details(subscription_id)

    async def refresh_subscription(self, subscription_id: int) -> list[PodcastEpisode]:
        """刷新播客订阅 - Delegates to SubscriptionService"""
        return await self.subscription_service.refresh_subscription(subscription_id)

    async def reparse_subscription(
        self,
        subscription_id: int,
        force_all: bool = False
    ) -> dict:
        """重新解析订阅 - Delegates to SubscriptionService"""
        return await self.subscription_service.reparse_subscription(subscription_id, force_all)

    async def remove_subscription(self, subscription_id: int) -> bool:
        """删除订阅 - Delegates to SubscriptionService"""
        return await self.subscription_service.remove_subscription(subscription_id)

    async def remove_subscriptions_bulk(
        self,
        subscription_ids: list[int]
    ) -> dict[str, Any]:
        """批量删除订阅 - Delegates to SubscriptionService"""
        return await self.subscription_service.remove_subscriptions_bulk(subscription_ids)

    # === 单集管理 (Episode Management) ===

    async def list_episodes(
        self,
        filters: Optional[dict] = None,
        page: int = 1,
        size: int = 20
    ) -> tuple[list[dict], int]:
        """获取播客单集列表 - Delegates to EpisodeService"""
        return await self.episode_service.list_episodes(filters, page, size)

    async def get_episode_by_id(self, episode_id: int) -> Optional[PodcastEpisode]:
        """获取单集详情 - Delegates to EpisodeService"""
        return await self.episode_service.get_episode_by_id(episode_id)

    async def get_episode_with_summary(self, episode_id: int) -> Optional[dict]:
        """获取单集详情和AI总结 - Delegates to EpisodeService"""
        return await self.episode_service.get_episode_with_summary(episode_id)

    async def get_subscription_by_id(self, subscription_id: int) -> Optional[Subscription]:
        """获取订阅详情 - Delegates to SubscriptionService"""
        sub = await self.repo.get_subscription_by_id(self.user_id, subscription_id)
        return sub

    # === 播放与进度管理 (Playback Management) ===

    async def update_playback_progress(
        self,
        episode_id: int,
        progress_seconds: int,
        is_playing: bool = False,
        playback_rate: float = 1.0
    ) -> dict:
        """更新播放进度 - Delegates to PlaybackService"""
        return await self.playback_service.update_playback_progress(
            episode_id, progress_seconds, is_playing, playback_rate
        )

    async def get_playback_state(self, episode_id: int) -> Optional[dict]:
        """获取播放状态 - Delegates to PlaybackService"""
        return await self.playback_service.get_playback_state(episode_id)

    # === AI总结 (AI Summary) ===

    async def generate_summary_for_episode(self, episode_id: int) -> str:
        """为指定单集生成AI总结 - Delegates to SummaryService"""
        return await self.summary_service.generate_summary_for_episode(episode_id)

    async def regenerate_summary(self, episode_id: int, force: bool = False) -> str:
        """重新生成总结 - Delegates to SummaryService"""
        return await self.summary_service.regenerate_summary(episode_id, force)

    async def get_pending_summaries(self) -> list[dict]:
        """获取待总结的单集 - Delegates to SummaryService"""
        return await self.summary_service.get_pending_summaries()

    # === 搜索和推荐 (Search and Recommendations) ===

    async def search_podcasts(
        self,
        query: str,
        search_in: str = "all",
        page: int = 1,
        size: int = 20
    ) -> tuple[list[dict], int]:
        """搜索播客内容 - Delegates to SearchService"""
        return await self.search_service.search_podcasts(query, search_in, page, size)

    async def get_recommendations(self, limit: int = 10) -> list[dict]:
        """获取播客推荐 - Delegates to SearchService"""
        return await self.search_service.get_recommendations(limit)

    # === 用户统计 (User Stats) ===

    async def get_user_stats(self) -> dict:
        """
        获取用户播客统计

        This method combines data from multiple services.
        """
        from app.core.redis import PodcastRedis

        redis = PodcastRedis()

        # Try cache first
        cached = await redis.get_user_stats(self.user_id)
        if cached:
            logger.info(f"Cache HIT for user stats: user_id={self.user_id}")
            return cached

        logger.info(f"Cache MISS for user stats: user_id={self.user_id}, querying database")

        # Get aggregated stats from repository
        stats = await self.repo.get_user_stats_aggregated(self.user_id)

        # Get recently played
        recently_played = await self.playback_service.get_recently_played(limit=5)

        # Calculate listening streak
        listening_streak = await self.playback_service.calculate_listening_streak()

        # Top categories (TODO: implement category statistics)
        top_categories = []

        result = {
            **stats,
            "recently_played": recently_played,
            "top_categories": top_categories,
            "listening_streak": listening_streak
        }

        # Cache the results
        await redis.set_user_stats(self.user_id, result)

        return result

    # === 私有辅助方法 (Private Helper Methods) ===
    # These are kept for backward compatibility with code that might access them directly

    async def _validate_and_get_subscription(
        self,
        subscription_id: int,
        check_source_type: bool = False
    ) -> Optional[Subscription]:
        """验证订阅存在且属于当前用户 - Delegates to SubscriptionService"""
        return await self.subscription_service._validate_and_get_subscription(
            subscription_id, check_source_type
        )

    async def _get_episode_ids_for_subscription(
        self,
        subscription_id: int
    ) -> list[int]:
        """获取订阅的所有episode_id - Delegates to SubscriptionService"""
        return await self.subscription_service._get_episode_ids_for_subscription(subscription_id)

    async def _delete_subscription_related_entities(
        self,
        subscription_id: int,
        episode_ids: list[int]
    ) -> None:
        """删除订阅相关的所有实体 - Delegates to SubscriptionService"""
        await self.subscription_service._delete_subscription_related_entities(
            subscription_id, episode_ids
        )

    async def _generate_summary_task(self, episode: PodcastEpisode):
        """后台任务：异步生成AI总结 - Delegates to SummaryService"""
        await self.summary_service._generate_summary_task(episode)

    async def _generate_summary(self, episode: PodcastEpisode, version: str = "v1") -> str:
        """核心AI总结生成逻辑 - Delegates to SummaryService"""
        return await self.summary_service._generate_summary(episode, version)

    async def _call_llm_for_summary(
        self,
        episode_title: str,
        content: str,
        content_type: str
    ) -> str:
        """调用LLM API生成总结 - Delegates to SummaryService"""
        return await self.summary_service._call_llm_for_summary(episode_title, content, content_type)

    def _build_episode_response(
        self,
        episodes: list[PodcastEpisode],
        playback_states: dict[int, Any]
    ) -> list[dict]:
        """Build episode response - Delegates to EpisodeService"""
        return self.episode_service._build_episode_response(episodes, playback_states)

    def _rule_based_summary(self, title: str, content: str) -> str:
        """如果没有LLM，使用规则生成基本总结 - Kept for compatibility"""
        import re

        # 提取关键句子
        sentences = re.split(r'[.!?]', content)
        important_sentences = [
            s.strip()[:200] for s in sentences
            if any(keyword in s.lower() for keyword in ['key', 'main', 'conclusion', 'important', 'learn', 'feel'])
        ][:3]

        bullet_points = '\n'.join(f"• {s}" for s in important_sentences) if important_sentences else '• ' + content[:150] + '...'
        disclaimer = "*（此为快速总结，实际使用时建议绑定OpenAI API）*"

        return f"""## 播客总结

**节目**: {title}

{bullet_points}

{disclaimer}"""

    async def _wait_for_existing_summary(
        self,
        episode: PodcastEpisode,
        session: Optional[AsyncSession]
    ) -> str:
        """等待现有的总结任务完成 - Delegates to SummaryService"""
        return await self.summary_service._wait_for_existing_summary(episode, session)

    def _prepare_episode_content(self, episode: PodcastEpisode) -> tuple:
        """准备播客单集内容 - Delegates to SummaryService"""
        return self.summary_service._prepare_episode_content(episode)

    def _sanitize_content(self, raw_content: str, sanitizer, content_type: str) -> str:
        """净化内容并验证 - Delegates to SummaryService"""
        return self.summary_service._sanitize_content(raw_content, sanitizer, content_type)

    async def _get_episode_count(self, subscription_id: int) -> int:
        """获取订阅的单集数量"""
        return await self.repo.count_subscription_episodes(subscription_id)

    async def _get_unplayed_count(self, subscription_id: int) -> int:
        """获取未播放的单集数量 - Uses PlaybackService"""
        episodes = await self.repo.get_subscription_episodes(subscription_id, limit=None)
        if not episodes:
            return 0

        # Batch fetch playback states
        episode_ids = [ep.id for ep in episodes]
        playback_states = await self.playback_service.get_playback_states_batch(episode_ids)

        unplayed = 0
        for ep in episodes:
            playback = playback_states.get(ep.id)
            if not playback or not playback.current_position or \
               (ep.audio_duration and playback.current_position < ep.audio_duration * 0.9):
                unplayed += 1

        return unplayed

    async def _calculate_listening_streak(self) -> int:
        """计算连续收听天数 - Delegates to PlaybackService"""
        return await self.playback_service.calculate_listening_streak()
