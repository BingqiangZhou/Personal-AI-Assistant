"""
播客业务逻辑服务 - Podcast Services

核心服务:
1. PodcastController: 管理播客订阅和单集
2. PodcastSummaryService: AI总结生成
3. PodcastSyncService: RSS轮询和同步
"""

import logging
from typing import List, Tuple, Optional, Dict, Any
from datetime import datetime, timedelta
import asyncio

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.llm_privacy import ContentSanitizer
from app.core.redis import PodcastRedis
from app.domains.podcast.repositories import PodcastRepository
from app.domains.podcast.models import PodcastEpisode
from app.domains.podcast.schemas import PodcastSubscriptionCreate
from app.domains.subscription.models import Subscription
from app.domains.assistant.models import Conversation, Message
from app.integration.podcast.security import PodcastSecurityValidator
from app.integration.podcast.secure_rss_parser import SecureRSSParser, PodcastFeed

logger = logging.getLogger(__name__)


class PodcastService:
    """
    播客核心服务 - 统一接口
    """

    def __init__(self, db: AsyncSession, user_id: int):
        self.db = db
        self.user_id = user_id
        self.repo = PodcastRepository(db)
        self.redis = PodcastRedis()
        self.sanitizer = ContentSanitizer(mode=settings.LLM_CONTENT_SANITIZE_MODE)
        self.security = PodcastSecurityValidator()
        self.parser = SecureRSSParser(user_id)
        from app.domains.podcast.transcription_manager import DatabaseBackedTranscriptionService
        self.transcription_service = DatabaseBackedTranscriptionService(db)

    # === 订阅管理 ===

    async def add_subscription(
        self,
        feed_url: str,
        category_ids: Optional[List[int]] = None
    ) -> Tuple[Subscription, List[PodcastEpisode]]:
        """
        添加播客订阅
        返回: (subscription, new_episodes)
        """
        # 1. 验证并解析RSS
        success, feed, error = await self.parser.fetch_and_parse_feed(feed_url)
        if not success:
            raise ValueError(f"无法解析播客: {error}")

        # 2. 检查订阅数量限制
        existing_subs = await self.repo.get_user_subscriptions(self.user_id)
        if len(existing_subs) >= settings.MAX_PODCAST_SUBSCRIPTIONS:
            raise ValueError(f"已达到最大订阅数量: {settings.MAX_PODCAST_SUBSCRIPTIONS}")

        # 3. 创建或更新订阅
        # 准备元数据
        metadata = {
            "author": feed.author,
            "language": feed.language,
            "categories": feed.categories,
            "explicit": feed.explicit,
            "image_url": feed.image_url,
            "podcast_type": feed.podcast_type,
            "link": feed.link,
            "total_episodes": len(feed.episodes),
            "platform": feed.platform
        }

        subscription = await self.repo.create_or_update_subscription(
            self.user_id,
            feed_url,
            feed.title,
            feed.description,
            None,  # custom_name
            metadata=metadata
        )

        # 4. 处理分类关联
        if category_ids:
            await self.repo.update_subscription_categories(subscription.id, category_ids)

        # 5. 保存并总结新单集
        new_episodes = []
        for episode in feed.episodes:  # 所有单集
            saved_episode, is_new = await self.repo.create_or_update_episode(
                subscription_id=subscription.id,
                title=episode.title,
                description=episode.description,
                audio_url=episode.audio_url,
                published_at=episode.published_at,
                audio_duration=episode.duration,
                transcript_url=episode.transcript_url,
                item_link=episode.link,
                metadata={"feed_title": feed.title}
            )

            if is_new:
                new_episodes.append(saved_episode)
                # 不在添加订阅时触发AI总结，避免会话冲突
                # 用户可以后续手动触发总结

        logger.info(f"用户{self.user_id} 添加播客: {feed.title}, {len(new_episodes)}期新节目")
        return subscription, new_episodes

    async def add_subscriptions_batch(
        self,
        subscriptions_data: List[PodcastSubscriptionCreate]
    ) -> List[Dict[str, Any]]:
        """批量添加播客订阅"""
        logger.info(f"开始批量添加订阅: {len(subscriptions_data)}个")
        results = []
        for sub_data in subscriptions_data:
            try:
                # 检查是否已存在记录 (通过URL)
                existing = await self.repo.get_subscription_by_url(self.user_id, sub_data.feed_url)
                if existing:
                    results.append({
                        "source_url": sub_data.feed_url,
                        "status": "skipped",
                        "message": "Subscription already exists"
                    })
                    continue
                
                # 添加订阅
                subscription, new_episodes = await self.add_subscription(
                    sub_data.feed_url,
                    sub_data.category_ids
                )
                
                results.append({
                    "source_url": sub_data.feed_url,
                    "status": "success",
                    "id": subscription.id,
                    "title": subscription.title,
                    "new_episodes": len(new_episodes)
                })
            except Exception as e:
                logger.error(f"批量添加订阅失败 {sub_data.feed_url}: {e}")
                # 回滚Session以清除错误状态
                try:
                    await self.repo.db.rollback()
                except Exception as rollback_error:
                    logger.warning(f"回滚Session失败: {rollback_error}")
                results.append({
                    "source_url": sub_data.feed_url,
                    "status": "error",
                    "message": str(e)
                })
        return results

    async def list_subscriptions(
        self,
        filters: Optional[dict] = None,
        page: int = 1,
        size: int = 20
    ) -> Tuple[List[dict], int]:
        """列出用户的所有播客订阅（支持分页和过滤）"""
        subscriptions, total = await self.repo.get_user_subscriptions_paginated(
            self.user_id,
            page=page,
            size=size,
            filters=filters
        )

        results = []
        for sub in subscriptions:
            # 获取最新3个单集
            episodes = await self.repo.get_subscription_episodes(sub.id, limit=3)
            episode_count = await self._get_episode_count(sub.id)
            unplayed_count = await self._get_unplayed_count(sub.id)

            # 从订阅配置中提取图片URL和其他元数据
            config = sub.config or {}
            image_url = config.get("image_url")
            author = config.get("author")
            platform = config.get("platform")
            # 处理categories格式 - 统一转换为字典列表
            raw_categories = config.get("categories") or []
            categories = []
            for cat in raw_categories:
                if isinstance(cat, str):
                    categories.append({"name": cat})
                elif isinstance(cat, dict):
                    categories.append(cat)
                else:
                    categories.append({"name": str(cat)})
            podcast_type = config.get("podcast_type")
            language = config.get("language")
            explicit = config.get("explicit", False)
            link = config.get("link")

            # 获取配置中的总集数（如果存在）
            total_episodes_from_config = config.get("total_episodes")

            # 将最新单集转换为字典
            latest_episode_dict = None
            if episodes:
                latest = episodes[0]
                latest_episode_dict = {
                    "id": latest.id,
                    "title": latest.title,
                    "audio_url": latest.audio_url,
                    "duration": latest.audio_duration,
                    "published_at": latest.published_at,
                    "ai_summary": latest.ai_summary,
                    "status": latest.status
                }

            results.append({
                "id": sub.id,
                "user_id": sub.user_id,
                "title": sub.title,
                "description": sub.description,
                "source_url": sub.source_url,
                "status": sub.status,
                "last_fetched_at": sub.last_fetched_at,
                "error_message": sub.error_message,
                "fetch_interval": sub.fetch_interval,
                "episode_count": episode_count,
                "unplayed_count": unplayed_count,
                "latest_episode": latest_episode_dict,
                "categories": categories,
                "image_url": image_url,
                "author": author,
                "platform": platform,
                "podcast_type": podcast_type,
                "language": language,
                "explicit": explicit,
                "link": link,
                "total_episodes_from_config": total_episodes_from_config,
                "created_at": sub.created_at,
                "updated_at": sub.updated_at
            })

        return results, total

    async def list_episodes(
        self,
        filters: Optional[dict] = None,
        page: int = 1,
        size: int = 20
    ) -> Tuple[List[dict], int]:
        """获取播客单集列表（支持分页和过滤）"""
        episodes, total = await self.repo.get_episodes_paginated(
            self.user_id,
            page=page,
            size=size,
            filters=filters
        )

        results = []
        for ep in episodes:
            # 获取用户播放状态
            playback = await self.repo.get_playback_state(self.user_id, ep.id)

            # 从订阅配置中提取图片URL
            subscription_image_url = None
            if ep.subscription and ep.subscription.config:
                subscription_image_url = ep.subscription.config.get("image_url")

            # Use episode image_url if available, otherwise fallback to subscription image
            image_url = ep.image_url or subscription_image_url

            results.append({
                "id": ep.id,
                "subscription_id": ep.subscription_id,
                "subscription_title": ep.subscription.title if ep.subscription else None,
                "subscription_image_url": subscription_image_url,
                "title": ep.title,
                "description": ep.description,
                "audio_url": ep.audio_url,
                "audio_duration": ep.audio_duration,
                "audio_file_size": ep.audio_file_size,
                "published_at": ep.published_at,
                "image_url": image_url,
                "item_link": ep.item_link,
                "transcript_url": ep.transcript_url,
                "transcript_content": ep.transcript_content,
                "ai_summary": ep.ai_summary,
                "summary_version": ep.summary_version,
                "ai_confidence_score": ep.ai_confidence_score,
                "play_count": ep.play_count,
                "last_played_at": ep.last_played_at,
                "season": ep.season,
                "episode_number": ep.episode_number,
                "explicit": ep.explicit,
                "status": ep.status,
                "metadata": ep.metadata_json,
                # 播放状态
                "playback_position": playback.current_position if playback else None,
                "is_playing": playback.is_playing if playback else False,
                "playback_rate": playback.playback_rate if playback else 1.0,
                "is_played": bool(playback and playback.current_position and
                             ep.audio_duration and
                             playback.current_position >= ep.audio_duration * 0.9),
                "created_at": ep.created_at,
                "updated_at": ep.updated_at
            })

        return results, total

    async def search_podcasts(
        self,
        query: str,
        search_in: str = "all",
        page: int = 1,
        size: int = 20
    ) -> Tuple[List[dict], int]:
        """搜索播客内容"""
        episodes, total = await self.repo.search_episodes(
            self.user_id,
            query=query,
            search_in=search_in,
            page=page,
            size=size
        )

        results = []
        for ep in episodes:
            # 获取用户播放状态
            playback = await self.repo.get_playback_state(self.user_id, ep.id)

            # 从订阅配置中提取图片URL
            subscription_image_url = None
            if ep.subscription and ep.subscription.config:
                subscription_image_url = ep.subscription.config.get("image_url")

            # Use episode image_url if available, otherwise fallback to subscription image
            image_url = ep.image_url or subscription_image_url

            results.append({
                "id": ep.id,
                "subscription_id": ep.subscription_id,
                "subscription_title": ep.subscription.title if ep.subscription else None,
                "subscription_image_url": subscription_image_url,
                "title": ep.title,
                "description": ep.description,
                "audio_url": ep.audio_url,
                "audio_duration": ep.audio_duration,
                "audio_file_size": ep.audio_file_size,
                "published_at": ep.published_at,
                "image_url": image_url,
                "item_link": ep.item_link,
                "transcript_url": ep.transcript_url,
                "transcript_content": ep.transcript_content,
                "ai_summary": ep.ai_summary,
                "summary_version": ep.summary_version,
                "ai_confidence_score": ep.ai_confidence_score,
                "play_count": ep.play_count,
                "last_played_at": ep.last_played_at,
                "season": ep.season,
                "episode_number": ep.episode_number,
                "explicit": ep.explicit,
                "status": ep.status,
                "metadata": ep.metadata_json,
                # 播放状态
                "playback_position": playback.current_position if playback else None,
                "is_playing": playback.is_playing if playback else False,
                "playback_rate": playback.playback_rate if playback else 1.0,
                "is_played": bool(playback and playback.current_position and
                             ep.audio_duration and
                             playback.current_position >= ep.audio_duration * 0.9),
                "created_at": ep.created_at,
                "updated_at": ep.updated_at,
                # 搜索相关性分数（如果存在）
                "relevance_score": getattr(ep, 'relevance_score', 1.0)
            })

        return results, total

    async def refresh_subscription(self, subscription_id: int) -> List[PodcastEpisode]:
        """刷新播客订阅，获取最新单集"""
        # 获取订阅信息
        sub = await self.repo.get_subscription_by_id(self.user_id, subscription_id)
        if not sub:
            raise ValueError("订阅不存在")

        # 解析RSS
        success, feed, error = await self.parser.fetch_and_parse_feed(sub.source_url)
        if not success:
            raise ValueError(f"刷新失败: {error}")

        # 保存新单集
        new_episodes = []
        for episode in feed.episodes:
            saved_episode, is_new = await self.repo.create_or_update_episode(
                subscription_id=subscription_id,
                title=episode.title,
                description=episode.description,
                audio_url=episode.audio_url,
                published_at=episode.published_at,
                audio_duration=episode.duration,
                transcript_url=episode.transcript_url,
                item_link=episode.link,
                metadata={"feed_title": feed.title, "refreshed_at": datetime.utcnow().isoformat()}
            )

            if is_new:
                new_episodes.append(saved_episode)
                # 异步触发转录任务（使用Celery）
                from app.domains.podcast.tasks import process_audio_transcription
                try:
                    # 创建并调度转录任务
                    task = await self.transcription_service.start_transcription(saved_episode.id)
                    logger.info(f"已为episode {saved_episode.id} 创建并调度转录任务 {task.id}")
                except Exception as e:
                    logger.error(f"创建转录任务失败 episode {saved_episode.id}: {e}")
                
                # 异步触发AI总结
                asyncio.create_task(self._generate_summary_task(saved_episode))

        # 更新订阅的最后抓取时间（使用最新分集的发布时间）
        await self.repo.update_subscription_fetch_time(subscription_id, feed.last_fetched)

        # 只在有新节目时输出日志
        if len(new_episodes) > 0:
            logger.info(f"用户{self.user_id} 刷新订阅: {sub.title}, 发现 {len(new_episodes)}期新节目")
        return new_episodes

    async def reparse_subscription(self, subscription_id: int, force_all: bool = False) -> dict:
        """
        重新解析订阅的所有单集（用于修复解析不全的问题）

        Args:
            subscription_id: 订阅ID
            force_all: 是否强制重新解析所有单集，默认只解析缺失的单集

        Returns:
            dict: 包含解析统计信息
        """
        # 获取订阅信息
        sub = await self.repo.get_subscription_by_id(self.user_id, subscription_id)
        if not sub:
            raise ValueError("订阅不存在")

        logger.info(f"用户{self.user_id} 开始重新解析订阅: {sub.title}")

        # 解析RSS
        success, feed, error = await self.parser.fetch_and_parse_feed(sub.source_url)
        if not success:
            raise ValueError(f"重新解析失败: {error}")

        # 获取当前已存在的单集item_links
        existing_item_links = set()
        if not force_all:
            existing_episodes = await self.repo.get_subscription_episodes(subscription_id, limit=None)
            existing_item_links = {ep.item_link for ep in existing_episodes if ep.item_link}
        # 保存单集
        processed = 0
        new_episodes = 0
        updated_episodes = 0
        failed = 0

        for episode in feed.episodes:
            # 如果不是强制全部重新解析，跳过已存在的
            if not force_all and episode.link in existing_item_links:
                continue

            try:
                # Debug: 记录 episode.link 的值
                logger.info(f"🔗 [REPARSE] Episode: {episode.title[:50]}...")
                logger.info(f"   - episode.link: {episode.link}")

                saved_episode, is_new = await self.repo.create_or_update_episode(
                    subscription_id=subscription_id,
                    title=episode.title,
                    description=episode.description,
                    audio_url=episode.audio_url,
                    published_at=episode.published_at,
                    audio_duration=episode.duration,
                    transcript_url=episode.transcript_url,
                    item_link=episode.link,
                    metadata={
                        "feed_title": feed.title,
                        "reparsed_at": datetime.utcnow().isoformat(),
                        "item_link": episode.link
                    }
                )

                processed += 1
                if is_new:
                    new_episodes += 1
                    # 不在reparse中触发AI总结，避免会话冲突
                    # 用户可以后续手动触发总结
                else:
                    updated_episodes += 1

            except Exception as e:
                # Use explicit logger access to avoid scoping issues
                logging.getLogger(__name__).error(f"重新解析单集失败: {episode.title}, 错误: {e}")
                failed += 1

        # 更新订阅配置和最后抓取时间
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
            "reparsed_at": datetime.utcnow().isoformat()
        }

        await self.repo.update_subscription_metadata(subscription_id, metadata)
        await self.repo.update_subscription_fetch_time(subscription_id, feed.last_fetched)

        result = {
            "subscription_id": subscription_id,
            "subscription_title": sub.title,
            "total_episodes_in_feed": len(feed.episodes),
            "processed": processed,
            "new_episodes": new_episodes,
            "updated_episodes": updated_episodes,
            "failed": failed,
            "message": f"重新解析完成: 处理{processed}个，新增{new_episodes}个，更新{updated_episodes}个，失败{failed}个"
        }

        logger.info(f"用户{self.user_id} 重新解析订阅完成: {result}")
        return result

    async def get_playback_state(self, episode_id: int) -> Optional[dict]:
        """获取播放状态"""
        playback = await self.repo.get_playback_state(self.user_id, episode_id)
        if not playback:
            return None

        episode = await self.repo.get_episode_by_id(episode_id)
        if not episode:
            return None

        progress_percentage = 0
        remaining_time = 0
        if episode.audio_duration and episode.audio_duration > 0:
            progress_percentage = (playback.current_position / episode.audio_duration) * 100
            remaining_time = max(0, episode.audio_duration - playback.current_position)

        return {
            "episode_id": episode_id,
            "current_position": playback.current_position,
            "is_playing": playback.is_playing,
            "playback_rate": playback.playback_rate,
            "play_count": playback.play_count,
            "last_updated_at": playback.last_updated_at,
            "progress_percentage": round(progress_percentage, 2),
            "remaining_time": remaining_time
        }

    async def get_user_stats(self) -> dict:
        """获取用户播客统计"""
        # 基础统计
        subscriptions = await self.repo.get_user_subscriptions(self.user_id)

        # 收听统计
        total_episodes = 0
        total_playtime = 0
        summaries_generated = 0
        pending_summaries = 0

        for sub in subscriptions:
            episodes = await self.repo.get_subscription_episodes(sub.id, limit=None)
            total_episodes += len(episodes)

            for ep in episodes:
                if ep.ai_summary:
                    summaries_generated += 1
                else:
                    pending_summaries += 1

                # 统计播放时间
                playback = await self.repo.get_playback_state(self.user_id, ep.id)
                if playback:
                    total_playtime += playback.current_position

        # 最近播放
        recently_played = await self.repo.get_recently_played(self.user_id, limit=5)

        # 连续收听天数
        listening_streak = await self._calculate_listening_streak()

        # 热门分类（TODO: 实现分类统计）
        top_categories = []

        return {
            "total_subscriptions": len(subscriptions),
            "total_episodes": total_episodes,
            "total_playtime": total_playtime,
            "summaries_generated": summaries_generated,
            "pending_summaries": pending_summaries,
            "recently_played": recently_played,
            "top_categories": top_categories,
            "listening_streak": listening_streak,
            "has_active_plus": any(s.status == "active" for s in subscriptions)
        }

    async def get_recommendations(self, limit: int = 10) -> List[dict]:
        """获取播客推荐"""
        # 基于用户收听历史推荐
        # 这里实现简单的推荐逻辑，实际应用中可以使用更复杂的算法

        # 1. 获取用户喜欢的播客（播放完成率高的）
        liked_episodes = await self.repo.get_liked_episodes(self.user_id, limit=20)

        # 2. 基于主题相似性推荐
        # TODO: 实现基于内容的推荐算法

        # 3. 返回推荐结果
        recommendations = []
        for ep in liked_episodes[:limit]:
            recommendations.append({
                "episode_id": ep.id,
                "title": ep.title,
                "description": ep.description[:150] + "...",
                "subscription_title": ep.subscription.title,
                "recommendation_reason": "基于您收听历史推荐",
                "match_score": 0.85
            })

        return recommendations

    async def get_subscription_details(self, subscription_id: int) -> Optional[dict]:
        """获取订阅详情及单集列表"""
        sub = await self.repo.get_subscription_by_id(self.user_id, subscription_id)
        if not sub:
            return None

        episodes = await self.repo.get_subscription_episodes(subscription_id, limit=50)
        pending_count = len([e for e in episodes if not e.ai_summary])

        # 从订阅配置中提取图片URL和其他元数据
        config = sub.config or {}
        image_url = config.get("image_url")
        author = config.get("author")
        categories = config.get("categories") or []
        podcast_type = config.get("podcast_type")
        language = config.get("language")
        explicit = config.get("explicit", False)
        link = config.get("link")

        return {
            "id": sub.id,
            "title": sub.title,
            "description": sub.description,
            "source_url": sub.source_url,
            "image_url": image_url,
            "author": author,
            "categories": categories,
            "podcast_type": podcast_type,
            "language": language,
            "explicit": explicit,
            "link": link,
            "episode_count": len(episodes),
            "pending_summaries": pending_count,
            "episodes": [{
                "id": ep.id,
                "title": ep.title,
                "description": ep.description[:100] + "..." if len(ep.description) > 100 else ep.description,
                "audio_url": ep.audio_url,
                "duration": ep.audio_duration,
                "published_at": ep.published_at,
                "has_summary": ep.ai_summary is not None,
                "summary": ep.ai_summary[:200] + "..." if ep.ai_summary and len(ep.ai_summary) > 200 else ep.ai_summary,
                "ai_confidence": ep.ai_confidence_score,
                "play_count": ep.play_count
            } for ep in episodes]
        }

    async def remove_subscription(self, subscription_id: int) -> bool:
        """删除订阅"""
        sub = await self.repo.get_subscription_by_id(self.user_id, subscription_id)
        if not sub:
            return False

        await self.db.delete(sub)
        await self.db.commit()
        logger.info(f"用户{self.user_id} 删除订阅: {sub.title}")
        return True

    # === 单集管理与AI总结 ===

    async def get_episode_by_id(self, episode_id: int) -> Optional[PodcastEpisode]:
        """获取单集详情"""
        return await self.repo.get_episode_by_id(episode_id, self.user_id)

    async def get_subscription_by_id(self, subscription_id: int) -> Optional[Subscription]:
        """获取订阅详情"""
        return await self.repo.get_subscription_by_id(self.user_id, subscription_id)

    async def get_episode_with_summary(self, episode_id: int) -> Optional[dict]:
        """获取单集详情和AI总结"""
        episode = await self.repo.get_episode_by_id(episode_id, self.user_id)
        if not episode:
            return None

        # 检查是否有待处理的总结
        if not episode.ai_summary and episode.status == "pending_summary":
            # 触发后台总结
            asyncio.create_task(self._generate_summary_task(episode))

        playback = await self.repo.get_playback_state(self.user_id, episode_id)

        # 从订阅配置中提取图片URL和其他元数据
        subscription_image_url = None
        subscription_author = None
        subscription_categories = []
        if episode.subscription and episode.subscription.config:
            config = episode.subscription.config
            subscription_image_url = config.get("image_url")
            subscription_author = config.get("author")
            subscription_categories = config.get("categories") or []

        return {
            "id": episode.id,
            "subscription_id": episode.subscription_id,
            "title": episode.title,
            "description": episode.description,
            "audio_url": episode.audio_url,
            "audio_duration": episode.audio_duration,
            "audio_file_size": episode.audio_file_size,
            "published_at": episode.published_at,
            "image_url": episode.image_url,
            "item_link": episode.item_link,
            "subscription_image_url": subscription_image_url,
            "transcript_url": episode.transcript_url,
            "transcript_content": episode.transcript_content,
            "ai_summary": episode.ai_summary,
            "summary_version": episode.summary_version,
            "ai_confidence_score": episode.ai_confidence_score,
            "play_count": episode.play_count,
            "last_played_at": episode.last_played_at,
            "season": episode.season,
            "episode_number": episode.episode_number,
            "explicit": episode.explicit,
            "status": episode.status,
            "metadata": episode.metadata_json or {},
            "created_at": episode.created_at,
            "updated_at": episode.updated_at,
            "playback_position": playback.current_position if playback else None,
            "is_playing": playback.is_playing if playback else False,
            "playback_rate": playback.playback_rate if playback else 1.0,
            "is_played": None,
            "subscription": {
                "id": episode.subscription.id,
                "title": episode.subscription.title,
                "description": episode.subscription.description,
                "image_url": subscription_image_url,
                "author": subscription_author,
                "categories": subscription_categories
            } if episode.subscription else None,
            "related_episodes": []
        }

    async def generate_summary_for_episode(self, episode_id: int) -> str:
        """
        为指定单集生成AI总结（同步方式，用于明确需要等待的场景）
        """
        episode = await self.repo.get_episode_by_id(episode_id, self.user_id)
        if not episode:
            raise ValueError("Episode not found")

        if episode.ai_summary:
            return episode.ai_summary

        return await self._generate_summary(episode)

    async def regenerate_summary(self, episode_id: int, force: bool = False) -> str:
        """
        重新生成总结
        force: 即使已有总结也重新生成
        """
        episode = await self.repo.get_episode_by_id(episode_id, self.user_id)
        if not episode:
            raise ValueError("Episode not found")

        if episode.ai_summary and not force:
            return episode.ai_summary

        return await self._generate_summary(episode, version="v2")

    async def get_pending_summaries(self) -> List[dict]:
        """获取待总结的单集"""
        subscriptions = await self.repo.get_user_subscriptions(self.user_id)
        results = []

        for sub in subscriptions:
            pending = await self.repo.get_unsummarized_episodes(sub.id)
            for episode in pending:
                results.append({
                    "episode_id": episode.id,
                    "subscription_title": sub.title,
                    "episode_title": episode.title,
                    "size_estimate": len(episode.description) + (len(episode.transcript_content) or 0)
                })

        return results

    # === 播放与进度管理 ===

    async def update_playback_progress(
        self,
        episode_id: int,
        progress_seconds: int,
        is_playing: bool = False,
        playback_rate: float = 1.0
    ) -> dict:
        """更新播放进度"""
        episode = await self.repo.get_episode_by_id(episode_id, self.user_id)
        if not episode:
            raise ValueError("Episode not found")

        playback = await self.repo.update_playback_progress(
            self.user_id,
            episode_id,
            progress_seconds,
            is_playing,
            playback_rate
        )

        return {
            "episode_id": episode_id,
            "progress": playback.current_position,
            "is_playing": playback.is_playing,
            "play_count": playback.play_count
        }

    # === 私有辅助方法 ===

    async def _generate_summary_task(self, episode: PodcastEpisode):
        """
        后台任务：异步生成AI总结

        注意：此方法运行在独立的后台任务中，需要创建自己的数据库 session，
        避免与主请求共享 session 导致 SQLAlchemy 并发错误。
        """
        from app.core.database import async_session_factory
        from app.domains.podcast.repositories import PodcastRepository
        from app.core.redis import PodcastRedis
        from app.core.config import settings
        from app.core.llm_privacy import ContentSanitizer

        # 创建独立的数据库 session 和服务实例
        async with async_session_factory() as session:
            try:
                # 创建独立的 repository 和 redis 实例
                repo = PodcastRepository(session, PodcastRedis())
                sanitizer = ContentSanitizer(mode=settings.LLM_CONTENT_SANITIZE_MODE)

                # 检查是否需要生成总结（使用独立的 session）
                await session.rollback()  # 确保干净状态
                stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode.id)
                result = await session.execute(stmt)
                fresh_episode = result.scalar_one_or_none()

                if not fresh_episode:
                    logger.warning(f"Episode {episode.id} 不存在，跳过总结生成")
                    return

                if fresh_episode.ai_summary:
                    logger.info(f"Episode {episode.id} 已有总结，跳过")
                    return

                # 使用独立 session 生成总结
                await self._generate_summary_with_session(
                    fresh_episode, session, repo, sanitizer
                )

            except Exception as e:
                logger.error(f"异步总结失败 episode:{episode.id}: {e}", exc_info=True)
                try:
                    await repo.mark_summary_failed(episode.id, str(e))
                except Exception as db_error:
                    logger.error(f"标记总结失败时出错 episode:{episode.id}: {db_error}")

    async def _generate_summary_with_session(
        self,
        episode: PodcastEpisode,
        session: AsyncSession,
        repo: PodcastRepository,
        sanitizer: 'ContentSanitizer'
    ) -> str:
        """使用指定 session 生成 AI 总结"""
        import asyncio
        from sqlalchemy import select

        # 检查锁，防止重复处理
        lock_key = f"summary:{episode.id}"
        if not await self.redis.acquire_lock(lock_key, expire=300):
            logger.info(f"总结任务已在进行中: episode_id={episode.id}")
            # 等待
            current_try = 0
            while current_try < 5:
                await asyncio.sleep(2)
                stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode.id)
                result = await session.execute(stmt)
                episode_check = result.scalar_one_or_none()
                if episode_check and episode_check.ai_summary:
                    return episode_check.ai_summary
                current_try += 1

        try:
            # 准备内容（优先使用转录文本）
            if episode.transcript_content:
                raw_content = episode.transcript_content
                content_type = "transcript"
                has_transcript = True
            else:
                raw_content = episode.description
                content_type = "description"
                has_transcript = False

            # 使用隐私净化器加工内容
            sanitized_prompt = sanitizer.sanitize(
                raw_content, self.user_id, f"podcast_{content_type}"
            )

            if not sanitized_prompt or len(sanitized_prompt.strip()) < 10:
                raise ValueError("内容太短或已被完全过滤")

            # 调用AI生成总结
            summary = await self._call_llm_for_summary(
                episode_title=episode.title,
                content=sanitized_prompt,
                content_type=content_type
            )

            # 保存到数据库和缓存
            await repo.update_ai_summary(
                episode.id,
                summary,
                version="v1",
                transcript_used=has_transcript
            )

            logger.info(f"AI总结完成 episode:{episode.id} ({content_type})")
            return summary

        except Exception as e:
            logger.error(f"生成AI总结失败 episode:{episode.id}: {e}")
            await repo.mark_summary_failed(episode.id, str(e))
            raise
        finally:
            await self.redis.release_lock(lock_key)

    async def _generate_summary(self, episode: PodcastEpisode, version: str = "v1") -> str:
        """核心AI总结生成逻辑"""
        # 检查锁，防止重复处理
        lock_key = f"summary:{episode.id}"
        if not await self.redis.acquire_lock(lock_key, expire=300):
            logger.info(f"总结任务已在进行中: episode_id={episode.id}")
            # 等待
            current_try = 0
            while current_try < 5:
                await asyncio.sleep(2)
                episode = await self.repo.get_episode_by_id(episode.id)  # Refresh
                if episode and episode.ai_summary:
                    return episode.ai_summary
                current_try += 1

        try:
            # 准备内容（优先使用转录文本）
            if episode.transcript_content:
                raw_content = episode.transcript_content
                content_type = "transcript"
                has_transcript = True
            else:
                raw_content = episode.description
                content_type = "description"
                has_transcript = False

            # 使用隐私净化器加工内容
            sanitized_prompt = self.sanitizer.sanitize(
                raw_content, self.user_id, f"podcast_{content_type}"
            )

            if not sanitized_prompt or len(sanitized_prompt.strip()) < 10:
                raise ValueError("内容太短或已被完全过滤")

            # 调用AI生成总结
            summary = await self._call_llm_for_summary(
                episode_title=episode.title,
                content=sanitized_prompt,
                content_type=content_type
            )

            # 保存到数据库和缓存
            await self.repo.update_ai_summary(
                episode.id,
                summary,
                version=version,
                transcript_used=has_transcript
            )

            logger.info(f"AI总结完成 episode:{episode.id} ({content_type})")
            return summary

        except Exception as e:
            logger.error(f"生成AI总结失败 episode:{episode.id}: {e}")
            await self.repo.mark_summary_failed(episode.id, str(e))
            raise
        finally:
            await self.redis.release_lock(lock_key)

    async def _call_llm_for_summary(
        self,
        episode_title: str,
        content: str,
        content_type: str
    ) -> str:
        """
        调用LLM API生成总结
        从数据库中的AI模型配置按优先级获取API key，实现fallback机制
        """
        from openai import AsyncOpenAI
        from app.domains.ai.repositories import AIModelConfigRepository
        from app.domains.ai.models import ModelType
        from app.core.security import decrypt_data
        from app.core.database import async_session_factory
        from openai import AuthenticationError, APIError, APIConnectionError, RateLimitError

        # 创建独立的数据库会话以避免并发问题
        async with async_session_factory() as ai_session:
            ai_repo = AIModelConfigRepository(ai_session)
            model_configs = await ai_repo.get_active_models_by_priority(ModelType.TEXT_GENERATION)

            if not model_configs:
                # 数据库中没有配置任何 API key
                logger.error("数据库中未配置任何启用的 TEXT_GENERATION 类型的 API key，跳过 AI 总结生成")
                return self._rule_based_summary(episode_title, content)

            # 按 priority 排序（数字越小优先级越高），依次尝试每个 API 配置
            last_error = None
            for idx, model_config in enumerate(model_configs):
                api_key = None
                try:
                    # 解密 API key
                    if model_config.api_key:
                        if model_config.api_key_encrypted:
                            api_key = decrypt_data(model_config.api_key)
                        else:
                            api_key = model_config.api_key

                    if not api_key:
                        logger.warning(f"模型配置 [{model_config.display_name or model_config.name}] (priority={model_config.priority}) 的 API key 为空，跳过")
                        continue

                    logger.info(f"尝试使用模型配置 [{model_config.display_name or model_config.name}] (priority={model_config.priority}, 尝试 {idx + 1}/{len(model_configs)})")

                    client = AsyncOpenAI(
                        api_key=api_key,
                        base_url=model_config.base_url if model_config.base_url else None
                    )

                    # 构建Prompt
                    system_prompt = """
你是一位专业的播客总结专家。你的任务是从播客单集内容中提取最有价值的信息。

请提取以下信息：
1. 主要话题和讨论点
2. 关键见解和结论
3. 可执行的建议
4. 需要进一步研究的领域

输出格式：
## 主要话题
[3-5个要点]

## 关键见解
[深入洞察]

## 行动建议
[具体步骤]

## 扩展思考
[关联问题]
"""

                    user_prompt = f"""
播客标题: {episode_title}
内容类型: {content_type}
内容: {content[:2000]}  <!-- 限制输入长度 -->

请提供详细总结（150-300字）。
"""

                    response = await client.chat.completions.create(
                        model=model_config.model_name if model_config.model_name else "gpt-4o-mini",
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt}
                        ],
                        temperature=0.7,
                        max_tokens=500
                    )

                    # 成功获取响应，记录并返回
                    logger.info(f"成功使用模型配置 [{model_config.display_name or model_config.name}] (priority={model_config.priority}) 生成总结")
                    return response.choices[0].message.content.strip()

                except AuthenticationError as e:
                    last_error = e
                    logger.error(f"模型配置 [{model_config.display_name or model_config.name}] (priority={model_config.priority}) 认证失败: {e}")
                except RateLimitError as e:
                    last_error = e
                    logger.error(f"模型配置 [{model_config.display_name or model_config.name}] (priority={model_config.priority}) 达到速率限制: {e}")
                except APIConnectionError as e:
                    last_error = e
                    logger.error(f"模型配置 [{model_config.display_name or model_config.name}] (priority={model_config.priority}) 连接失败: {e}")
                except APIError as e:
                    last_error = e
                    logger.error(f"模型配置 [{model_config.display_name or model_config.name}] (priority={model_config.priority}) API 错误: {e}")
                except Exception as e:
                    last_error = e
                    logger.error(f"模型配置 [{model_config.display_name or model_config.name}] (priority={model_config.priority}) 未知错误: {type(e).__name__}: {e}")

            # 所有 API 配置都失败了
            logger.error(f"所有 {len(model_configs)} 个 TEXT_GENERATION 模型配置均访问失败，最后错误: {type(last_error).__name__}: {last_error}")
            return self._rule_based_summary(episode_title, content)

    def _rule_based_summary(self, title: str, content: str) -> str:
        """如果没有LLM，使用规则生成基本总结"""
        # 关键词提取
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

    async def _get_episode_count(self, subscription_id: int) -> int:
        """获取订阅的单集数量"""
        # 简化实现，实际可缓存
        episodes = await self.repo.get_subscription_episodes(subscription_id, limit=9999)
        return len(episodes)

    async def _get_unplayed_count(self, subscription_id: int) -> int:
        """获取未播放的单集数量"""
        episodes = await self.repo.get_subscription_episodes(subscription_id, limit=None)
        unplayed = 0

        for ep in episodes:
            playback = await self.repo.get_playback_state(self.user_id, ep.id)
            if not playback or not playback.current_position or \
               (ep.audio_duration and playback.current_position < ep.audio_duration * 0.9):
                unplayed += 1

        return unplayed

    async def _calculate_listening_streak(self) -> int:
        """计算连续收听天数"""
        # 获取最近30天的播放记录
        recent_plays = await self.repo.get_recent_play_dates(self.user_id, days=30)

        if not recent_plays:
            return 0

        # 计算连续天数
        streak = 1  # 今天
        from datetime import date, timedelta
        today = date.today()

        for i in range(1, 30):
            check_date = today - timedelta(days=i)
            if check_date in recent_plays:
                streak += 1
            else:
                break

        return streak

    # === 批量删除订阅 ===

    async def remove_subscriptions_bulk(
        self,
        subscription_ids: List[int]
    ) -> Dict[str, Any]:
        """
        批量删除播客订阅

        删除顺序（按外键依赖关系）:
        1. conversations (通过 episode_id)
        2. playback_progress (podcast_playback_states)
        3. transcriptions (transcription_tasks)
        4. episodes (podcast_episodes)
        5. subscriptions

        Args:
            subscription_ids: 要删除的订阅ID列表

        Returns:
            dict: {
                "success_count": int,
                "failed_count": int,
                "errors": List[Dict[str, Any]],
                "deleted_subscription_ids": List[int]
            }
        """
        from sqlalchemy import delete, and_
        from app.domains.podcast.models import (
            PodcastEpisode,
            PodcastPlaybackState,
            TranscriptionTask,
            PodcastConversation
        )
        from app.domains.subscription.models import Subscription

        success_count = 0
        failed_count = 0
        errors: List[Dict[str, Any]] = []
        deleted_subscription_ids: List[int] = []

        for subscription_id in subscription_ids:
            try:
                # 使用显式事务确保删除操作的原子性
                async with self.db.begin():
                    # 1. 验证订阅存在且属于当前用户
                    stmt = select(Subscription).where(
                        and_(
                            Subscription.id == subscription_id,
                            Subscription.user_id == self.user_id,
                            Subscription.source_type == "podcast-rss"
                        )
                    )
                    result = await self.db.execute(stmt)
                    subscription = result.scalar_one_or_none()

                    if not subscription:
                        errors.append({
                            "subscription_id": subscription_id,
                            "error": f"订阅 {subscription_id} 不存在或无权访问"
                        })
                        failed_count += 1
                        continue

                    # 获取该订阅的所有 episode_id
                    ep_stmt = select(PodcastEpisode.id).where(
                        PodcastEpisode.subscription_id == subscription_id
                    )
                    ep_result = await self.db.execute(ep_stmt)
                    episode_ids = [row[0] for row in ep_result.fetchall()]

                    # 2. 删除 conversations (通过 episode_id)
                    # 使用 synchronize_session=False 避免 SQLAlchemy 自引用关系递归问题
                    if episode_ids:
                        conv_delete = delete(PodcastConversation).where(
                            PodcastConversation.episode_id.in_(episode_ids)
                        ).execution_options(synchronize_session="fetch")
                        await self.db.execute(conv_delete)

                    # 3. 删除 playback_progress (podcast_playback_states)
                    if episode_ids:
                        playback_delete = delete(PodcastPlaybackState).where(
                            PodcastPlaybackState.episode_id.in_(episode_ids)
                        ).execution_options(synchronize_session="fetch")
                        await self.db.execute(playback_delete)

                    # 4. 删除 transcriptions (transcription_tasks)
                    if episode_ids:
                        trans_delete = delete(TranscriptionTask).where(
                            TranscriptionTask.episode_id.in_(episode_ids)
                        ).execution_options(synchronize_session="fetch")
                        await self.db.execute(trans_delete)

                    # 5. 删除 episodes (podcast_episodes)
                    episode_delete = delete(PodcastEpisode).where(
                        PodcastEpisode.subscription_id == subscription_id
                    ).execution_options(synchronize_session="fetch")
                    await self.db.execute(episode_delete)

                    # 6. 删除 subscription
                    sub_delete = delete(Subscription).where(
                        Subscription.id == subscription_id
                    ).execution_options(synchronize_session="fetch")
                    await self.db.execute(sub_delete)

                # 事务提交成功，记录成功
                success_count += 1
                deleted_subscription_ids.append(subscription_id)
                logger.info(f"用户 {self.user_id} 批量删除订阅 {subscription_id} 成功")

            except Exception as e:
                # 事务会自动回滚
                logger.error(f"批量删除订阅 {subscription_id} 失败: {e}")
                errors.append({
                    "subscription_id": subscription_id,
                    "error": str(e)
                })
                failed_count += 1

        return {
            "success_count": success_count,
            "failed_count": failed_count,
            "errors": errors,
            "deleted_subscription_ids": deleted_subscription_ids
        }
