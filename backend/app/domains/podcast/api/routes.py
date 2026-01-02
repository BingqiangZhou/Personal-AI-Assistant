"""
播客API路由 - /api/v1/podcasts/*

终端路由:
POST   /podcasts/subscription           添加播客订阅
GET    /podcasts/subscription           列出所有订阅
GET    /podcasts/subscription/{id}      获取订阅详情
DELETE /podcasts/subscription/{id}      删除订阅

GET    /podcasts/episodes/feed          获取播客信息流
GET    /podcasts/episodes               获取单集列表
GET    /podcasts/episodes/{id}          获取单集详情
POST   /podcasts/episodes/{id}/summary  触发AI总结
POST   /podcasts/episodes/{id}/progress 更新播放进度

GET    /podcasts/summary/pending        待总结列表
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Header, status, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db_session
from app.core.security import get_token_from_request
from app.domains.podcast.services import PodcastService
from app.domains.podcast.repositories import PodcastRepository
from app.domains.podcast.transcription import PodcastTranscriptionService, AISummaryService
from app.domains.podcast.models import TranscriptionStatus
from app.domains.podcast.transcription_manager import DatabaseBackedTranscriptionService
from app.domains.podcast.summary_manager import DatabaseBackedAISummaryService
from app.domains.podcast.transcription_state import get_transcription_state_manager

logger = logging.getLogger(__name__)
from app.domains.podcast.transcription_scheduler import (
    TranscriptionScheduler,
    AutomatedTranscriptionScheduler,
    ScheduleFrequency,
    schedule_episode_transcription,
    get_episode_transcript,
    batch_transcribe_subscription
)
from app.domains.podcast.schemas import (
    PodcastSubscriptionCreate,
    PodcastSubscriptionResponse,
    PodcastSubscriptionListResponse,
    PodcastEpisodeResponse,
    PodcastEpisodeListResponse,
    PodcastEpisodeDetailResponse,
    PodcastFeedResponse,
    PodcastPlaybackUpdate,
    PodcastPlaybackStateResponse,
    PodcastSummaryRequest,
    PodcastSummaryResponse,
    PodcastSummaryPendingResponse,
    SummaryModelInfo,
    SummaryModelsResponse,
    PodcastEpisodeFilter,
    PodcastSearchFilter,
    PodcastStatsResponse,
    PodcastTranscriptionRequest,
    PodcastTranscriptionResponse,
    PodcastTranscriptionDetailResponse,
    PodcastTranscriptionListResponse,
    PodcastTranscriptionStatusResponse,
    PodcastTranscriptionChunkInfo,
    PodcastConversationSendRequest,
    PodcastConversationSendResponse,
    PodcastConversationHistoryResponse,
    PodcastConversationClearResponse,
    PodcastConversationMessage,
    ScheduleConfigUpdate,
    ScheduleConfigResponse,
    PodcastSubscriptionBatchResponse,
    PodcastSubscriptionBulkDelete,
    PodcastSubscriptionBulkDeleteResponse
)

router = APIRouter(prefix="")

logger = logging.getLogger(__name__)


# === 订阅管理 ===

@router.post(
    "/subscriptions",
    status_code=status.HTTP_201_CREATED,
    response_model=PodcastSubscriptionResponse,
    summary="添加播客订阅",
    description="通过RSS链接添加播客订阅，并自动生成前几期音频的AI总结"
)
async def add_subscription(
    subscription_data: PodcastSubscriptionCreate,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """
    请求示例:
    ```json
    {
        "feed_url": "https://feeds.soundcloud.com/users/soundcloud:users:123456/tracks.rss",
        "custom_name": "我的播客",
        "category_ids": [1, 2]
    }
    ```
    """
    service = PodcastService(db, int(user["sub"]))
    try:
        subscription, new_episodes = await service.add_subscription(
            feed_url=subscription_data.feed_url,
            category_ids=subscription_data.category_ids
        )

        # 转换为响应模型
        response_data = {
            "id": subscription.id,
            "user_id": subscription.user_id,
            "title": subscription.title,
            "description": subscription.description,
            "source_url": subscription.source_url,
            "status": subscription.status,
            "last_fetched_at": subscription.last_fetched_at,
            "error_message": subscription.error_message,
            "fetch_interval": subscription.fetch_interval,
            "episode_count": len(new_episodes),
            "unplayed_count": len(new_episodes),
            "created_at": subscription.created_at,
            "updated_at": subscription.updated_at
        }

        return PodcastSubscriptionResponse(**response_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"添加订阅失败: {str(e)}")


@router.post(
    "/subscriptions/bulk",
    response_model=PodcastSubscriptionBatchResponse,
    summary="批量添加播客订阅"
)
async def create_subscriptions_batch(
    subscriptions_data: List[PodcastSubscriptionCreate],
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """批量添加播客订阅"""
    service = PodcastService(db, int(user["sub"]))
    results = await service.add_subscriptions_batch(subscriptions_data)
    
    success_count = sum(1 for r in results if r["status"] == "success")
    skipped_count = sum(1 for r in results if r["status"] == "skipped")
    error_count = sum(1 for r in results if r["status"] == "error")
    
    return PodcastSubscriptionBatchResponse(
        results=results,
        total_requested=len(subscriptions_data),
        success_count=success_count,
        skipped_count=skipped_count,
        error_count=error_count
    )


@router.get(
    "/subscriptions",
    response_model=PodcastSubscriptionListResponse,
    summary="列出所有播客订阅"
)
async def list_subscriptions(
    page: int = Query(1, ge=1, description="页码"),
    size: int = Query(20, ge=1, le=100, description="每页数量"),
    category_id: Optional[int] = Query(None, description="分类ID筛选"),
    status: Optional[str] = Query(None, description="状态筛选"),
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """返回用户的所有播客订阅及其最新节目"""
    service = PodcastService(db, int(user["sub"]))

    # 构建过滤器
    filters = PodcastSearchFilter(
        category_id=category_id,
        status=status
    )

    subscriptions, total = await service.list_subscriptions(
        filters=filters,
        page=page,
        size=size
    )

    # 转换为响应模型
    subscription_responses = []
    for sub in subscriptions:
        subscription_responses.append(PodcastSubscriptionResponse(**sub))

    pages = (total + size - 1) // size
    return PodcastSubscriptionListResponse(
        subscriptions=subscription_responses,
        total=total,
        page=page,
        size=size,
        pages=pages
    )


# === 批量操作路由 (必须在单个订阅路由之前，避免路径参数匹配冲突) ===

@router.post(
    "/subscriptions/bulk-delete",
    response_model=PodcastSubscriptionBulkDeleteResponse,
    summary="批量删除播客订阅",
    description="批量删除多个播客订阅及其关联的单集、播放进度、转录和对话数据"
)
async def delete_subscriptions_bulk(
    request: PodcastSubscriptionBulkDelete,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """
    批量删除播客订阅

    请求示例:
    ```json
    {
        "subscription_ids": [1, 2, 3]
    }
    ```

    删除顺序（按外键依赖关系）:
    1. conversations (对话记录)
    2. playback_progress (播放进度)
    3. transcriptions (转录任务)
    4. episodes (单集)
    5. subscriptions (订阅)

    权限验证：确保所有订阅都属于当前用户
    """
    service = PodcastService(db, int(user["sub"]))

    result = await service.remove_subscriptions_bulk(request.subscription_ids)

    return PodcastSubscriptionBulkDeleteResponse(
        success_count=result["success_count"],
        failed_count=result["failed_count"],
        errors=result["errors"],
        deleted_subscription_ids=result["deleted_subscription_ids"]
    )


# === 单个订阅路由 ===

@router.get(
    "/subscriptions/{subscription_id}",
    response_model=PodcastSubscriptionResponse,
    summary="获取订阅详情"
)
async def get_subscription(
    subscription_id: int,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """获取订阅详情"""
    service = PodcastService(db, int(user["sub"]))
    details = await service.get_subscription_details(subscription_id)
    if not details:
        raise HTTPException(status_code=404, detail="订阅不存在或无权限")
    return PodcastSubscriptionResponse(**details)


@router.delete(
    "/subscriptions/{subscription_id}",
    summary="删除订阅"
)
async def delete_subscription(
    subscription_id: int,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """删除订阅和关联的单集数据"""
    service = PodcastService(db, int(user["sub"]))
    success = await service.remove_subscription(subscription_id)
    if not success:
        raise HTTPException(status_code=404, detail="订阅不存在")
    return {"success": True, "message": "订阅已删除"}


@router.get(
    "/subscriptions/{subscription_id}/schedule",
    response_model=ScheduleConfigResponse,
    summary="Get subscription schedule configuration",
    description="Get the current schedule configuration for a subscription"
)
async def get_subscription_schedule(
    subscription_id: int,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """Get subscription schedule configuration"""
    from app.domains.subscription.models import Subscription
    from sqlalchemy import select

    stmt = select(Subscription).where(
        Subscription.id == subscription_id
    ).where(
        Subscription.user_id == int(user['sub'])
    )

    result = await db.execute(stmt)
    subscription = result.scalar_one_or_none()

    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Subscription not found"
        )

    return ScheduleConfigResponse(
        id=subscription.id,
        title=subscription.title,
        update_frequency=subscription.update_frequency,
        update_time=subscription.update_time,
        update_day_of_week=subscription.update_day_of_week,
        fetch_interval=subscription.fetch_interval,
        next_update_at=subscription.next_update_at,
        last_updated_at=subscription.last_fetched_at
    )


@router.patch(
    "/subscriptions/{subscription_id}/schedule",
    response_model=ScheduleConfigResponse,
    summary="Update subscription schedule configuration",
    description="Update the schedule configuration for a subscription"
)
async def update_subscription_schedule(
    subscription_id: int,
    schedule_data: ScheduleConfigUpdate,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """Update subscription schedule configuration"""
    from app.domains.subscription.models import Subscription
    from sqlalchemy import select

    stmt = select(Subscription).where(
        Subscription.id == subscription_id
    ).where(
        Subscription.user_id == int(user['sub'])
    )

    result = await db.execute(stmt)
    subscription = result.scalar_one_or_none()

    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Subscription not found"
        )

    # Update schedule configuration
    subscription.update_frequency = schedule_data.update_frequency
    subscription.update_time = schedule_data.update_time
    subscription.update_day_of_week = schedule_data.update_day_of_week

    if schedule_data.fetch_interval is not None:
        subscription.fetch_interval = schedule_data.fetch_interval

    await db.commit()
    await db.refresh(subscription)

    return ScheduleConfigResponse(
        id=subscription.id,
        title=subscription.title,
        update_frequency=subscription.update_frequency,
        update_time=subscription.update_time,
        update_day_of_week=subscription.update_day_of_week,
        fetch_interval=subscription.fetch_interval,
        next_update_at=subscription.next_update_at,
        last_updated_at=subscription.last_fetched_at
    )


# === 单集管理 ===

@router.get(
    "/episodes/feed",
    response_model=PodcastFeedResponse,
    summary="获取播客信息流"
)
async def get_podcast_feed(
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(10, ge=1, le=50, description="每页数量"),
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """获取用户订阅的所有播客分集，按发布时间倒序排列"""
    service = PodcastService(db, int(user["sub"]))

    # 获取用户所有订阅的播客分集
    episodes, total = await service.list_episodes(
        filters=None,  # 不过滤，获取所有订阅的分集
        page=page,
        size=page_size
    )

    # 转换为响应模型
    episode_responses = []
    for ep in episodes:
        episode_responses.append(PodcastEpisodeResponse(**ep))

    # 计算是否还有更多数据
    has_more = (page * page_size) < total
    next_page = page + 1 if has_more else None

    return PodcastFeedResponse(
        items=episode_responses,
        has_more=has_more,
        next_page=next_page,
        total=total
    )


@router.get(
    "/episodes",
    response_model=PodcastEpisodeListResponse,
    summary="获取单集列表"
)
async def list_episodes(
    subscription_id: Optional[int] = Query(None, description="订阅ID筛选"),
    page: int = Query(1, ge=1, description="页码"),
    size: int = Query(20, ge=1, le=100, description="每页数量"),
    has_summary: Optional[bool] = Query(None, description="是否有AI总结"),
    is_played: Optional[bool] = Query(None, description="是否已播放"),
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """获取播客单集列表"""
    service = PodcastService(db, int(user["sub"]))

    # 构建过滤器
    filters = PodcastEpisodeFilter(
        subscription_id=subscription_id,
        has_summary=has_summary,
        is_played=is_played
    )

    episodes, total = await service.list_episodes(
        filters=filters,
        page=page,
        size=size
    )

    # 转换为响应模型
    episode_responses = []
    for ep in episodes:
        episode_responses.append(PodcastEpisodeResponse(**ep))

    pages = (total + size - 1) // size
    return PodcastEpisodeListResponse(
        episodes=episode_responses,
        total=total,
        page=page,
        size=size,
        pages=pages,
        subscription_id=subscription_id or 0
    )


@router.get(
    "/episodes/{episode_id}",
    response_model=PodcastEpisodeDetailResponse,
    summary="获取单集详情"
)
async def get_episode(
    episode_id: int,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """获取单集详情，包含AI总结（如有）"""
    service = PodcastService(db, int(user["sub"]))
    episode = await service.get_episode_with_summary(episode_id)
    if not episode:
        raise HTTPException(status_code=404, detail="单集不存在或无权限")
    return PodcastEpisodeDetailResponse(**episode)


@router.post(
    "/episodes/{episode_id}/summary",
    response_model=PodcastSummaryResponse,
    summary="生成(或重新生成)AI总结"
)
async def generate_summary(
    episode_id: int,
    request: PodcastSummaryRequest,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """
    功能:
    - 如果没有总结，立即生成
    - 如果有总结，force=true时重新生成
    - 支持切换AI模型和自定义提示词
    """
    service = PodcastService(db, int(user["sub"]))
    ai_summary_service = DatabaseBackedAISummaryService(db)

    try:
        # 验证播客单集存在且属于当前用户
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found"
            )

        # 验证用户权限
        if episode.subscription.user_id != int(user["sub"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this episode"
            )

        # 生成或重新生成总结
        summary_result = await ai_summary_service.generate_summary(
            episode_id,
            request.summary_model,
            request.custom_prompt
        )

        # 返回总结响应
        return PodcastSummaryResponse(
            episode_id=episode_id,
            summary=summary_result["summary_content"],
            version="1.0",
            confidence_score=None,
            transcript_used=True,
            generated_at=datetime.utcnow(),
            word_count=len(summary_result["summary_content"].split()),
            model_used=summary_result["model_name"],
            processing_time=summary_result["processing_time"]
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to generate summary for episode {episode_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put(
    "/episodes/{episode_id}/playback",
    response_model=PodcastPlaybackStateResponse,
    summary="更新播放进度"
)
async def update_playback_progress(
    episode_id: int,
    playback_data: PodcastPlaybackUpdate,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """更新播客播放进度和状态"""
    service = PodcastService(db, int(user["sub"]))
    try:
        result = await service.update_playback_progress(
            episode_id,
            playback_data.position,
            playback_data.is_playing,
            playback_data.playback_rate
        )

        return PodcastPlaybackStateResponse(
            episode_id=episode_id,
            current_position=result["progress"],
            is_playing=result["is_playing"],
            playback_rate=result.get("playback_rate", 1.0),
            play_count=result.get("play_count", 0),
            last_updated_at=result.get("last_updated_at", datetime.utcnow()),
            progress_percentage=result.get("progress_percentage", 0),
            remaining_time=result.get("remaining_time", 0)
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/episodes/{episode_id}/playback",
    response_model=PodcastPlaybackStateResponse,
    summary="获取播放状态"
)
async def get_playback_state(
    episode_id: int,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """获取播客播放状态"""
    service = PodcastService(db, int(user["sub"]))
    try:
        playback = await service.get_playback_state(episode_id)
        if not playback:
            raise HTTPException(status_code=404, detail="播放记录不存在")

        return PodcastPlaybackStateResponse(**playback)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get(
    "/summaries/pending",
    response_model=PodcastSummaryPendingResponse,
    summary="待AI总结的单集"
)
async def get_pending_summaries(
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """列出所有需要AI总结的单集"""
    service = PodcastService(db, int(user["sub"]))
    pending = await service.get_pending_summaries()
    return PodcastSummaryPendingResponse(
        count=len(pending),
        episodes=pending
    )


@router.get(
    "/summaries/models",
    response_model=SummaryModelsResponse,
    summary="获取可用的AI总结模型列表"
)
async def get_summary_models(
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """获取所有可用的AI总结模型"""
    ai_summary_service = DatabaseBackedAISummaryService(db)

    try:
        models = await ai_summary_service.get_summary_models()

        # 转换为SummaryModelInfo格式
        model_infos = [
            SummaryModelInfo(
                id=model["id"],
                name=model["name"],
                display_name=model["display_name"],
                provider=model["provider"],
                model_id=model["model_id"],
                is_default=model["is_default"]
            )
            for model in models
        ]

        return SummaryModelsResponse(
            models=model_infos,
            total=len(model_infos)
        )
    except Exception as e:
        logger.error(f"Failed to get summary models: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# === 搜索功能 ===

@router.get(
    "/search",
    response_model=PodcastEpisodeListResponse,
    summary="搜索播客内容"
)
async def search_podcasts(
    q: str = Query(..., min_length=1, description="搜索关键词"),
    search_in: Optional[str] = Query("all", description="搜索范围: title, description, summary, all"),
    page: int = Query(1, ge=1, description="页码"),
    size: int = Query(20, ge=1, le=100, description="每页数量"),
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """搜索播客和单集内容"""
    service = PodcastService(db, int(user["sub"]))

    episodes, total = await service.search_podcasts(
        query=q,
        search_in=search_in,
        page=page,
        size=size
    )

    # 转换为响应模型
    episode_responses = []
    for ep in episodes:
        episode_responses.append(PodcastEpisodeResponse(**ep))

    pages = (total + size - 1) // size
    return PodcastEpisodeListResponse(
        episodes=episode_responses,
        total=total,
        page=page,
        size=size,
        pages=pages,
        subscription_id=0
    )


# === 统计信息 ===

@router.get(
    "/stats",
    response_model=PodcastStatsResponse,
    summary="获取播客统计信息"
)
async def get_podcast_stats(
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """获取用户的播客收听统计"""
    service = PodcastService(db, int(user["sub"]))
    stats = await service.get_user_stats()
    return PodcastStatsResponse(**stats)


# === 批量操作 ===

@router.post(
    "/subscriptions/{subscription_id}/refresh",
    summary="刷新订阅"
)
async def refresh_subscription(
    subscription_id: int,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """手动刷新播客订阅，获取最新单集"""
    service = PodcastService(db, int(user["sub"]))
    try:
        new_episodes = await service.refresh_subscription(subscription_id)
        return {
            "success": True,
            "new_episodes": len(new_episodes),
            "message": f"已更新，发现 {len(new_episodes)} 期新节目"
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/subscriptions/{subscription_id}/reparse",
    summary="重新解析订阅（修复解析不全问题）"
)
async def reparse_subscription(
    subscription_id: int,
    force_all: bool = False,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """
    重新解析订阅的所有单集，用于修复解析不全的问题

    - 默认只解析缺失的单集
    - force_all=true 时强制重新解析所有单集
    """
    service = PodcastService(db, int(user["sub"]))
    try:
        result = await service.reparse_subscription(subscription_id, force_all=force_all)
        return {
            "success": True,
            "result": result
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# === 推荐功能 ===

@router.get(
    "/recommendations",
    response_model=List[dict],
    summary="获取播客推荐"
)
async def get_recommendations(
    limit: int = Query(10, ge=1, le=50, description="推荐数量"),
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """基于用户收听历史获取播客推荐"""
    service = PodcastService(db, int(user["sub"]))
    recommendations = await service.get_recommendations(limit=limit)
    return recommendations


# === 转录功能 ===

@router.post(
    "/episodes/{episode_id}/transcribe",
    status_code=status.HTTP_201_CREATED,
    response_model=PodcastTranscriptionResponse,
    summary="启动播客单集转录",
    description="为指定的播客单集启动音频转录任务"
)
async def start_transcription(
    episode_id: int,
    transcription_request: PodcastTranscriptionRequest,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """
    请求示例:
    ```json
    {
        "force_regenerate": false,
        "chunk_size_mb": 10
    }
    ```

    工作流程:
    1. 检查Redis缓存是否有正在进行的任务（快速路径）
    2. 检查数据库是否有已完成的转录
    3. 如果都不存在，创建新任务并立即返回task_id
    4. 后台Celery worker异步处理转录
    """
    service = PodcastService(db, int(user["sub"]))
    transcription_service = DatabaseBackedTranscriptionService(db)
    state_manager = await get_transcription_state_manager()

    try:
        # 验证播客单集存在且属于当前用户
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found"
            )

        # 验证用户权限
        if episode.subscription.user_id != int(user["sub"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this episode"
            )

        # === FAST PATH 1: Check Redis for in-progress task ===
        redis_task_id = await state_manager.get_episode_task(episode_id)
        if redis_task_id:
            # Get task progress from Redis cache
            cached_progress = await state_manager.get_task_progress(redis_task_id)
            if cached_progress and cached_progress.get("status") not in ["completed", "failed"]:
                logger.info(f"⚡ [REDIS] Returning cached in-progress task {redis_task_id} for episode {episode_id}")
                # Return cached task data
                task = await transcription_service.get_transcription_status(redis_task_id)
                if task:
                    return _build_transcription_response(task, episode)

        # === FAST PATH 2: Check DB for existing completed or in-progress task ===
        existing_task = await transcription_service.get_episode_transcription(episode_id)
        if existing_task:
            if existing_task.status == 'completed' and not transcription_request.force_regenerate:  # Use string value
                logger.info(f"✅ [DB] Returning existing completed task {existing_task.id} for episode {episode_id}")
                return _build_transcription_response(existing_task, episode)
            elif existing_task.status == 'in_progress':  # Use string value
                if not transcription_request.force_regenerate:
                    # Task is in progress, map it in Redis and return
                    await state_manager.set_episode_task(episode_id, existing_task.id)
                    logger.info(f"🔄 [DB] Returning existing in-progress task {existing_task.id} (step: {existing_task.current_step}) for episode {episode_id}")
                    return _build_transcription_response(existing_task, episode)

        # === Create new task if force_regenerate or no existing task ===
        if existing_task and transcription_request.force_regenerate:
            logger.info(f"🔄 [FORCE] Deleting existing task {existing_task.id} for regeneration")
            await db.delete(existing_task)
            await db.commit()

        # Acquire Redis lock before creating task
        lock_acquired = await state_manager.acquire_task_lock(episode_id, 0)  # task_id not known yet
        if not lock_acquired and not transcription_request.force_regenerate:
            # Someone else is processing this episode
            locked_task_id = await state_manager.is_episode_locked(episode_id)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Transcription already in progress. Task ID: {locked_task_id}"
            )

        # Create new transcription task
        task = await transcription_service.start_transcription(
            episode_id,
            transcription_request.transcription_model
        )

        # Update Redis lock with actual task_id and map episode to task
        await state_manager.release_task_lock(episode_id, 0)  # Release temp lock
        await state_manager.acquire_task_lock(episode_id, task.id)  # Acquire with real task_id
        await state_manager.set_episode_task(episode_id, task.id)

        # Set initial progress in Redis
        await state_manager.set_task_progress(
            task.id,
            TranscriptionStatus.PENDING.value,
            0,
            "Transcription task created, waiting for worker to start..."
        )

        # Note: Celery task dispatch is handled by transcription_service.start_transcription()
        # No need to dispatch again here to avoid duplicate execution

        logger.info(f"✅ [CREATED] New transcription task {task.id} for episode {episode_id}")
        return _build_transcription_response(task, episode)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start transcription for episode {episode_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start transcription: {str(e)}"
        )


def _build_transcription_response(task, episode) -> PodcastTranscriptionResponse:
    """Helper to build transcription response from task and episode"""
    return PodcastTranscriptionResponse(
        id=task.id,
        episode_id=task.episode_id,
        status=task.status.value if hasattr(task.status, 'value') else task.status,
        progress_percentage=task.progress_percentage,
        original_audio_url=task.original_audio_url,
        original_file_size=task.original_file_size,
        transcript_word_count=task.transcript_word_count,
        transcript_duration=task.transcript_duration,
        transcript_content=task.transcript_content,  # ← 添加缺失的字段
        error_message=task.error_message,
        error_code=task.error_code,
        download_time=task.download_time,
        conversion_time=task.conversion_time,
        transcription_time=task.transcription_time,
        chunk_size_mb=task.chunk_size_mb,
        model_used=task.model_used,
        created_at=task.created_at,
        started_at=task.started_at,
        completed_at=task.completed_at,
        updated_at=task.updated_at,
        duration_seconds=task.duration_seconds,
        total_processing_time=task.total_processing_time,
        summary_content=task.summary_content,
        summary_model_used=task.summary_model_used,
        summary_word_count=task.summary_word_count,
        summary_processing_time=task.summary_processing_time,
        summary_error_message=task.summary_error_message,
        debug_message=(task.chunk_info or {}).get("debug_message"),
        episode={
            "id": episode.id,
            "title": episode.title,
            "audio_url": episode.audio_url,
            "audio_duration": episode.audio_duration
        }
    )


@router.get(
    "/episodes/{episode_id}/transcription",
    response_model=PodcastTranscriptionDetailResponse,
    summary="获取播客单集转录状态和结果",
    description="查询指定播客单集的转录任务状态和转录结果"
)
async def get_transcription(
    episode_id: int,
    include_content: bool = Query(True, description="是否包含完整转录文本"),
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """获取转录任务详情"""
    service = PodcastService(db, int(user["sub"]))
    transcription_service = DatabaseBackedTranscriptionService(db)

    try:
        # 验证播客单集存在且属于当前用户
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found"
            )

        # 验证用户权限
        if episode.subscription.user_id != int(user["sub"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this episode"
            )

        # 获取转录任务
        task = await transcription_service.get_episode_transcription(episode_id)
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No transcription task found for this episode"
            )

        # 构建响应数据
        response_data = {
            "id": task.id,
            "episode_id": task.episode_id,
            "status": task.status.value if hasattr(task.status, 'value') else task.status,
            "progress_percentage": task.progress_percentage,
            "original_audio_url": task.original_audio_url,
            "original_file_size": task.original_file_size,
            "transcript_word_count": task.transcript_word_count,
            "transcript_duration": task.transcript_duration,
            "error_message": task.error_message,
            "error_code": task.error_code,
            "download_time": task.download_time,
            "conversion_time": task.conversion_time,
            "transcription_time": task.transcription_time,
            "chunk_size_mb": task.chunk_size_mb,
            "model_used": task.model_used,
            "created_at": task.created_at,
            "started_at": task.started_at,
            "completed_at": task.completed_at,
            "updated_at": task.updated_at,
            "duration_seconds": task.duration_seconds,
            "total_processing_time": task.total_processing_time,
            "chunk_info": task.chunk_info,
            "original_file_path": task.original_file_path,
            "episode": {
                "id": episode.id,
                "title": episode.title,
                "audio_url": episode.audio_url,
                "audio_duration": episode.audio_duration
            },
            "debug_message": (task.chunk_info or {}).get("debug_message")
        }

        # 根据参数决定是否包含转录内容
        if include_content:
            response_data["transcript_content"] = task.transcript_content

        # 格式化时间信息
        if task.duration_seconds:
            hours = task.duration_seconds // 3600
            minutes = (task.duration_seconds % 3600) // 60
            seconds = task.duration_seconds % 60
            response_data["formatted_duration"] = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        if task.total_processing_time:
            response_data["formatted_processing_time"] = f"{task.total_processing_time:.2f} seconds"

        # 格式化时间戳
        response_data["formatted_created_at"] = task.created_at.strftime("%Y-%m-%d %H:%M:%S")
        if task.started_at:
            response_data["formatted_started_at"] = task.started_at.strftime("%Y-%m-%d %H:%M:%S")
        if task.completed_at:
            response_data["formatted_completed_at"] = task.completed_at.strftime("%Y-%m-%d %H:%M:%S")

        return PodcastTranscriptionDetailResponse(**response_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get transcription for episode {episode_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get transcription: {str(e)}"
        )


@router.get(
    "/transcriptions/{task_id}/status",
    response_model=PodcastTranscriptionStatusResponse,
    summary="获取转录任务实时状态",
    description="获取转录任务的实时进度状态"
)
async def get_transcription_status(
    task_id: int,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """获取转录任务状态"""
    transcription_service = DatabaseBackedTranscriptionService(db)

    try:
        # 获取转录任务
        task = await transcription_service.get_transcription_status(task_id)
        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Transcription task not found"
            )

        # 验证用户权限（通过episode获取）
        service = PodcastService(db, int(user["sub"]))
        episode = await service.get_episode_by_id(task.episode_id)
        if not episode or episode.subscription.user_id != int(user["sub"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this transcription task"
            )

        # 构建响应数据
        status_messages = {
            "pending": "等待开始转录",
            "downloading": "正在下载音频文件",
            "converting": "正在转换音频格式",
            "splitting": "正在分割音频文件",
            "transcribing": "正在进行语音识别",
            "merging": "正在合并转录结果",
            "completed": "转录完成",
            "failed": "转录失败",
            "cancelled": "转录已取消"
        }

        # 获取当前chunk信息
        current_chunk = 0
        total_chunks = 0
        if task.chunk_info and "chunks" in task.chunk_info:
            total_chunks = len(task.chunk_info["chunks"])
            # 根据进度估算当前处理到的chunk
            if task.status == "transcribing" and task.progress_percentage > 45:
                current_chunk = int(((task.progress_percentage - 45) / 50) * total_chunks)

        # 预计剩余时间（简单估算）
        eta_seconds = None
        if task.started_at and task.status not in ["completed", "failed", "cancelled"]:
            elapsed = (datetime.utcnow() - task.started_at).total_seconds()
            if task.progress_percentage > 0:
                estimated_total = elapsed / (task.progress_percentage / 100)
                eta_seconds = int(estimated_total - elapsed)

        response_data = {
            "task_id": task.id,
            "episode_id": task.episode_id,
            "status": task.status.value if hasattr(task.status, 'value') else task.status,
            "progress": task.progress_percentage,
            "message": status_messages.get(
                task.status.value if hasattr(task.status, 'value') else task.status,
                "未知状态"
            ),
            "current_chunk": current_chunk,
            "total_chunks": total_chunks,
            "eta_seconds": eta_seconds
        }

        return PodcastTranscriptionStatusResponse(**response_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get transcription status for task {task_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get transcription status: {str(e)}"
        )


# === 转录调度功能 ===

@router.post(
    "/episodes/{episode_id}/transcribe/schedule",
    status_code=status.HTTP_201_CREATED,
    summary="安排播客单集转录（支持调度规则）",
    description="为指定播客单集安排转录任务，支持自动调度和避免重复转录"
)
async def schedule_episode_transcription_endpoint(
    episode_id: int,
    force: bool = Body(False, description="是否强制重新转录（即使已存在结果）"),
    frequency: str = Body("manual", description="调度频率: hourly, daily, weekly, manual"),
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """
    安排转录任务，支持以下特性：
    - 自动检查是否已存在转录结果
    - 避免重复转录已成功的内容
    - 支持定时调度
    - 可强制重新转录

    请求示例:
    ```json
    {
        "force": false,
        "frequency": "manual"
    }
    ```
    """
    service = PodcastService(db, int(user["sub"]))

    try:
        # 验证播客单集存在且属于当前用户
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found"
            )

        # 验证用户权限
        if episode.subscription.user_id != int(user["sub"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this episode"
            )

        # 检查是否已有转录结果
        existing_transcript = await get_episode_transcript(db, episode_id)
        if existing_transcript and not force:
            return {
                "status": "skipped",
                "message": "Transcription already exists. Use force=true to re-transcribe.",
                "episode_id": episode_id,
                "transcript_preview": existing_transcript[:100] + "..." if len(existing_transcript) > 100 else existing_transcript
            }

        # 安排转录
        scheduler = TranscriptionScheduler(db)
        result = await scheduler.schedule_transcription(
            episode_id=episode_id,
            frequency=ScheduleFrequency(frequency),
            force=force
        )

        return result

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to schedule transcription for episode {episode_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to schedule transcription: {str(e)}"
        )


@router.get(
    "/episodes/{episode_id}/transcript",
    summary="获取转录文本（避免重复转录）",
    description="获取播客单集的转录文本，如果已存在则直接返回，避免重复转录"
)
async def get_episode_transcript_endpoint(
    episode_id: int,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """
    核心功能：读取已存在的转录文本

    逻辑：
    1. 检查PodcastEpisode.transcript_content
    2. 检查TranscriptionTask.transcript_content
    3. 如果都不存在，返回404
    """
    service = PodcastService(db, int(user["sub"]))

    try:
        # 验证播客单集存在且属于当前用户
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found"
            )

        # 验证用户权限
        if episode.subscription.user_id != int(user["sub"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this episode"
            )

        # 获取转录文本
        transcript = await get_episode_transcript(db, episode_id)

        if not transcript:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No transcription found for this episode. Please schedule transcription first."
            )

        return {
            "episode_id": episode_id,
            "episode_title": episode.title,
            "transcript_length": len(transcript),
            "transcript": transcript,
            "status": "success"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get transcript for episode {episode_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get transcript: {str(e)}"
        )


@router.post(
    "/subscriptions/{subscription_id}/transcribe/batch",
    status_code=status.HTTP_201_CREATED,
    summary="批量转录订阅的所有分集",
    description="为订阅的所有分集批量安排转录，自动跳过已转录的内容"
)
async def batch_transcribe_subscription_endpoint(
    subscription_id: int,
    skip_existing: bool = Body(True, description="是否跳过已存在转录的分集"),
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """
    批量转录功能：
    - 自动获取订阅的所有分集
    - 跳过已成功转录的分集
    - 批量安排转录任务

    请求示例:
    ```json
    {
        "skip_existing": true
    }
    ```
    """
    service = PodcastService(db, int(user["sub"]))

    try:
        # 验证订阅存在且属于当前用户
        subscription = await service.get_subscription_by_id(subscription_id)
        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Subscription {subscription_id} not found"
            )

        if subscription.user_id != int(user["sub"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this subscription"
            )

        # 批量转录
        result = await batch_transcribe_subscription(
            db,
            subscription_id,
            skip_existing=skip_existing
        )

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to batch transcribe subscription {subscription_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to batch transcribe: {str(e)}"
        )


@router.get(
    "/episodes/{episode_id}/transcription/schedule-status",
    summary="获取转录调度状态",
    description="获取指定分集的转录任务状态和调度信息"
)
async def get_transcription_schedule_status(
    episode_id: int,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """获取转录任务的详细状态信息"""
    service = PodcastService(db, int(user["sub"]))
    scheduler = TranscriptionScheduler(db)

    try:
        # 验证播客单集存在且属于当前用户
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found"
            )

        # 验证用户权限
        if episode.subscription.user_id != int(user["sub"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this episode"
            )

        # 获取转录状态
        status = await scheduler.get_transcription_status(episode_id)

        return status

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get transcription status for episode {episode_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get transcription status: {str(e)}"
        )


@router.post(
    "/episodes/{episode_id}/transcription/cancel",
    summary="取消转录任务",
    description="取消指定分集的转录任务"
)
async def cancel_transcription_endpoint(
    episode_id: int,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """取消转录任务"""
    service = PodcastService(db, int(user["sub"]))
    scheduler = TranscriptionScheduler(db)

    try:
        # 验证播客单集存在且属于当前用户
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found"
            )

        # 验证用户权限
        if episode.subscription.user_id != int(user["sub"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this episode"
            )

        # 取消转录
        success = await scheduler.cancel_transcription(episode_id)

        return {
            "success": success,
            "message": "Transcription cancelled" if success else "No active transcription to cancel"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel transcription for episode {episode_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cancel transcription: {str(e)}"
        )


@router.post(
    "/subscriptions/{subscription_id}/check-new-episodes",
    summary="检查并转录新分集",
    description="检查订阅中的新分集并自动安排转录"
)
async def check_and_transcribe_new_episodes(
    subscription_id: int,
    hours_since_published: int = Body(24, description="检查多少小时内发布的分集"),
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """
    智能检查新分集并转录：
    - 检查指定时间范围内发布的新分集
    - 自动跳过已转录的分集
    - 批量安排转录任务

    请求示例:
    ```json
    {
        "hours_since_published": 24
    }
    ```
    """
    service = PodcastService(db, int(user["sub"]))
    scheduler = TranscriptionScheduler(db)

    try:
        # 验证订阅存在且属于当前用户
        subscription = await service.get_subscription_by_id(subscription_id)
        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Subscription {subscription_id} not found"
            )

        if subscription.user_id != int(user["sub"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this subscription"
            )

        # 检查并转录新分集
        result = await scheduler.check_and_transcribe_new_episodes(
            subscription_id=subscription_id,
            hours_since_published=hours_since_published
        )

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to check new episodes for subscription {subscription_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to check new episodes: {str(e)}"
        )


@router.get(
    "/transcriptions/pending",
    summary="获取待处理的转录任务",
    description="获取所有待处理的转录任务列表"
)
async def get_pending_transcriptions(
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """获取当前用户所有待处理的转录任务"""
    scheduler = TranscriptionScheduler(db)

    try:
        # 获取待处理任务
        tasks = await scheduler.get_pending_transcriptions()

        # 过滤当前用户的任务
        service = PodcastService(db, int(user["sub"]))
        user_tasks = []
        for task in tasks:
            episode = await service.get_episode_by_id(task["episode_id"])
            if episode and episode.subscription.user_id == int(user["sub"]):
                user_tasks.append(task)

        return {
            "total": len(user_tasks),
            "tasks": user_tasks
        }

    except Exception as e:
        logger.error(f"Failed to get pending transcriptions: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get pending transcriptions: {str(e)}"
        )


# === Conversation相关 ===

@router.get(
    "/episodes/{episode_id}/conversations",
    response_model=PodcastConversationHistoryResponse,
    summary="获取对话历史",
    description="获取指定播客单集的对话历史"
)
async def get_conversation_history(
    episode_id: int,
    limit: int = Query(50, ge=1, le=200, description="返回的消息数量限制"),
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """获取对话历史"""
    from app.domains.podcast.conversation_service import ConversationService

    service = PodcastService(db, int(user["sub"]))
    conversation_service = ConversationService(db)

    try:
        # 验证播客单集存在且属于当前用户
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found"
            )

        # 验证用户权限
        if episode.subscription.user_id != int(user["sub"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this episode"
            )

        # 获取对话历史
        messages = await conversation_service.get_conversation_history(
            episode_id=episode_id,
            user_id=int(user["sub"]),
            limit=limit
        )

        # 转换为响应模型
        message_responses = [
            PodcastConversationMessage(**msg) for msg in messages
        ]

        return PodcastConversationHistoryResponse(
            episode_id=episode_id,
            messages=message_responses,
            total=len(message_responses)
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get conversation history for episode {episode_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get conversation history: {str(e)}"
        )


@router.post(
    "/episodes/{episode_id}/conversations",
    status_code=status.HTTP_201_CREATED,
    response_model=PodcastConversationSendResponse,
    summary="发送对话消息",
    description="向AI助手发送消息并获取回复，支持上下文保持"
)
async def send_conversation_message(
    episode_id: int,
    request: PodcastConversationSendRequest,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """
    发送对话消息：

    请求示例:
    ```json
    {
        "message": "这期播客主要讲了什么？",
        "model_name": "gpt-4"
    }
    ```
    """
    from app.domains.podcast.conversation_service import ConversationService

    service = PodcastService(db, int(user["sub"]))
    conversation_service = ConversationService(db)

    try:
        # 验证播客单集存在且属于当前用户
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found"
            )

        # 验证用户权限
        if episode.subscription.user_id != int(user["sub"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this episode"
            )

        # 发送消息并获取AI回复
        response = await conversation_service.send_message(
            episode_id=episode_id,
            user_id=int(user["sub"]),
            user_message=request.message,
            model_name=request.model_name
        )

        return PodcastConversationSendResponse(**response)

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to send message for episode {episode_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send message: {str(e)}"
        )


@router.delete(
    "/episodes/{episode_id}/conversations",
    response_model=PodcastConversationClearResponse,
    summary="清除对话历史",
    description="清除指定播客单集的对话历史"
)
async def clear_conversation_history(
    episode_id: int,
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """清除对话历史"""
    from app.domains.podcast.conversation_service import ConversationService

    service = PodcastService(db, int(user["sub"]))
    conversation_service = ConversationService(db)

    try:
        # 验证播客单集存在且属于当前用户
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found"
            )

        # 验证用户权限
        if episode.subscription.user_id != int(user["sub"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this episode"
            )

        # 清除对话历史
        deleted_count = await conversation_service.clear_conversation_history(
            episode_id=episode_id,
            user_id=int(user["sub"])
        )

        return PodcastConversationClearResponse(
            episode_id=episode_id,
            deleted_count=deleted_count
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to clear conversation history for episode {episode_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear conversation history: {str(e)}"
        )



@router.get(
    "/subscriptions/schedule/all",
    response_model=List[ScheduleConfigResponse],
    summary="Get all subscription schedules",
    description="Get schedule configuration for all user subscriptions"
)
async def get_all_subscription_schedules(
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """Get all subscription schedule configurations"""
    from app.domains.subscription.models import Subscription

    stmt = select(Subscription).where(
        Subscription.user_id == int(user['sub'])
    ).where(
        Subscription.source_type == "podcast-rss"
    ).order_by(Subscription.created_at)

    result = await db.execute(stmt)
    subscriptions = list(result.scalars().all())

    return [
        ScheduleConfigResponse(
            id=sub.id,
            title=sub.title,
            update_frequency=sub.update_frequency,
            update_time=sub.update_time,
            update_day_of_week=sub.update_day_of_week,
            fetch_interval=sub.fetch_interval,
            next_update_at=sub.computed_next_update_at,
            last_updated_at=sub.last_fetched_at
        )
        for sub in subscriptions
    ]


@router.post(
    "/subscriptions/schedule/batch-update",
    response_model=List[ScheduleConfigResponse],
    summary="Batch update subscription schedules",
    description="Update schedule configuration for multiple subscriptions"
)
async def batch_update_subscription_schedules(
    subscription_ids: List[int] = Body(..., embed=True),
    schedule_data: ScheduleConfigUpdate = Body(...),
    user=Depends(get_token_from_request),
    db: AsyncSession = Depends(get_db_session)
):
    """Batch update schedule configuration for multiple subscriptions"""
    from app.domains.subscription.models import Subscription

    stmt = select(Subscription).where(
        Subscription.id.in_(subscription_ids)
    ).where(
        Subscription.user_id == int(user['sub'])
    )

    result = await db.execute(stmt)
    subscriptions = list(result.scalars().all())

    updated_subs = []
    for sub in subscriptions:
        # Update schedule configuration
        sub.update_frequency = schedule_data.update_frequency
        sub.update_time = schedule_data.update_time
        sub.update_day_of_week = schedule_data.update_day_of_week

        if schedule_data.fetch_interval is not None:
            sub.fetch_interval = schedule_data.fetch_interval

        updated_subs.append(sub)

    await db.commit()

    # Refresh to get computed properties
    for sub in updated_subs:
        await db.refresh(sub)

    return [
        ScheduleConfigResponse(
            id=sub.id,
            title=sub.title,
            update_frequency=sub.update_frequency,
            update_time=sub.update_time,
            update_day_of_week=sub.update_day_of_week,
            fetch_interval=sub.fetch_interval,
            next_update_at=sub.computed_next_update_at,
            last_updated_at=sub.last_fetched_at
        )
        for sub in updated_subs
    ]

# Export router
__all__ = ["router"]
