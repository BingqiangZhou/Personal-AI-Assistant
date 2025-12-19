"""
播客API路由 - /api/v1/podcasts/*

终端路由:
POST   /podcasts/subscription           添加播客订阅
GET    /podcasts/subscription           列出所有订阅
GET    /podcasts/subscription/{id}      获取订阅详情
DELETE /podcasts/subscription/{id}      删除订阅

GET    /podcasts/episodes/{id}          获取单集详情
POST   /podcasts/episodes/{id}/summary  触发AI总结
POST   /podcasts/episodes/{id}/progress 更新播放进度

GET    /podcasts/summary/pending        待总结列表
"""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Header, status, Body
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.security import get_token_from_request
from app.domains.podcast.services import PodcastService
from app.domains.podcast.repositories import PodcastRepository
from app.domains.podcast.schemas import (
    PodcastSubscriptionCreate,
    PodcastSubscriptionResponse,
    PodcastSubscriptionListResponse,
    PodcastEpisodeResponse,
    PodcastEpisodeListResponse,
    PodcastEpisodeDetailResponse,
    PodcastPlaybackUpdate,
    PodcastPlaybackStateResponse,
    PodcastSummaryRequest,
    PodcastSummaryResponse,
    PodcastSummaryPendingResponse,
    PodcastEpisodeFilter,
    PodcastSearchFilter,
    PodcastStatsResponse
)

router = APIRouter(prefix="")


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
    service = PodcastService(db, user["sub"])
    try:
        subscription, new_episodes = await service.add_subscription(
            feed_url=subscription_data.feed_url,
            custom_name=subscription_data.custom_name,
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
    service = PodcastService(db, user["sub"])

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
    service = PodcastService(db, user["sub"])
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
    service = PodcastService(db, user["sub"])
    success = await service.remove_subscription(subscription_id)
    if not success:
        raise HTTPException(status_code=404, detail="订阅不存在")
    return {"success": True, "message": "订阅已删除"}


# === 单集管理 ===

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
    service = PodcastService(db, user["sub"])

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
    service = PodcastService(db, user["sub"])
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
    - 默认异步处理，返回任务ID
    """
    service = PodcastService(db, user["sub"])
    try:
        if request.force_regenerate:
            summary = await service.regenerate_summary(episode_id, force=True)
        else:
            summary = await service.generate_summary_for_episode(
                episode_id,
                use_transcript=request.use_transcript
            )

        return PodcastSummaryResponse(
            episode_id=episode_id,
            summary=summary["content"],
            version=summary["version"],
            confidence_score=summary.get("confidence_score"),
            transcript_used=summary.get("transcript_used", False),
            generated_at=summary["generated_at"],
            word_count=len(summary["content"])
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
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
    service = PodcastService(db, user["sub"])
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
    service = PodcastService(db, user["sub"])
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
    service = PodcastService(db, user["sub"])
    pending = await service.get_pending_summaries()
    return PodcastSummaryPendingResponse(
        count=len(pending),
        episodes=pending
    )


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
    service = PodcastService(db, user["sub"])

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
    service = PodcastService(db, user["sub"])
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
    service = PodcastService(db, user["sub"])
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
    service = PodcastService(db, user["sub"])
    recommendations = await service.get_recommendations(limit=limit)
    return recommendations
