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

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Header, status, Body
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.security import get_token_from_request
from app.domains.podcast.services import PodcastService
from app.domains.podcast.repositories import PodcastRepository
from app.domains.podcast.transcription import PodcastTranscriptionService, AISummaryService
from app.domains.podcast.transcription_manager import DatabaseBackedTranscriptionService
from app.domains.podcast.summary_manager import DatabaseBackedAISummaryService
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
    PodcastEpisodeFilter,
    PodcastSearchFilter,
    PodcastStatsResponse,
    PodcastTranscriptionRequest,
    PodcastTranscriptionResponse,
    PodcastTranscriptionDetailResponse,
    PodcastTranscriptionListResponse,
    PodcastTranscriptionStatusResponse,
    PodcastTranscriptionChunkInfo
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
    service = PodcastService(db, int(user["sub"]))
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
    ai_summary_service = AISummaryService(db)

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
        if request.force_regenerate:
            task = await ai_summary_service.regenerate_summary(
                episode_id,
                request.summary_model,
                request.custom_prompt
            )
        else:
            task = await ai_summary_service.generate_summary(
                episode_id,
                request.summary_model,
                request.custom_prompt
            )

        # 返回总结响应
        return PodcastSummaryResponse(
            episode_id=episode_id,
            summary=task.summary_content or "",
            version="1.0",  # 可以根据需要管理版本
            confidence_score=None,  # 可以后续添加
            transcript_used=True,  # AI总结服务总是使用转录内容
            generated_at=task.updated_at,
            word_count=task.summary_word_count or 0
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
    """
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

        # 检查是否已有转录任务
        existing_task = await transcription_service.get_episode_transcription(episode_id)
        if existing_task and not transcription_request.force_regenerate:
            if existing_task.status in ["pending", "downloading", "converting", "splitting", "transcribing", "merging"]:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Transcription task already in progress"
                )
            if existing_task.status == "completed":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Transcription already completed. Use force_regenerate=true to re-transcribe"
                )

        # 启动转录任务
        task = await transcription_service.start_transcription(
            episode_id,
            transcription_request.transcription_model
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
            # AI总结信息
            "summary_content": task.summary_content,
            "summary_model_used": task.summary_model_used,
            "summary_word_count": task.summary_word_count,
            "summary_processing_time": task.summary_processing_time,
            "summary_error_message": task.summary_error_message,
            "episode": {
                "id": episode.id,
                "title": episode.title,
                "audio_url": episode.audio_url,
                "audio_duration": episode.audio_duration
            }
        }

        return PodcastTranscriptionResponse(**response_data)

    except HTTPException:
        raise
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to start transcription for episode {episode_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start transcription: {str(e)}"
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
            }
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
        import logging
        logger = logging.getLogger(__name__)
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
        import logging
        logger = logging.getLogger(__name__)
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
        import logging
        logger = logging.getLogger(__name__)
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
        import logging
        logger = logging.getLogger(__name__)
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
        import logging
        logger = logging.getLogger(__name__)
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
        import logging
        logger = logging.getLogger(__name__)
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
        import logging
        logger = logging.getLogger(__name__)
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
        import logging
        logger = logging.getLogger(__name__)
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
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to get pending transcriptions: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get pending transcriptions: {str(e)}"
        )


# Export router
__all__ = ["router"]
