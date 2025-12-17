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
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.security import verify_token
from app.domains.podcast.services import PodcastService
from app.domains.podcast.repositories import PodcastRepository

router = APIRouter(prefix="/podcasts", tags=["播客"])


# === 订阅管理 ===

@router.post(
    "/subscription",
    status_code=status.HTTP_201_CREATED,
    summary="添加播客订阅",
    description="通过RSS链接添加播客订阅，并自动生成前几期音频的AI总结"
)
async def add_subscription(
    request: dict,
    user=Depends(verify_token),
    db: AsyncSession = Depends(get_db_session)
):
    """
    请求示例:
    ```json
    {
        "feed_url": "https://feeds.soundcloud.com/users/soundcloud:users:123456/tracks.rss",
        "custom_name": "我的播客"
    }
    ```
    """
    service = PodcastService(db, user["sub"])
    try:
        subscription, new_episodes = await service.add_subscription(
            feed_url=request["feed_url"],
            custom_name=request.get("custom_name")
        )

        return {
            "success": True,
            "subscription_id": subscription.id,
            "new_episodes": len(new_episodes),
            "message": f"已添加 {subscription.title}, 发现 {len(new_episodes)} 期新节目"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get(
    "/subscription",
    response_model=List[dict],
    summary="列出所有播客订阅"
)
async def list_subscriptions(
    user=Depends(verify_token),
    db: AsyncSession = Depends(get_db_session)
):
    """返回用户的所有播客订阅及其最新节目"""
    service = PodcastService(db, user["sub"])
    subscriptions = await service.list_subscriptions()
    return subscriptions


@router.get(
    "/subscription/{subscription_id}",
    summary="获取订阅详情"
)
async def get_subscription(
    subscription_id: int,
    user=Depends(verify_token),
    db: AsyncSession = Depends(get_db_session)
):
    """获取订阅详情和单集列表（最多50条）"""
    service = PodcastService(db, user["sub"])
    details = await service.get_subscription_details(subscription_id)
    if not details:
        raise HTTPException(status_code=404, detail="订阅不存在或无权限")
    return details


@router.delete(
    "/subscription/{subscription_id}",
    summary="删除订阅"
)
async def delete_subscription(
    subscription_id: int,
    user=Depends(verify_token),
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
    "/episodes/{episode_id}",
    summary="获取单集详情"
)
async def get_episode(
    episode_id: int,
    user=Depends(verify_token),
    db: AsyncSession = Depends(get_db_session)
):
    """获取单集详情，包含AI总结（如有）"""
    service = PodcastService(db, user["sub"])
    episode = await service.get_episode_with_summary(episode_id)
    if not episode:
        raise HTTPException(status_code=404, detail="单集不存在或无权限")
    return episode


@router.post(
    "/episodes/{episode_id}/summary",
    summary="生成(或重新生成)AI总结"
)
async def generate_summary(
    episode_id: int,
    force: bool = False,
    user=Depends(verify_token),
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
        if force:
            summary = await service.regenerate_summary(episode_id, force=True)
        else:
            summary = await service.generate_summary_for_episode(episode_id)
        return {
            "success": True,
            "summary": summary,
            "episode_id": episode_id
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/episodes/{episode_id}/progress",
    summary="更新播放进度"
)
async def update_progress(
    episode_id: int,
    request: dict,
    user=Depends(verify_token),
    db: AsyncSession = Depends(get_db_session)
):
    """
    请求示例:
    ```json
    {
        "position": 125,  // 秒
        "is_playing": true
    }
    ```
    """
    service = PodcastService(db, user["sub"])
    try:
        result = await service.update_playback_progress(
            episode_id,
            request["position"],
            request.get("is_playing", False)
        )
        return {"success": True, **result}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get(
    "/summary/pending",
    summary="待AI总结的单集"
)
async def get_pending_summaries(
    user=Depends(verify_token),
    db: AsyncSession = Depends(get_db_session)
):
    """列出所有需要AI总结的单集"""
    service = PodcastService(db, user["sub"])
    pending = await service.get_pending_summaries()
    return {
        "count": len(pending),
        "episodes": pending
    }
