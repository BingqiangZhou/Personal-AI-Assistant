"""Podcast conversation routes."""
# ruff: noqa

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.domains.podcast.api.dependencies import (
    get_conversation_service,
    get_podcast_service,
)
from app.domains.podcast.conversation_service import ConversationService
from app.domains.podcast.schemas import (
    PodcastConversationClearResponse,
    PodcastConversationHistoryResponse,
    PodcastConversationMessage,
    PodcastConversationSendRequest,
    PodcastConversationSendResponse,
)
from app.domains.podcast.services import PodcastService


router = APIRouter(prefix="")
logger = logging.getLogger(__name__)


@router.get(
    "/episodes/{episode_id}/conversations",
    response_model=PodcastConversationHistoryResponse,
    summary="Get conversation history",
    description="Get conversation history for a podcast episode",
)
async def get_conversation_history(
    episode_id: int,
    limit: int = Query(50, ge=1, le=200, description="Number of messages"),
    service: PodcastService = Depends(get_podcast_service),
    conversation_service: ConversationService = Depends(get_conversation_service),
):
    try:
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found",
            )

        messages = await conversation_service.get_conversation_history(
            episode_id=episode_id,
            user_id=service.user_id,
            limit=limit,
        )

        message_responses = [PodcastConversationMessage(**msg) for msg in messages]
        return PodcastConversationHistoryResponse(
            episode_id=episode_id,
            messages=message_responses,
            total=len(message_responses),
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Failed to get conversation history for episode %s: %s",
            episode_id,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get conversation history: {exc}",
        )


@router.post(
    "/episodes/{episode_id}/conversations",
    status_code=status.HTTP_201_CREATED,
    response_model=PodcastConversationSendResponse,
    summary="Send conversation message",
    description="Send a message and get AI response with context",
)
async def send_conversation_message(
    episode_id: int,
    request: PodcastConversationSendRequest,
    service: PodcastService = Depends(get_podcast_service),
    conversation_service: ConversationService = Depends(get_conversation_service),
):
    try:
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found",
            )

        response = await conversation_service.send_message(
            episode_id=episode_id,
            user_id=service.user_id,
            user_message=request.message,
            model_name=request.model_name,
        )

        return PodcastConversationSendResponse(**response)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to send message for episode %s: %s", episode_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send message: {exc}",
        )


@router.delete(
    "/episodes/{episode_id}/conversations",
    response_model=PodcastConversationClearResponse,
    summary="Clear conversation history",
    description="Clear conversation history for a podcast episode",
)
async def clear_conversation_history(
    episode_id: int,
    service: PodcastService = Depends(get_podcast_service),
    conversation_service: ConversationService = Depends(get_conversation_service),
):
    try:
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found",
            )

        deleted_count = await conversation_service.clear_conversation_history(
            episode_id=episode_id,
            user_id=service.user_id,
        )

        return PodcastConversationClearResponse(
            episode_id=episode_id,
            deleted_count=deleted_count,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Failed to clear conversation history for episode %s: %s",
            episode_id,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear conversation history: {exc}",
        )
