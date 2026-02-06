"""Handlers for recommendation generation tasks."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select

from app.domains.podcast.services import PodcastService
from app.domains.user.models import User, UserStatus


async def generate_podcast_recommendations_handler(session) -> dict:
    """Generate recommendations for all active users."""
    stmt = select(User).where(User.status == UserStatus.ACTIVE)
    result = await session.execute(stmt)
    users = list(result.scalars().all())

    recommendations_generated = 0
    for user in users:
        service = PodcastService(session, user.id)
        recommendations = await service.get_recommendations(limit=20)
        recommendations_generated += len(recommendations)

    return {
        "status": "success",
        "recommendations_generated": recommendations_generated,
        "processed_at": datetime.utcnow().isoformat(),
    }
