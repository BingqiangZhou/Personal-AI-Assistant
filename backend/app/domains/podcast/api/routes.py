"""Podcast API router aggregator.

External API paths remain unchanged; this module only composes split route modules.
"""

from fastapi import APIRouter

from .routes_conversations import router as conversations_router
from .routes_episodes import router as episodes_router
from .routes_stats import router as stats_router
from .routes_transcriptions import router as transcriptions_router


router = APIRouter(prefix="")
router.include_router(episodes_router)
router.include_router(stats_router)
router.include_router(transcriptions_router)
router.include_router(conversations_router)

__all__ = ["router", "podcast_router"]

# Backward compatibility alias
podcast_router = router
