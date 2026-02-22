"""Admin dashboard route module."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.dependencies import admin_required
from app.admin.routes._shared import get_templates
from app.core.database import get_db_session
from app.domains.ai.models import AIModelConfig
from app.domains.subscription.models import Subscription
from app.domains.user.models import User


logger = logging.getLogger(__name__)

router = APIRouter()
templates = get_templates()


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Display admin dashboard."""
    try:
        # Get statistics
        # Count API keys (AI Model Configs)
        apikey_count_query = select(func.count()).select_from(AIModelConfig)
        apikey_count_result = await db.execute(apikey_count_query)
        apikey_count = apikey_count_result.scalar() or 0

        # Count subscriptions
        subscription_count_query = select(func.count()).select_from(Subscription)
        subscription_count_result = await db.execute(subscription_count_query)
        subscription_count = subscription_count_result.scalar() or 0

        # Count users
        user_count_query = select(func.count()).select_from(User)
        user_count_result = await db.execute(user_count_query)
        user_count = user_count_result.scalar() or 0

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "user": user,
                "apikey_count": apikey_count,
                "subscription_count": subscription_count,
                "user_count": user_count,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to load dashboard",
        ) from e
