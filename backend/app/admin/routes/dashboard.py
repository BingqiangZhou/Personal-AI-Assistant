"""Admin dashboard route module."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.admin.auth import admin_required
from app.admin.routes._shared import get_templates
from app.admin.services.dashboard_service import AdminDashboardService
from app.core.providers import get_admin_dashboard_service
from app.domains.user.models import User


logger = logging.getLogger(__name__)

router = APIRouter()
templates = get_templates()


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user: User = Depends(admin_required),
    service: AdminDashboardService = Depends(get_admin_dashboard_service),
):
    """Display admin dashboard."""
    try:
        context = await service.get_dashboard_context()

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "user": user,
                **context,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to load dashboard",
        ) from e
