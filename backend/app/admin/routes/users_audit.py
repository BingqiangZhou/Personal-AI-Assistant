"""Admin users and audit routes module.

This module contains all routes related to:
- User management (list, toggle status, reset password)
- Audit log viewing (with filtering and pagination)
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.admin.audit import log_admin_action
from app.admin.auth import admin_required
from app.admin.routes._shared import get_templates
from app.admin.services.users_audit_service import AdminUsersAuditService
from app.core.providers import get_admin_users_audit_service
from app.domains.user.models import User


logger = logging.getLogger(__name__)

router = APIRouter()
templates = get_templates()


# ==================== Audit Log Management ====================


@router.get("/audit-logs", response_class=HTMLResponse)
async def audit_logs_page(
    request: Request,
    user: User = Depends(admin_required),
    service: AdminUsersAuditService = Depends(get_admin_users_audit_service),
    page: int = 1,
    per_page: int = 10,
    action: str | None = None,
    resource_type: str | None = None,
):
    """Display audit logs page with filtering and pagination."""
    try:
        context = await service.get_audit_logs_context(
            page=page,
            per_page=per_page,
            action=action,
            resource_type=resource_type,
        )

        return templates.TemplateResponse(
            "audit_logs.html",
            {
                "request": request,
                "user": user,
                **context,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Audit logs page error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to load audit logs",
        ) from e


# ==================== User Management ====================


@router.get("/users", response_class=HTMLResponse)
async def users_page(
    request: Request,
    user: User = Depends(admin_required),
    service: AdminUsersAuditService = Depends(get_admin_users_audit_service),
    page: int = 1,
    per_page: int = 10,
):
    """Display users management page with pagination."""
    try:
        context = await service.get_users_context(page=page, per_page=per_page)

        return templates.TemplateResponse(
            "users.html",
            {
                "request": request,
                "user": user,
                **context,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Users page error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to load users",
        ) from e


@router.put("/users/{user_id}/toggle")
async def toggle_user(
    user_id: int,
    request: Request,
    user: User = Depends(admin_required),
    service: AdminUsersAuditService = Depends(get_admin_users_audit_service),
):
    """Toggle user active status."""
    try:
        target_user = await service.toggle_user_status(
            target_user_id=user_id,
            acting_user_id=user.id,
        )
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        logger.info(
            f"User {user_id} toggled to {target_user.status} by user {user.username}"
        )

        await log_admin_action(
            db=service.db,
            user_id=user.id,
            username=user.username,
            action="toggle",
            resource_type="user",
            resource_id=user_id,
            resource_name=target_user.username,
            details={"status": target_user.status},
            request=request,
        )

        return JSONResponse(content={"success": True, "status": target_user.status})
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Toggle user error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to toggle user",
        ) from e


@router.put("/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    request: Request,
    user: User = Depends(admin_required),
    service: AdminUsersAuditService = Depends(get_admin_users_audit_service),
):
    """Reset user password to a random value."""
    try:
        target_user, new_password = await service.reset_user_password(
            target_user_id=user_id
        )
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        logger.info(
            f"User {user_id} password reset by user {user.username}"
        )

        await log_admin_action(
            db=service.db,
            user_id=user.id,
            username=user.username,
            action="reset_password",
            resource_type="user",
            resource_id=user_id,
            resource_name=target_user.username,
            request=request,
        )

        return JSONResponse(content={
            "success": True,
            "new_password": new_password,
            "message": f"Password reset successful. New password: {new_password}"
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Reset password error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to reset password",
        ) from e
