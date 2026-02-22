"""Admin users and audit routes module.

This module contains all routes related to:
- User management (list, toggle status, reset password)
- Audit log viewing (with filtering and pagination)
"""

import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.dependencies import admin_required
from app.admin.models import AdminAuditLog
from app.admin.routes._shared import get_templates
from app.core.database import get_db_session
from app.core.security import get_password_hash
from app.domains.user.models import User, UserStatus


logger = logging.getLogger(__name__)

router = APIRouter()
templates = get_templates()


# ==================== Audit Log Management ====================


@router.get("/audit-logs", response_class=HTMLResponse)
async def audit_logs_page(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
    page: int = 1,
    per_page: int = 10,
    action: str | None = None,
    resource_type: str | None = None,
):
    """Display audit logs page with filtering and pagination."""
    try:
        # Build query
        query = select(AdminAuditLog).order_by(AdminAuditLog.created_at.desc())

        # Apply filters
        if action:
            query = query.where(AdminAuditLog.action == action)
        if resource_type:
            query = query.where(AdminAuditLog.resource_type == resource_type)

        # Get total count
        count_query = select(func.count()).select_from(AdminAuditLog)
        if action:
            count_query = count_query.where(AdminAuditLog.action == action)
        if resource_type:
            count_query = count_query.where(AdminAuditLog.resource_type == resource_type)

        total_result = await db.execute(count_query)
        total_count = total_result.scalar() or 0

        # Apply pagination
        offset = (page - 1) * per_page
        query = query.limit(per_page).offset(offset)

        # Execute query
        result = await db.execute(query)
        audit_logs = result.scalars().all()

        # Calculate pagination info
        total_pages = (total_count + per_page - 1) // per_page

        return templates.TemplateResponse(
            "audit_logs.html",
            {
                "request": request,
                "user": user,
                "audit_logs": audit_logs,
                "page": page,
                "per_page": per_page,
                "total_count": total_count,
                "total_pages": total_pages,
                "action_filter": action,
                "resource_type_filter": resource_type,
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
    db: AsyncSession = Depends(get_db_session),
    page: int = 1,
    per_page: int = 10,
):
    """Display users management page with pagination."""
    try:
        # Get total count
        count_result = await db.execute(select(func.count()).select_from(User))
        total_count = count_result.scalar() or 0

        # Calculate pagination
        total_pages = (total_count + per_page - 1) // per_page
        offset = (page - 1) * per_page

        # Get paginated users
        result = await db.execute(
            select(User)
            .order_by(User.created_at.desc())
            .limit(per_page)
            .offset(offset)
        )
        users = result.scalars().all()

        return templates.TemplateResponse(
            "users.html",
            {
                "request": request,
                "user": user,
                "users": users,
                "page": page,
                "per_page": per_page,
                "total_count": total_count,
                "total_pages": total_pages,
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
    db: AsyncSession = Depends(get_db_session),
):
    """Toggle user active status."""
    try:
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        target_user = result.scalar_one_or_none()

        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        # Prevent disabling self
        if target_user.id == user.id:
            raise HTTPException(status_code=400, detail="Cannot disable your own account")

        # Toggle status
        if target_user.status == UserStatus.ACTIVE:
            target_user.status = UserStatus.INACTIVE
        else:
            target_user.status = UserStatus.ACTIVE

        await db.commit()
        await db.refresh(target_user)

        logger.info(
            f"User {user_id} toggled to {target_user.status} by user {user.username}"
        )

        # Log audit action
        from app.admin.helpers import log_admin_action

        await log_admin_action(
            db=db,
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
    db: AsyncSession = Depends(get_db_session),
):
    """Reset user password to a random value."""
    try:
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        target_user = result.scalar_one_or_none()

        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        # Generate random password
        new_password = secrets.token_urlsafe(16)
        target_user.hashed_password = get_password_hash(new_password)

        await db.commit()
        await db.refresh(target_user)

        logger.info(
            f"User {user_id} password reset by user {user.username}"
        )

        # Log audit action
        from app.admin.helpers import log_admin_action

        await log_admin_action(
            db=db,
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
