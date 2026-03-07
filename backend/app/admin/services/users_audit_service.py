"""Admin service helpers for users and audit routes."""

import secrets

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.models import AdminAuditLog
from app.core.security import get_password_hash
from app.domains.user.models import User, UserStatus


class AdminUsersAuditService:
    """Query and mutate admin users/audit data."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_audit_logs_context(
        self,
        *,
        page: int,
        per_page: int,
        action: str | None,
        resource_type: str | None,
    ) -> dict:
        query = select(AdminAuditLog).order_by(AdminAuditLog.created_at.desc())
        if action:
            query = query.where(AdminAuditLog.action == action)
        if resource_type:
            query = query.where(AdminAuditLog.resource_type == resource_type)

        count_query = select(func.count()).select_from(AdminAuditLog)
        if action:
            count_query = count_query.where(AdminAuditLog.action == action)
        if resource_type:
            count_query = count_query.where(AdminAuditLog.resource_type == resource_type)

        total_count = int((await self.db.execute(count_query)).scalar() or 0)
        offset = (page - 1) * per_page
        audit_logs = (
            await self.db.execute(query.limit(per_page).offset(offset))
        ).scalars().all()
        total_pages = (total_count + per_page - 1) // per_page if total_count else 0
        return {
            "audit_logs": audit_logs,
            "page": page,
            "per_page": per_page,
            "total_count": total_count,
            "total_pages": total_pages,
            "action_filter": action,
            "resource_type_filter": resource_type,
        }

    async def get_users_context(self, *, page: int, per_page: int) -> dict:
        total_count = int(
            (await self.db.execute(select(func.count()).select_from(User))).scalar() or 0
        )
        total_pages = (total_count + per_page - 1) // per_page if total_count else 0
        offset = (page - 1) * per_page
        users = (
            await self.db.execute(
                select(User)
                .order_by(User.created_at.desc())
                .limit(per_page)
                .offset(offset)
            )
        ).scalars().all()
        return {
            "users": users,
            "page": page,
            "per_page": per_page,
            "total_count": total_count,
            "total_pages": total_pages,
        }

    async def toggle_user_status(
        self,
        *,
        target_user_id: int,
        acting_user_id: int,
    ) -> User | None:
        result = await self.db.execute(select(User).where(User.id == target_user_id))
        target_user = result.scalar_one_or_none()
        if not target_user:
            return None
        if target_user.id == acting_user_id:
            raise ValueError("Cannot disable your own account")

        target_user.status = (
            UserStatus.INACTIVE
            if target_user.status == UserStatus.ACTIVE
            else UserStatus.ACTIVE
        )
        await self.db.commit()
        await self.db.refresh(target_user)
        return target_user

    async def reset_user_password(self, *, target_user_id: int) -> tuple[User | None, str]:
        result = await self.db.execute(select(User).where(User.id == target_user_id))
        target_user = result.scalar_one_or_none()
        if not target_user:
            return None, ""

        new_password = secrets.token_urlsafe(16)
        target_user.hashed_password = get_password_hash(new_password)
        await self.db.commit()
        await self.db.refresh(target_user)
        return target_user, new_password
