"""Admin authentication dependencies and utilities."""
import logging
from datetime import datetime, timezone

from fastapi import Cookie, Depends, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db_session
from app.domains.user.models import User
from app.domains.user.repositories import UserRepository


logger = logging.getLogger(__name__)

# Session serializer for secure cookies
serializer = URLSafeTimedSerializer(settings.SECRET_KEY)

# Session timeout (30 minutes)
SESSION_TIMEOUT = 30 * 60  # seconds


class AdminAuthRequired:
    """Dependency to require admin authentication."""

    def __init__(self, require_2fa: bool = True):
        """
        Initialize admin auth dependency.

        Args:
            require_2fa: If True, require 2FA to be enabled. If False, allow access without 2FA.
        """
        self.require_2fa = require_2fa

    async def __call__(
        self,
        request: Request,
        admin_session: str | None = Cookie(None),
        db: AsyncSession = Depends(get_db_session),
    ) -> User:
        """Verify admin session and return user."""
        if not admin_session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
            )

        try:
            # Verify session token
            data = serializer.loads(admin_session, max_age=SESSION_TIMEOUT)
            user_id = data.get("user_id")

            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid session",
                )

            # Get user from database
            user_repo = UserRepository(db)
            user = await user_repo.get_by_id(user_id)

            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive",
                )

            # Check if 2FA is required and not enabled
            # 检查是否需要2FA但用户未启用
            # If global 2FA is disabled, don't require 2FA even if require_2fa is True
            # 如果全局2FA被禁用，即使 require_2fa 为 True 也不要求2FA
            # Priority: database setting > environment variable
            # 优先级：数据库设置 > 环境变量
            from app.admin.security_settings import get_admin_2fa_enabled
            admin_2fa_enabled, _ = await get_admin_2fa_enabled(db)

            if self.require_2fa and admin_2fa_enabled and not user.is_2fa_enabled:
                # Redirect to 2FA setup page
                # Note: This will raise an exception that should be caught by the route handler
                raise HTTPException(
                    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                    detail="2FA setup required",
                    headers={"Location": "/super/2fa/setup"},
                )

            return user

        except SignatureExpired as err:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired",
            ) from err
        except BadSignature as err:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid session",
            ) from err
        except Exception as e:
            # Re-raise HTTP exceptions
            if isinstance(e, HTTPException):
                raise
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Authentication error: {str(e)}",
            ) from e


def create_admin_session(user_id: int) -> str:
    """Create a secure session token for admin user."""
    data = {"user_id": user_id, "created_at": datetime.now(timezone.utc).isoformat()}
    return serializer.dumps(data)


# Dependency instances
admin_required = AdminAuthRequired(require_2fa=True)  # Requires 2FA
admin_required_no_2fa = AdminAuthRequired(require_2fa=False)  # Does not require 2FA

