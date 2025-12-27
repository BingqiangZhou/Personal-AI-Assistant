"""Authentication dependencies."""

import logging
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError

from app.core.config import settings
from app.core.database import get_db_session
from app.core.security import verify_token
from app.domains.user.models import User
from app.domains.user.repositories import UserRepository

logger = logging.getLogger(__name__)

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login"
)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db_session)
) -> User:
    """Get current authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="[DEPS] Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        logger.error(f"[DEBUG] Starting token verification")
        payload = verify_token(token)
        logger.error(f"[DEBUG] Token payload: {payload}")
        user_id_str: str = payload.get("sub")
        logger.error(f"[DEBUG] user_id_str: {user_id_str}")
        if user_id_str is None:
            logger.error("[DEBUG] user_id_str is None")
            raise credentials_exception
        user_id = int(user_id_str)
        logger.error(f"[DEBUG] user_id: {user_id}")
    except HTTPException as e:
        logger.error(f"[DEBUG] HTTPException from verify_token: {e.detail}")
        raise
    except (JWTError, ValueError) as e:
        logger.error(f"[DEBUG] Exception in token verification: {e}")
        raise credentials_exception

    user_repo = UserRepository(db)
    user = await user_repo.get_by_id(user_id)
    logger.error(f"[DEBUG] User found: {user is not None}")
    if user is None:
        logger.error("[DEBUG] User is None")
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


async def get_current_superuser(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current superuser."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user