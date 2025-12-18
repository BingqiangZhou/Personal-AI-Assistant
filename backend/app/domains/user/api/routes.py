"""User authentication and management API routes."""

from datetime import timedelta
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.core.database import get_db_session
from app.core.security import get_current_user
from app.core.exceptions import (
    BaseCustomException,
    ConflictError,
    BadRequestError,
    UnauthorizedError,
    NotFoundError
)
from app.shared.schemas import Token, UserCreate, UserResponse
from app.domains.user.services import AuthenticationService

router = APIRouter(tags=["authentication"])


class LoginRequest(BaseModel):
    """Login request schema."""
    email_or_username: str
    password: str


class RefreshTokenRequest(BaseModel):
    """Refresh token request schema."""
    refresh_token: str


class LogoutRequest(BaseModel):
    """Logout request schema."""
    refresh_token: Optional[str] = None


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db_session)
) -> Any:
    """Register a new user."""
    try:
        auth_service = AuthenticationService(db)

        # Extract device info from request
        device_info = {
            "user_agent": request.headers.get("user-agent"),
            "ip_address": request.client.host
        }

        # Create user
        user = await auth_service.register_user(
            email=user_data.email,
            password=user_data.password,
            username=user_data.username,
            full_name=user_data.full_name
        )

        return UserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            full_name=user.full_name,
            is_active=user.status == "active",
            is_superuser=user.is_superuser,
            is_verified=user.is_verified,
            avatar_url=user.avatar_url,
            created_at=user.created_at
        )

    except BaseCustomException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )


@router.post("/login", response_model=Token)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session)
) -> Any:
    """Login with email/username and password."""
    try:
        auth_service = AuthenticationService(db)

        # Authenticate user
        user = await auth_service.authenticate_user(
            email_or_username=login_data.email_or_username,
            password=login_data.password
        )

        if not user:
            raise UnauthorizedError("Invalid credentials")

        # Extract device info
        device_info = {
            "user_agent": request.headers.get("user-agent"),
            "ip_address": request.client.host,
            "device_type": "web"  # Could be enhanced with device detection
        }

        # Create session with tokens
        token_data = await auth_service.create_user_session(
            user=user,
            device_info=device_info,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )

        return Token(
            access_token=token_data["access_token"],
            refresh_token=token_data["refresh_token"],
            token_type=token_data["token_type"],
            expires_in=token_data["expires_in"]
        )

    except BaseCustomException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db_session)
) -> Any:
    """Refresh access token using refresh token."""
    try:
        auth_service = AuthenticationService(db)

        token_data = await auth_service.refresh_access_token(
            refresh_token=refresh_data.refresh_token
        )

        return Token(
            access_token=token_data["access_token"],
            refresh_token=refresh_data.refresh_token,  # Return same refresh token
            token_type=token_data["token_type"],
            expires_in=token_data["expires_in"]
        )

    except BaseCustomException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token refresh failed: {str(e)}"
        )


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    logout_data: LogoutRequest,
    current_user: Any = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
) -> Any:
    """Logout current user."""
    try:
        auth_service = AuthenticationService(db)

        if logout_data.refresh_token:
            # Logout specific session
            await auth_service.logout_user(logout_data.refresh_token)
        else:
            # Logout all sessions for user
            await auth_service.logout_all_sessions(current_user.id)

        return {"message": "Successfully logged out"}

    except BaseCustomException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: Any = Depends(get_current_user)
) -> Any:
    """Get current user information."""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        full_name=current_user.full_name,
        is_active=current_user.status == "active",
        is_superuser=current_user.is_superuser,
        is_verified=current_user.is_verified,
        avatar_url=current_user.avatar_url,
        created_at=current_user.created_at
    )


@router.post("/logout-all", status_code=status.HTTP_200_OK)
async def logout_all(
    current_user: Any = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session)
) -> Any:
    """Logout from all devices."""
    try:
        auth_service = AuthenticationService(db)
        await auth_service.logout_all_sessions(current_user.id)
        return {"message": "Successfully logged out from all devices"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}"
        )