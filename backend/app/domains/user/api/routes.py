"""User authentication and management API routes."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.dependencies import get_current_user
from app.core.exceptions import BaseCustomException, UnauthorizedError
from app.domains.user.services import AuthenticationService
from app.shared.schemas import (
    ForgotPasswordRequest,
    PasswordResetResponse,
    ResetPasswordRequest,
    Token,
    UserResponse,
)


router = APIRouter()


class LoginRequest(BaseModel):
    """Login request schema."""
    username: str | None = Field(None, description="Username for login (alternative to email_or_username)")
    email_or_username: str | None = Field(None, description="Email or username for login (alternative to username)")
    password: str
    remember_me: bool = False

    @model_validator(mode='before')
    @classmethod
    def validate_identifier(cls, data):
        """Ensure either username or email_or_username is provided."""
        if (
            isinstance(data, dict)
            and not data.get('username')
            and not data.get('email_or_username')
        ):
            raise ValueError('Either username or email_or_username must be provided')
        return data


class RefreshTokenRequest(BaseModel):
    """Refresh token request schema."""
    refresh_token: str


class LogoutRequest(BaseModel):
    """Logout request schema."""
    refresh_token: str | None = None


class RegisterRequest(BaseModel):
    """Register request schema."""
    email: str
    password: str
    username: str | None = None
    remember_me: bool = False


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    register_data: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session)
) -> Any:
    """Register a new user - returns tokens on success."""
    try:
        auth_service = AuthenticationService(db)

        # Extract device info from request
        device_info = {
            "user_agent": request.headers.get("user-agent"),
            "ip_address": request.client.host
        }

        # Create user
        user = await auth_service.register_user(
            email=register_data.email,
            password=register_data.password,
            username=register_data.username
        )

        # Create session with tokens (like login)
        token_data = await auth_service.create_user_session(
            user=user,
            device_info=device_info,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent"),
            remember_me=register_data.remember_me
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
            detail=f"Registration failed: {str(e)}"
        ) from e


@router.post("/login", response_model=Token)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db_session)
) -> Any:
    """Login with email/username and password."""
    try:
        auth_service = AuthenticationService(db)

        # Determine which field to use (username takes priority if both provided)
        identifier = login_data.username or login_data.email_or_username

        # Authenticate user
        user = await auth_service.authenticate_user(
            email_or_username=identifier,
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
            user_agent=request.headers.get("user-agent"),
            remember_me=login_data.remember_me
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
        ) from e


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db_session)
) -> Any:
    """Refresh access token using refresh token with sliding session."""
    try:
        auth_service = AuthenticationService(db)

        token_data = await auth_service.refresh_access_token(
            refresh_token=refresh_data.refresh_token
        )

        # Return new refresh token for sliding session
        return Token(
            access_token=token_data["access_token"],
            refresh_token=token_data["refresh_token"],  # Return NEW refresh token
            token_type=token_data["token_type"],
            expires_in=token_data["expires_in"]
        )

    except BaseCustomException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token refresh failed: {str(e)}"
        ) from e


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
        ) from e


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: Any = Depends(get_current_user)
) -> Any:
    """Get current user information."""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        is_active=current_user.status == "active",
        is_superuser=current_user.is_superuser,
        is_verified=current_user.is_verified,
        avatar_url=current_user.avatar_url,
        full_name=current_user.account_name,
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
        ) from e


@router.post("/forgot-password", response_model=PasswordResetResponse)
async def forgot_password(
    request_data: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db_session)
) -> Any:
    """Request a password reset link via email."""
    try:
        auth_service = AuthenticationService(db)

        # Create password reset token
        result = await auth_service.create_password_reset_token(
            email=request_data.email
        )

        return PasswordResetResponse(
            message=result["message"],
            token=result.get("token"),  # Will be None in production
            expires_at=result.get("expires_at")
        )

    except BaseCustomException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process password reset request: {str(e)}"
        ) from e


@router.post("/reset-password", response_model=PasswordResetResponse)
async def reset_password(
    request_data: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db_session)
) -> Any:
    """Reset password using a valid reset token."""
    try:
        auth_service = AuthenticationService(db)

        # Reset password
        result = await auth_service.reset_password(
            token=request_data.token,
            new_password=request_data.new_password
        )

        return PasswordResetResponse(
            message=result["message"]
        )

    except BaseCustomException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reset password: {str(e)}"
        ) from e
