"""Shared Pydantic schemas."""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


# Base schemas
class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class TimestampedSchema(BaseSchema):
    created_at: datetime
    updated_at: Optional[datetime] = None


# User schemas
class UserBase(BaseSchema):
    email: EmailStr
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    account_name: Optional[str] = Field(None, max_length=255)
    is_active: bool = True
    is_superuser: bool = False

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        """Validate username format."""
        if v is not None:
            if not v.replace('_', '').replace('-', '').isalnum():
                raise ValueError('Username must contain only alphanumeric characters, hyphens, and underscores')
        return v


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        """Validate password strength."""
        errors = []

        if len(v) < 8:
            errors.append('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            errors.append('Password must contain at least one uppercase letter (A-Z)')
        if not any(c.islower() for c in v):
            errors.append('Password must contain at least one lowercase letter (a-z)')
        if not any(c.isdigit() for c in v):
            errors.append('Password must contain at least one number (0-9)')

        if errors:
            # Join all errors with a separator for better readability
            raise ValueError(' | '.join(errors))

        return v


class UserUpdate(BaseSchema):
    account_name: Optional[str] = None
    avatar_url: Optional[str] = None
    settings: Optional[dict[str, Any]] = None


class UserInDB(UserBase, TimestampedSchema):
    id: int
    is_verified: bool
    last_login_at: Optional[datetime] = None


class UserResponse(UserBase):
    id: int
    is_verified: bool
    avatar_url: Optional[str] = None
    account_name: Optional[str] = None
    created_at: datetime


class UserLogin(BaseSchema):
    username: str
    password: str


# Token schemas
class Token(BaseSchema):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseSchema):
    username: Optional[str] = None


# Pagination schemas
class PaginationParams(BaseSchema):
    page: int = Field(1, ge=1)
    size: int = Field(20, ge=1, le=100)

    @property
    def skip(self) -> int:
        return (self.page - 1) * self.size


class PaginatedResponse(BaseSchema):
    items: list[Any]
    total: int
    page: int
    size: int
    pages: int

    @classmethod
    def create(
        cls,
        items: list[Any],
        total: int,
        page: int,
        size: int
    ) -> "PaginatedResponse":
        pages = (total + size - 1) // size
        return cls(
            items=items,
            total=total,
            page=page,
            size=size,
            pages=pages
        )


# API Response schemas
class APIResponse(BaseSchema):
    success: bool = True
    message: Optional[str] = None
    data: Optional[Any] = None


class ErrorResponse(BaseSchema):
    success: bool = False
    message: str
    errors: Optional[dict[str, list[str]]] = None


# Subscription schemas
class SubscriptionBase(BaseSchema):
    title: str
    description: Optional[str] = None
    source_type: str
    source_url: str
    config: Optional[dict[str, Any]] = {}
    fetch_interval: int = 3600


class SubscriptionCreate(SubscriptionBase):
    pass


class SubscriptionUpdate(BaseSchema):
    title: Optional[str] = None
    description: Optional[str] = None
    config: Optional[dict[str, Any]] = None
    fetch_interval: Optional[int] = None
    is_active: Optional[bool] = None


class SubscriptionResponse(SubscriptionBase, TimestampedSchema):
    id: int
    status: str
    last_fetched_at: Optional[datetime] = None
    latest_item_published_at: Optional[datetime] = None
    next_update_at: Optional[datetime] = None
    error_message: Optional[str] = None
    item_count: int = 0


# Message schemas
class MessageBase(BaseSchema):
    content: str
    role: str


class MessageCreate(MessageBase):
    conversation_id: int


class MessageResponse(MessageBase, TimestampedSchema):
    id: int
    conversation_id: int
    tokens: Optional[int] = None
    model_name: Optional[str] = None
    metadata: Optional[dict[str, Any]] = {}


# Conversation schemas
class ConversationBase(BaseSchema):
    title: str
    description: Optional[str] = None
    model_name: str = "gpt-3.5-turbo"
    system_prompt: Optional[str] = None
    temperature: int = 70
    settings: Optional[dict[str, Any]] = {}


class ConversationCreate(ConversationBase):
    pass


class ConversationUpdate(BaseSchema):
    title: Optional[str] = None
    description: Optional[str] = None
    system_prompt: Optional[str] = None
    temperature: Optional[int] = None
    settings: Optional[dict[str, Any]] = None


class ConversationResponse(ConversationBase, TimestampedSchema):
    id: int
    user_id: int
    status: str
    message_count: Optional[int] = 0


# Password Reset schemas
class ForgotPasswordRequest(BaseSchema):
    """Forgot password request schema."""
    email: EmailStr = Field(..., description="Email address associated with the account")


class ResetPasswordRequest(BaseSchema):
    """Reset password request schema."""
    token: str = Field(..., description="Password reset token received via email")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")

    @field_validator('new_password')
    @classmethod
    def validate_password(cls, v):
        """Validate password strength."""
        errors = []

        if len(v) < 8:
            errors.append('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            errors.append('Password must contain at least one uppercase letter (A-Z)')
        if not any(c.islower() for c in v):
            errors.append('Password must contain at least one lowercase letter (a-z)')
        if not any(c.isdigit() for c in v):
            errors.append('Password must contain at least one number (0-9)')

        if errors:
            # Join all errors with a separator for better readability
            raise ValueError(' | '.join(errors))

        return v


class PasswordResetResponse(BaseSchema):
    """Password reset response schema."""
    message: str = Field(..., description="Response message")
    # Include token only in development for testing
    token: Optional[str] = Field(None, description="Reset token (development only)")
    expires_at: Optional[str] = Field(None, description="Token expiry time (ISO format)")