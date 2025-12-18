"""Shared Pydantic schemas."""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, EmailStr, ConfigDict, Field, field_validator


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
    full_name: Optional[str] = Field(None, max_length=255)
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
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserUpdate(BaseSchema):
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None


class UserInDB(UserBase, TimestampedSchema):
    id: int
    is_verified: bool
    last_login_at: Optional[datetime] = None


class UserResponse(UserBase):
    id: int
    is_verified: bool
    avatar_url: Optional[str] = None
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
    items: List[Any]
    total: int
    page: int
    size: int
    pages: int

    @classmethod
    def create(
        cls,
        items: List[Any],
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
    errors: Optional[Dict[str, List[str]]] = None


# Subscription schemas
class SubscriptionBase(BaseSchema):
    title: str
    description: Optional[str] = None
    source_type: str
    source_url: str
    config: Optional[Dict[str, Any]] = {}
    fetch_interval: int = 3600


class SubscriptionCreate(SubscriptionBase):
    pass


class SubscriptionUpdate(BaseSchema):
    title: Optional[str] = None
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    fetch_interval: Optional[int] = None
    is_active: Optional[bool] = None


class SubscriptionResponse(SubscriptionBase, TimestampedSchema):
    id: int
    user_id: int
    status: str
    last_fetched_at: Optional[datetime] = None
    error_message: Optional[str] = None


# Knowledge Base schemas
class KnowledgeBaseBase(BaseSchema):
    name: str
    description: Optional[str] = None
    is_public: bool = False
    settings: Optional[Dict[str, Any]] = {}


class KnowledgeBaseCreate(KnowledgeBaseBase):
    pass


class KnowledgeBaseUpdate(BaseSchema):
    name: Optional[str] = None
    description: Optional[str] = None
    is_public: Optional[bool] = None
    settings: Optional[Dict[str, Any]] = None


class KnowledgeBaseResponse(KnowledgeBaseBase, TimestampedSchema):
    id: int
    user_id: int
    is_default: bool
    document_count: Optional[int] = 0


# Document schemas
class DocumentBase(BaseSchema):
    title: str
    content: Optional[str] = None
    content_type: str
    metadata: Optional[Dict[str, Any]] = {}
    tags: Optional[List[str]] = []


class DocumentCreate(DocumentBase):
    knowledge_base_id: int


class DocumentUpdate(BaseSchema):
    title: Optional[str] = None
    content: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None


class DocumentResponse(DocumentBase, TimestampedSchema):
    id: int
    knowledge_base_id: int
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    indexed_at: Optional[datetime] = None


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
    metadata: Optional[Dict[str, Any]] = {}


# Conversation schemas
class ConversationBase(BaseSchema):
    title: str
    description: Optional[str] = None
    model_name: str = "gpt-3.5-turbo"
    system_prompt: Optional[str] = None
    temperature: int = 70
    settings: Optional[Dict[str, Any]] = {}


class ConversationCreate(ConversationBase):
    pass


class ConversationUpdate(BaseSchema):
    title: Optional[str] = None
    description: Optional[str] = None
    system_prompt: Optional[str] = None
    temperature: Optional[int] = None
    settings: Optional[Dict[str, Any]] = None


class ConversationResponse(ConversationBase, TimestampedSchema):
    id: int
    user_id: int
    status: str
    message_count: Optional[int] = 0