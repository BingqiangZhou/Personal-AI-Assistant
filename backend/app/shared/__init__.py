"""Shared components used across domains."""

from .base_service import BaseService
from .base_repository import BaseRepository
from .pagination import PaginationParams, PaginatedResponse, PaginationHelper
from .response_builder import ResponseBuilder, COMMON_FIELD_MAPPINGS
from .schemas import (
    BaseSchema,
    TimestampedSchema,
    UserBase,
    UserCreate,
    UserUpdate,
    UserResponse,
    UserInDB,
    UserLogin,
    Token,
    TokenData,
    PaginationParams as LegacyPaginationParams,
    PaginatedResponse as LegacyPaginatedResponse,
    APIResponse,
    ErrorResponse,
    SubscriptionBase,
    SubscriptionCreate,
    SubscriptionUpdate,
    SubscriptionResponse,
    MessageBase,
    MessageCreate,
    MessageResponse,
    ConversationBase,
    ConversationCreate,
    ConversationUpdate,
    ConversationResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    PasswordResetResponse,
)
from .mappers import (
    map_model_to_response,
    map_models_to_responses,
    create_paginated_response,
    DOCUMENT_FIELD_MAPPING,
    MEDIA_FIELD_MAPPING,
    CONVERSATION_FIELD_MAPPING,
    MESSAGE_FIELD_MAPPING,
)

__all__ = [
    # Base classes
    "BaseService",
    "BaseRepository",

    # Pagination
    "PaginationParams",
    "PaginatedResponse",
    "PaginationHelper",

    # Response building
    "ResponseBuilder",
    "COMMON_FIELD_MAPPINGS",

    # Schemas
    "BaseSchema",
    "TimestampedSchema",
    "UserBase",
    "UserCreate",
    "UserUpdate",
    "UserResponse",
    "UserInDB",
    "UserLogin",
    "Token",
    "TokenData",
    "APIResponse",
    "ErrorResponse",
    "SubscriptionBase",
    "SubscriptionCreate",
    "SubscriptionUpdate",
    "SubscriptionResponse",
    "MessageBase",
    "MessageCreate",
    "MessageResponse",
    "ConversationBase",
    "ConversationCreate",
    "ConversationUpdate",
    "ConversationResponse",
    "ForgotPasswordRequest",
    "ResetPasswordRequest",
    "PasswordResetResponse",

    # Legacy pagination (for backward compatibility)
    "LegacyPaginationParams",
    "LegacyPaginatedResponse",

    # Mappers
    "map_model_to_response",
    "map_models_to_responses",
    "create_paginated_response",
    "DOCUMENT_FIELD_MAPPING",
    "MEDIA_FIELD_MAPPING",
    "CONVERSATION_FIELD_MAPPING",
    "MESSAGE_FIELD_MAPPING",
]
