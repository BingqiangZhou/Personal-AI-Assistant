"""Shared components used across domains."""

from .base_repository import BaseRepository
from .base_service import BaseService
from .mappers import (
    CONVERSATION_FIELD_MAPPING,
    DOCUMENT_FIELD_MAPPING,
    MEDIA_FIELD_MAPPING,
    MESSAGE_FIELD_MAPPING,
    create_paginated_response,
    map_model_to_response,
    map_models_to_responses,
)
from .pagination import PaginatedResponse, PaginationHelper, PaginationParams
from .response_builder import COMMON_FIELD_MAPPINGS, ResponseBuilder
from .schemas import (
    APIResponse,
    BaseSchema,
    ConversationBase,
    ConversationCreate,
    ConversationResponse,
    ConversationUpdate,
    ErrorResponse,
    ForgotPasswordRequest,
    MessageBase,
    MessageCreate,
    MessageResponse,
    PasswordResetResponse,
    ResetPasswordRequest,
    SubscriptionBase,
    SubscriptionCreate,
    SubscriptionResponse,
    SubscriptionUpdate,
    TimestampedSchema,
    Token,
    TokenData,
    UserBase,
    UserCreate,
    UserInDB,
    UserLogin,
    UserResponse,
    UserUpdate,
)
from .schemas import (
    PaginatedResponse as LegacyPaginatedResponse,
)
from .schemas import (
    PaginationParams as LegacyPaginationParams,
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
