"""
Generic response mappers for converting database models to API responses.

This module provides utility functions to reduce code duplication across
service layers when mapping database models to response schemas.
通用响应映射器，用于将数据库模型转换为 API 响应
"""

from typing import Any, Optional, TypeVar

from pydantic import BaseModel


T = TypeVar('T', bound=BaseModel)
M = TypeVar('M')  # Model type


def map_model_to_response(
    model: M,
    response_class: type[T],
    field_mapping: Optional[dict[str, str]] = None,
    additional_fields: Optional[dict[str, Any]] = None
) -> T:
    """
    Generic mapper to convert database model to response schema.

    Args:
        model: Database model instance
        response_class: Pydantic response schema class
        field_mapping: Optional mapping of model fields to response fields
                       e.g., {"doc_metadata": "metadata", "metadata_json": "metadata"}
        additional_fields: Additional fields to include in the response

    Returns:
        Instance of response_class with data from model

    Example:
        >>> map_model_to_response(
        ...     kb_model,
        ...     KnowledgeBaseResponse,
        ...     additional_fields={"document_count": 5}
        ... )
    """
    # Build field data from model
    field_data = {}

    # Get fields from response class
    if hasattr(response_class, 'model_fields'):
        # Pydantic v2
        response_fields = response_class.model_fields
    elif hasattr(response_class, '__fields__'):
        # Pydantic v1
        response_fields = response_class.__fields__
    else:
        # Fallback: try to get fields from model
        response_fields = {}

    for field_name in response_fields:
        # Check if there's a custom mapping
        model_field = field_mapping.get(field_name) if field_mapping else None

        if model_field:
            # Use custom field mapping
            if hasattr(model, model_field):
                field_data[field_name] = getattr(model, model_field)
        else:
            # Direct field access
            if hasattr(model, field_name):
                field_data[field_name] = getattr(model, field_name)

    # Add any additional fields
    if additional_fields:
        field_data.update(additional_fields)

    return response_class(**field_data)


def map_models_to_responses(
    models: list[M],
    response_class: type[T],
    field_mapping: Optional[dict[str, str]] = None,
    additional_fields_map: Optional[dict[int, dict[str, Any]]] = None
) -> list[T]:
    """
    Generic mapper to convert list of database models to response schemas.

    Args:
        models: List of database model instances
        response_class: Pydantic response schema class
        field_mapping: Optional mapping of model fields to response fields
        additional_fields_map: Optional mapping of model ID to additional fields

    Returns:
        List of response_class instances

    Example:
        >>> map_models_to_responses(
        ...     kb_models,
        ...     KnowledgeBaseResponse,
        ...     additional_fields_map={1: {"document_count": 5}}
        ... )
    """
    responses = []
    for model in models:
        additional = None
        if additional_fields_map and hasattr(model, 'id'):
            additional = additional_fields_map.get(model.id)

        responses.append(
            map_model_to_response(
                model,
                response_class,
                field_mapping=field_mapping,
                additional_fields=additional
            )
        )
    return responses


def create_paginated_response(
    items: list,
    total: int,
    page: int,
    size: int,
    response_class: Optional[type[T]] = None
) -> dict[str, Any]:
    """
    Create a standardized paginated response.

    Args:
        items: List of items (can be models or already mapped responses)
        total: Total number of items
        page: Current page number
        size: Items per page
        response_class: Optional Pydantic class to convert items to

    Returns:
        Dictionary with pagination metadata

    Example:
        >>> create_paginated_response(
        ...     items=[kb1, kb2],
        ...     total=10,
        ...     page=1,
        ...     size=20
        ... )
        {
            "items": [...],
            "total": 10,
            "page": 1,
            "size": 20,
            "pages": 1
        }
    """
    total_pages = (total + size - 1) // size if total > 0 else 0

    return {
        "items": items,
        "total": total,
        "page": page,
        "size": size,
        "pages": total_pages
    }


# Common field mappings for different domains
DOCUMENT_FIELD_MAPPING = {
    "doc_metadata": "metadata",
    "metadata_json": "metadata",
}

MEDIA_FIELD_MAPPING = {
    "media_metadata": "metadata",
}

CONVERSATION_FIELD_MAPPING = {
    "metadata_json": "metadata",
}

MESSAGE_FIELD_MAPPING = {
    "metadata_json": "metadata",
}
