"""
Response builder utilities for consistent API responses.

响应构建器，用于创建一致的API响应
"""

from typing import TypeVar, Type, Optional, List, Dict, Any
from pydantic import BaseModel
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


T = TypeVar('T', bound=BaseModel)
M = TypeVar('M')  # Model type


class ResponseBuilder:
    """
    Utility class for building consistent API responses.

    Provides methods for:
    - Success responses
    - Error responses
    - Paginated responses
    - Model to schema mapping
    """

    @staticmethod
    def success(
        data: Any = None,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Build a success response.

        Args:
            data: Response data
            message: Optional success message
            metadata: Optional metadata dictionary

        Returns:
            Dictionary with success response structure
        """
        response = {
            "success": True,
            "data": data
        }

        if message:
            response["message"] = message

        if metadata:
            response["metadata"] = metadata

        return response

    @staticmethod
    def error(
        message: str,
        errors: Optional[Dict[str, List[str]]] = None,
        error_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Build an error response.

        Args:
            message: Error message
            errors: Optional field-level errors
            error_code: Optional error code

        Returns:
            Dictionary with error response structure
        """
        response = {
            "success": False,
            "message": message
        }

        if errors:
            response["errors"] = errors

        if error_code:
            response["error_code"] = error_code

        return response

    @staticmethod
    def paginated(
        items: List[Any],
        total: int,
        page: int,
        size: int,
        response_type: Optional[Type[T]] = None
    ) -> Dict[str, Any]:
        """
        Build a paginated response.

        Args:
            items: List of items (models or dicts)
            total: Total number of items
            page: Current page number
            size: Items per page
            response_type: Optional Pydantic model to convert items to

        Returns:
            Dictionary with pagination metadata
        """
        from math import ceil

        pages = ceil(total / size) if total > 0 else 0

        # Convert items if response type is provided
        if response_type:
            converted_items = []
            for item in items:
                converted_items.append(
                    ResponseBuilder.to_schema(item, response_type)
                )
            items = converted_items

        return {
            "items": items,
            "total": total,
            "page": page,
            "size": size,
            "pages": pages,
            "has_next": page < pages,
            "has_prev": page > 1
        }

    @staticmethod
    def to_schema(
        model: M,
        schema_class: Type[T],
        field_mapping: Optional[Dict[str, str]] = None,
        additional_fields: Optional[Dict[str, Any]] = None
    ) -> T:
        """
        Convert database model to Pydantic schema.

        Args:
            model: Database model instance
            schema_class: Target Pydantic schema class
            field_mapping: Optional field name mappings
            additional_fields: Additional fields to include

        Returns:
            Instance of schema_class
        """
        # Build field data from model
        field_data = {}

        # Get fields from response class
        if hasattr(schema_class, 'model_fields'):
            # Pydantic v2
            response_fields = schema_class.model_fields
        elif hasattr(schema_class, '__fields__'):
            # Pydantic v1
            response_fields = schema_class.__fields__
        else:
            response_fields = {}

        for field_name in response_fields:
            # Check if there's a custom mapping
            model_field = field_mapping.get(field_name) if field_mapping else None

            if model_field:
                # Use custom field mapping
                if hasattr(model, model_field):
                    value = getattr(model, model_field)
                    # Handle datetime serialization
                    if isinstance(value, datetime):
                        value = value.isoformat()
                    field_data[field_name] = value
            else:
                # Direct field access
                if hasattr(model, field_name):
                    value = getattr(model, field_name)
                    # Handle datetime serialization
                    if isinstance(value, datetime):
                        value = value.isoformat()
                    field_data[field_name] = value

        # Add any additional fields
        if additional_fields:
            field_data.update(additional_fields)

        return schema_class(**field_data)

    @staticmethod
    def to_schemas(
        models: List[M],
        schema_class: Type[T],
        field_mapping: Optional[Dict[str, str]] = None,
        additional_fields_map: Optional[Dict[int, Dict[str, Any]]] = None
    ) -> List[T]:
        """
        Convert list of database models to Pydantic schemas.

        Args:
            models: List of database model instances
            schema_class: Target Pydantic schema class
            field_mapping: Optional field name mappings
            additional_fields_map: Optional mapping of model ID to additional fields

        Returns:
            List of schema_class instances
        """
        schemas = []
        for model in models:
            additional = None
            if additional_fields_map and hasattr(model, 'id'):
                additional = additional_fields_map.get(model.id)

            schemas.append(
                ResponseBuilder.to_schema(
                    model,
                    schema_class,
                    field_mapping=field_mapping,
                    additional_fields=additional
                )
            )
        return schemas

    @staticmethod
    def build_detail_response(
        item: Any,
        response_type: Type[T],
        field_mapping: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Build a detail response for a single item.

        Args:
            item: Model instance or dict
            response_type: Pydantic schema class
            field_mapping: Optional field name mappings
            metadata: Optional metadata

        Returns:
            Dictionary with item data
        """
        data = ResponseBuilder.to_schema(item, response_type, field_mapping)

        response = {"data": data}

        if metadata:
            response["metadata"] = metadata

        return response

    @staticmethod
    def build_list_response(
        items: List[Any],
        response_type: Type[T],
        field_mapping: Optional[Dict[str, str]] = None,
        total: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Build a list response for multiple items.

        Args:
            items: List of model instances
            response_type: Pydantic schema class
            field_mapping: Optional field name mappings
            total: Optional total count (defaults to len(items))
            metadata: Optional metadata

        Returns:
            Dictionary with items list
        """
        data = ResponseBuilder.to_schemas(items, response_type, field_mapping)

        response = {
            "items": data,
            "count": len(data)
        }

        if total is not None:
            response["total"] = total

        if metadata:
            response["metadata"] = metadata

        return response


# Common field mappings for different domains
COMMON_FIELD_MAPPINGS = {
    "document": {
        "doc_metadata": "metadata",
        "metadata_json": "metadata",
    },
    "media": {
        "media_metadata": "metadata",
    },
    "conversation": {
        "metadata_json": "metadata",
    },
    "message": {
        "metadata_json": "metadata",
    },
    "podcast_episode": {
        "metadata_json": "metadata",
    }
}
