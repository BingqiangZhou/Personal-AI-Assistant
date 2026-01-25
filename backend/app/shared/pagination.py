"""
Pagination helper utilities.

分页辅助工具类
"""

from typing import TypeVar, Generic, List, Optional, Dict, Any
from pydantic import BaseModel, Field
from math import ceil


T = TypeVar("T")


class PaginationParams(BaseModel):
    """Pagination parameters."""
    page: int = Field(1, ge=1, description="Page number (1-indexed)")
    size: int = Field(20, ge=1, le=100, description="Items per page")

    @property
    def skip(self) -> int:
        """Calculate offset for database query."""
        return (self.page - 1) * self.size

    @property
    def limit(self) -> int:
        """Get limit for database query."""
        return self.size


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response."""
    items: List[T] = Field(default_factory=list, description="List of items")
    total: int = Field(0, ge=0, description="Total number of items")
    page: int = Field(1, ge=1, description="Current page number")
    size: int = Field(20, ge=1, le=100, description="Items per page")
    pages: int = Field(0, ge=0, description="Total number of pages")

    @classmethod
    def create(
        cls,
        items: List[Any],
        total: int,
        page: int,
        size: int,
        response_type: Optional[type] = None
    ) -> "PaginatedResponse[T]":
        """
        Create a paginated response.

        Args:
            items: List of items (models or dicts)
            total: Total number of items
            page: Current page number
            size: Items per page
            response_type: Optional Pydantic model to convert items to

        Returns:
            PaginatedResponse instance
        """
        # Calculate total pages
        pages = ceil(total / size) if total > 0 else 0

        # Convert items if response type is provided
        if response_type:
            converted_items = []
            for item in items:
                if isinstance(item, dict):
                    converted_items.append(response_type(**item))
                elif hasattr(item, 'model_validate'):
                    # Pydantic v2
                    converted_items.append(response_type.model_validate(item))
                elif hasattr(item, 'from_orm'):
                    # Pydantic v1
                    converted_items.append(response_type.from_orm(item))
                else:
                    converted_items.append(item)
            items = converted_items

        return cls(
            items=items,
            total=total,
            page=page,
            size=size,
            pages=pages
        )

    @property
    def has_next(self) -> bool:
        """Check if there is a next page."""
        return self.page < self.pages

    @property
    def has_prev(self) -> bool:
        """Check if there is a previous page."""
        return self.page > 1

    @property
    def next_page(self) -> Optional[int]:
        """Get next page number."""
        return self.page + 1 if self.has_next else None

    @property
    def prev_page(self) -> Optional[int]:
        """Get previous page number."""
        return self.page - 1 if self.has_prev else None


class PaginationHelper:
    """
    Helper class for pagination calculations and responses.
    """

    @staticmethod
    def calculate_offset(page: int, size: int) -> int:
        """
        Calculate offset for database query.

        Args:
            page: Page number (1-indexed)
            size: Items per page

        Returns:
            Offset value
        """
        return (page - 1) * size

    @staticmethod
    def calculate_total_pages(total: int, size: int) -> int:
        """
        Calculate total number of pages.

        Args:
            total: Total number of items
            size: Items per page

        Returns:
            Total number of pages
        """
        return ceil(total / size) if total > 0 else 0

    @staticmethod
    def create_response(
        items: List[Any],
        total: int,
        page: int,
        size: int,
        response_type: Optional[type] = None
    ) -> Dict[str, Any]:
        """
        Create a paginated response dictionary.

        Args:
            items: List of items
            total: Total number of items
            page: Current page number
            size: Items per page
            response_type: Optional Pydantic model to convert items to

        Returns:
            Dictionary with pagination metadata
        """
        pages = PaginationHelper.calculate_total_pages(total, size)

        # Convert items if response type is provided
        if response_type:
            converted_items = []
            for item in items:
                if isinstance(item, dict):
                    converted_items.append(response_type(**item))
                elif hasattr(item, 'model_validate'):
                    converted_items.append(response_type.model_validate(item))
                elif hasattr(item, 'from_orm'):
                    converted_items.append(response_type.from_orm(item))
                else:
                    converted_items.append(item)
            items = converted_items

        return {
            "items": items,
            "total": total,
            "page": page,
            "size": size,
            "pages": pages,
            "has_next": page < pages,
            "has_prev": page > 1,
            "next_page": page + 1 if page < pages else None,
            "prev_page": page - 1 if page > 1 else None
        }
