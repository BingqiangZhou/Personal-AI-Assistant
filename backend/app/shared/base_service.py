"""
Base service class for common CRUD operations.

基础服务类，提供通用的CRUD操作
"""

import logging
from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession


logger = logging.getLogger(__name__)


ModelType = TypeVar("ModelType")
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)


class BaseService(Generic[ModelType]):
    """
    Base service class with common CRUD operations.

    Provides generic methods for:
    - Get by ID
    - List with pagination
    - Create
    - Update
    - Delete
    """

    def __init__(self, db: AsyncSession, model: type[ModelType], user_id: Optional[int] = None):
        """
        Initialize base service.

        Args:
            db: Database session
            model: SQLAlchemy model class
            user_id: Optional user ID for multi-tenant data isolation
        """
        self.db = db
        self.model = model
        self.user_id = user_id

    async def get_by_id(self, id: int) -> Optional[ModelType]:
        """
        Get entity by ID.

        Args:
            id: Entity ID

        Returns:
            Model instance or None
        """
        stmt = select(self.model).where(self.model.id == id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_list(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[dict[str, Any]] = None
    ) -> list[ModelType]:
        """
        Get list of entities with pagination.

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            filters: Optional filters dictionary

        Returns:
            List of model instances
        """
        stmt = select(self.model)

        # Apply user filter if user_id is set
        if self.user_id and hasattr(self.model, 'user_id'):
            stmt = stmt.where(self.model.user_id == self.user_id)

        # Apply additional filters
        if filters:
            for key, value in filters.items():
                if hasattr(self.model, key):
                    stmt = stmt.where(getattr(self.model, key) == value)

        stmt = stmt.offset(skip).limit(limit)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def count(self, filters: Optional[dict[str, Any]] = None) -> int:
        """
        Count entities with optional filters.

        Args:
            filters: Optional filters dictionary

        Returns:
            Count of entities
        """
        stmt = select(func.count(self.model.id))

        # Apply user filter if user_id is set
        if self.user_id and hasattr(self.model, 'user_id'):
            stmt = stmt.where(self.model.user_id == self.user_id)

        # Apply additional filters
        if filters:
            for key, value in filters.items():
                if hasattr(self.model, key):
                    stmt = stmt.where(getattr(self.model, key) == value)

        result = await self.db.execute(stmt)
        return result.scalar() or 0

    async def create(self, **kwargs) -> ModelType:
        """
        Create new entity.

        Args:
            **kwargs: Entity attributes

        Returns:
            Created model instance
        """
        # Set user_id if available
        if self.user_id and hasattr(self.model, 'user_id'):
            kwargs['user_id'] = self.user_id

        entity = self.model(**kwargs)
        self.db.add(entity)
        await self.db.commit()
        await self.db.refresh(entity)
        return entity

    async def update(self, id: int, **kwargs) -> Optional[ModelType]:
        """
        Update entity by ID.

        Args:
            id: Entity ID
            **kwargs: Attributes to update

        Returns:
            Updated model instance or None
        """
        entity = await self.get_by_id(id)
        if not entity:
            return None

        for key, value in kwargs.items():
            if hasattr(entity, key):
                setattr(entity, key, value)

        await self.db.commit()
        await self.db.refresh(entity)
        return entity

    async def delete(self, id: int) -> bool:
        """
        Delete entity by ID.

        Args:
            id: Entity ID

        Returns:
            True if deleted, False if not found
        """
        entity = await self.get_by_id(id)
        if not entity:
            return False

        await self.db.delete(entity)
        await self.db.commit()
        return True

    async def exists(self, id: int) -> bool:
        """
        Check if entity exists by ID.

        Args:
            id: Entity ID

        Returns:
            True if exists, False otherwise
        """
        stmt = select(func.count(self.model.id)).where(self.model.id == id)
        result = await self.db.execute(stmt)
        return (result.scalar() or 0) > 0
