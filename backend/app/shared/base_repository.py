"""
Base repository class for common data access operations.

基础仓储类，提供通用的数据访问操作
"""

import logging
from typing import Any, Generic, Optional, TypeVar

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession


logger = logging.getLogger(__name__)


ModelType = TypeVar("ModelType")


class BaseRepository(Generic[ModelType]):
    """
    Base repository class with common data access operations.

    Provides generic methods for:
    - Get by ID
    - List with pagination and filters
    - Count
    - Create
    - Update
    - Delete
    - Batch operations
    """

    def __init__(self, db: AsyncSession, model: type[ModelType]):
        """
        Initialize base repository.

        Args:
            db: Database session
            model: SQLAlchemy model class
        """
        self.db = db
        self.model = model

    async def get_by_id(
        self,
        id: int,
        options: Optional[list] = None
    ) -> Optional[ModelType]:
        """
        Get entity by ID.

        Args:
            id: Entity ID
            options: Optional SQLAlchemy options (e.g., joinedload)

        Returns:
            Model instance or None
        """
        stmt = select(self.model).where(self.model.id == id)

        if options:
            stmt = stmt.options(*options)

        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_ids(
        self,
        ids: list[int],
        options: Optional[list] = None
    ) -> list[ModelType]:
        """
        Get multiple entities by IDs.

        Args:
            ids: List of entity IDs
            options: Optional SQLAlchemy options

        Returns:
            List of model instances
        """
        if not ids:
            return []

        stmt = select(self.model).where(self.model.id.in_(ids))

        if options:
            stmt = stmt.options(*options)

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_list(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[dict[str, Any]] = None,
        order_by: Optional[Any] = None,
        options: Optional[list] = None
    ) -> list[ModelType]:
        """
        Get list of entities with pagination and filters.

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            filters: Optional filters dictionary
            order_by: Optional order by clause
            options: Optional SQLAlchemy options

        Returns:
            List of model instances
        """
        stmt = select(self.model)

        # Apply filters
        if filters:
            conditions = []
            for key, value in filters.items():
                if hasattr(self.model, key):
                    if value is None:
                        conditions.append(getattr(self.model, key).is_(None))
                    else:
                        conditions.append(getattr(self.model, key) == value)

            if conditions:
                stmt = stmt.where(and_(*conditions))

        # Apply ordering
        if order_by is not None:
            stmt = stmt.order_by(order_by)

        # Apply options
        if options:
            stmt = stmt.options(*options)

        # Apply pagination
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

        # Apply filters
        if filters:
            conditions = []
            for key, value in filters.items():
                if hasattr(self.model, key):
                    if value is None:
                        conditions.append(getattr(self.model, key).is_(None))
                    else:
                        conditions.append(getattr(self.model, key) == value)

            if conditions:
                stmt = stmt.where(and_(*conditions))

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
        entity = self.model(**kwargs)
        self.db.add(entity)
        await self.db.commit()
        await self.db.refresh(entity)
        return entity

    async def create_many(self, items: list[dict[str, Any]]) -> list[ModelType]:
        """
        Create multiple entities in batch.

        Args:
            items: List of dictionaries with entity attributes

        Returns:
            List of created model instances
        """
        entities = [self.model(**item) for item in items]
        self.db.add_all(entities)
        await self.db.commit()

        for entity in entities:
            await self.db.refresh(entity)

        return entities

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

    async def update_many(
        self,
        ids: list[int],
        **kwargs
    ) -> int:
        """
        Update multiple entities by IDs.

        Args:
            ids: List of entity IDs
            **kwargs: Attributes to update

        Returns:
            Number of updated entities
        """
        if not ids:
            return 0

        # Build update statement
        stmt = select(self.model).where(self.model.id.in_(ids))
        result = await self.db.execute(stmt)
        entities = result.scalars().all()

        count = 0
        for entity in entities:
            for key, value in kwargs.items():
                if hasattr(entity, key):
                    setattr(entity, key, value)
            count += 1

        await self.db.commit()
        return count

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

    async def delete_many(self, ids: list[int]) -> int:
        """
        Delete multiple entities by IDs.

        Args:
            ids: List of entity IDs

        Returns:
            Number of deleted entities
        """
        if not ids:
            return 0

        entities = await self.get_by_ids(ids)
        count = len(entities)

        for entity in entities:
            await self.db.delete(entity)

        await self.db.commit()
        return count

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

    async def get_paginated(
        self,
        page: int = 1,
        size: int = 20,
        filters: Optional[dict[str, Any]] = None,
        order_by: Optional[Any] = None,
        options: Optional[list] = None
    ) -> tuple[list[ModelType], int]:
        """
        Get paginated list of entities.

        Args:
            page: Page number (1-indexed)
            size: Items per page
            filters: Optional filters dictionary
            order_by: Optional order by clause
            options: Optional SQLAlchemy options

        Returns:
            Tuple of (items list, total count)
        """
        # Calculate offset
        skip = (page - 1) * size

        # Get total count
        total = await self.count(filters)

        # Get items
        items = await self.get_list(
            skip=skip,
            limit=size,
            filters=filters,
            order_by=order_by,
            options=options
        )

        return items, total
