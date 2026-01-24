"""Knowledge domain repositories."""

from typing import List, Optional, Tuple, Any, Dict
from sqlalchemy import select, func, update, delete, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.domains.knowledge.models import KnowledgeBase, Document, DocumentChunk, DocumentTag, DocumentTagMapping
from app.shared.schemas import KnowledgeBaseCreate, KnowledgeBaseUpdate, DocumentCreate, DocumentUpdate


class KnowledgeRepository:
    """Repository for managing knowledge bases and documents."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # Knowledge Base operations
    async def get_user_knowledge_bases(
        self,
        user_id: int,
        page: int = 1,
        size: int = 20
    ) -> Tuple[List[KnowledgeBase], int]:
        """Get user's knowledge bases with pagination."""
        skip = (page - 1) * size
        
        # Get total count
        count_query = select(func.count()).select_from(KnowledgeBase).where(KnowledgeBase.user_id == user_id)
        total = await self.db.scalar(count_query) or 0
        
        # Get items
        query = (
            select(KnowledgeBase)
            .where(KnowledgeBase.user_id == user_id)
            .offset(skip)
            .limit(size)
            .order_by(KnowledgeBase.updated_at.desc())
        )
        result = await self.db.execute(query)
        items = result.scalars().all()
        
        return list(items), total

    async def get_document_counts_for_bases(self, kb_ids: List[int]) -> Dict[int, int]:
        """Get document counts for multiple knowledge bases in a single query.

        Args:
            kb_ids: List of knowledge base IDs

        Returns:
            Dictionary mapping knowledge base ID to document count
        """
        if not kb_ids:
            return {}

        query = (
            select(Document.knowledge_base_id, func.count(Document.id))
            .where(Document.knowledge_base_id.in_(kb_ids))
            .group_by(Document.knowledge_base_id)
        )
        result = await self.db.execute(query)

        # Convert to dict: {kb_id: count}
        return {row[0]: row[1] for row in result.all()}

    async def get_document_count_for_base(self, kb_id: int) -> int:
        """Get document count for a single knowledge base.

        Args:
            kb_id: Knowledge base ID

        Returns:
            Number of documents in the knowledge base
        """
        query = select(func.count()).where(Document.knowledge_base_id == kb_id)
        return await self.db.scalar(query) or 0

    async def get_knowledge_base_by_id(self, user_id: int, kb_id: int) -> Optional[KnowledgeBase]:
        """Get knowledge base by ID."""
        query = select(KnowledgeBase).where(
            KnowledgeBase.id == kb_id,
            KnowledgeBase.user_id == user_id
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def create_knowledge_base(self, user_id: int, kb_data: KnowledgeBaseCreate) -> KnowledgeBase:
        """Create a new knowledge base."""
        # Check if this is the first one, make it default
        count_query = select(func.count()).select_from(KnowledgeBase).where(KnowledgeBase.user_id == user_id)
        count = await self.db.scalar(count_query) or 0
        
        kb = KnowledgeBase(
            user_id=user_id,
            name=kb_data.name,
            description=kb_data.description,
            is_public=kb_data.is_public,
            settings=kb_data.settings,
            is_default=(count == 0)
        )
        self.db.add(kb)
        await self.db.commit()
        await self.db.refresh(kb)
        return kb

    async def update_knowledge_base(
        self,
        user_id: int,
        kb_id: int,
        kb_data: KnowledgeBaseUpdate
    ) -> Optional[KnowledgeBase]:
        """Update knowledge base."""
        kb = await self.get_knowledge_base_by_id(user_id, kb_id)
        if not kb:
            return None
        
        update_data = kb_data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(kb, key, value)
            
        await self.db.commit()
        await self.db.refresh(kb)
        return kb

    async def delete_knowledge_base(self, user_id: int, kb_id: int) -> bool:
        """Delete knowledge base."""
        kb = await self.get_knowledge_base_by_id(user_id, kb_id)
        if not kb:
            return False
            
        await self.db.delete(kb)
        await self.db.commit()
        return True

    # Document operations
    async def get_kb_documents(
        self,
        kb_id: int,
        page: int = 1,
        size: int = 20,
        search: Optional[str] = None
    ) -> Tuple[List[Document], int]:
        """Get documents in a knowledge base with pagination and search."""
        skip = (page - 1) * size
        
        base_query = select(Document).where(Document.knowledge_base_id == kb_id)
        if search:
            base_query = base_query.where(
                or_(
                    Document.title.ilike(f"%{search}%"),
                    Document.content.ilike(f"%{search}%")
                )
            )
            
        # Get total count
        count_query = select(func.count()).select_from(base_query.subquery())
        total = await self.db.scalar(count_query) or 0
        
        # Get items
        query = (
            base_query
            .offset(skip)
            .limit(size)
            .order_by(Document.updated_at.desc())
        )
        result = await self.db.execute(query)
        items = result.scalars().all()
        
        return list(items), total

    async def get_document_by_id(self, user_id: int, doc_id: int) -> Optional[Document]:
        """Get document by ID and verify user ownership through knowledge base."""
        query = (
            select(Document)
            .join(KnowledgeBase)
            .where(
                Document.id == doc_id,
                KnowledgeBase.user_id == user_id
            )
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def create_document(self, doc_data: DocumentCreate) -> Document:
        """Create a new document."""
        doc = Document(
            knowledge_base_id=doc_data.knowledge_base_id,
            title=doc_data.title,
            content=doc_data.content,
            content_type=doc_data.content_type,
            doc_metadata=doc_data.metadata,
            tags=doc_data.tags
        )
        self.db.add(doc)
        await self.db.commit()
        await self.db.refresh(doc)
        return doc

    async def update_document(
        self,
        user_id: int,
        doc_id: int,
        doc_data: DocumentUpdate
    ) -> Optional[Document]:
        """Update document."""
        doc = await self.get_document_by_id(user_id, doc_id)
        if not doc:
            return None
            
        update_data = doc_data.model_dump(exclude_unset=True)
        # Handle tags and metadata specially if needed, but simple setattr usually works
        for key, value in update_data.items():
            if key == 'metadata':
                setattr(doc, 'doc_metadata', value)
            else:
                setattr(doc, key, value)
            
        await self.db.commit()
        await self.db.refresh(doc)
        return doc

    async def delete_document(self, user_id: int, doc_id: int) -> bool:
        """Delete document."""
        doc = await self.get_document_by_id(user_id, doc_id)
        if not doc:
            return False
            
        await self.db.delete(doc)
        await self.db.commit()
        return True

    async def search_across_bases(
        self,
        user_id: int,
        query_str: str,
        kb_ids: Optional[List[int]] = None
    ) -> List[Document]:
        """Simple cross-base keyword search."""
        kb_filter = select(KnowledgeBase.id).where(KnowledgeBase.user_id == user_id)
        if kb_ids:
            kb_filter = kb_filter.where(KnowledgeBase.id.in_(kb_ids))
            
        search_query = (
            select(Document)
            .where(
                Document.knowledge_base_id.in_(kb_filter),
                or_(
                    Document.title.ilike(f"%{query_str}%"),
                    Document.content.ilike(f"%{query_str}%")
                )
            )
            .limit(50)
            .order_by(Document.updated_at.desc())
        )
        result = await self.db.execute(search_query)
        return list(result.scalars().all())
