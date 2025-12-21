"""Knowledge domain services."""

import logging
from typing import List, Tuple, Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.knowledge.repositories import KnowledgeRepository
from app.domains.knowledge.models import KnowledgeBase, Document
from app.shared.schemas import (
    KnowledgeBaseCreate, 
    KnowledgeBaseUpdate, 
    KnowledgeBaseResponse,
    DocumentCreate, 
    DocumentUpdate, 
    DocumentResponse,
    PaginatedResponse
)

logger = logging.getLogger(__name__)


class KnowledgeService:
    """Service for orchestrating knowledge domain logic."""

    def __init__(self, db: AsyncSession, user_id: int):
        self.db = db
        self.user_id = user_id
        self.repo = KnowledgeRepository(db)

    # Knowledge Base orchestration
    async def list_knowledge_bases(self, page: int = 1, size: int = 20) -> PaginatedResponse:
        """List knowledge bases and format as paginated response."""
        items, total = await self.repo.get_user_knowledge_bases(self.user_id, page, size)
        
        # We need to count documents for each KB to match the schema
        # In a real app, this might be optimized with joined queries
        response_items = []
        for kb in items:
            # Simple count for now
            from sqlalchemy import select, func
            from app.domains.knowledge.models import Document as DocModel
            doc_count = await self.db.scalar(
                select(func.count()).where(DocModel.knowledge_base_id == kb.id)
            ) or 0
            
            response_items.append(KnowledgeBaseResponse(
                id=kb.id,
                user_id=kb.user_id,
                name=kb.name,
                description=kb.description,
                is_public=kb.is_public,
                is_default=kb.is_default,
                settings=kb.settings,
                document_count=doc_count,
                created_at=kb.created_at,
                updated_at=kb.updated_at
            ))
            
        return PaginatedResponse.create(
            items=response_items,
            total=total,
            page=page,
            size=size
        )

    async def create_knowledge_base(self, kb_data: KnowledgeBaseCreate) -> KnowledgeBaseResponse:
        """Create a new knowledge base."""
        kb = await self.repo.create_knowledge_base(self.user_id, kb_data)
        return KnowledgeBaseResponse(
            id=kb.id,
            user_id=kb.user_id,
            name=kb.name,
            description=kb.description,
            is_public=kb.is_public,
            is_default=kb.is_default,
            settings=kb.settings,
            document_count=0,
            created_at=kb.created_at,
            updated_at=kb.updated_at
        )

    async def get_knowledge_base(self, kb_id: int) -> Optional[KnowledgeBaseResponse]:
        """Get details for a specific knowledge base."""
        kb = await self.repo.get_knowledge_base_by_id(self.user_id, kb_id)
        if not kb:
            return None
            
        from sqlalchemy import select, func
        from app.domains.knowledge.models import Document as DocModel
        doc_count = await self.db.scalar(
            select(func.count()).where(DocModel.knowledge_base_id == kb.id)
        ) or 0
            
        return KnowledgeBaseResponse(
            id=kb.id,
            user_id=kb.user_id,
            name=kb.name,
            description=kb.description,
            is_public=kb.is_public,
            is_default=kb.is_default,
            settings=kb.settings,
            document_count=doc_count,
            created_at=kb.created_at,
            updated_at=kb.updated_at
        )

    async def update_knowledge_base(
        self, 
        kb_id: int, 
        kb_data: KnowledgeBaseUpdate
    ) -> Optional[KnowledgeBaseResponse]:
        """Update knowledge base."""
        kb = await self.repo.update_knowledge_base(self.user_id, kb_id, kb_data)
        if not kb:
            return None
            
        return await self.get_knowledge_base(kb_id)

    async def delete_knowledge_base(self, kb_id: int) -> bool:
        """Hande deletion of knowledge base."""
        return await self.repo.delete_knowledge_base(self.user_id, kb_id)

    # Document orchestration
    async def list_documents(
        self, 
        kb_id: int, 
        page: int = 1, 
        size: int = 20, 
        search: Optional[str] = None
    ) -> PaginatedResponse:
        """List documents in a KB and format as response."""
        # First verify user owns the KB
        kb = await self.repo.get_knowledge_base_by_id(self.user_id, kb_id)
        if not kb:
            # We'll just return empty/error or let repository return items
            # Better to check here
            return PaginatedResponse.create(items=[], total=0, page=page, size=size)
            
        items, total = await self.repo.get_kb_documents(kb_id, page, size, search)
        
        response_items = [
            DocumentResponse(
                id=doc.id,
                knowledge_base_id=doc.knowledge_base_id,
                title=doc.title,
                content=doc.content,
                content_type=doc.content_type,
                metadata=doc.doc_metadata,
                tags=doc.tags,
                file_path=doc.file_path,
                file_size=doc.file_size,
                indexed_at=doc.indexed_at,
                created_at=doc.created_at,
                updated_at=doc.updated_at
            ) for doc in items
        ]
        
        return PaginatedResponse.create(
            items=response_items,
            total=total,
            page=page,
            size=size
        )

    async def create_document(self, doc_data: DocumentCreate) -> Optional[DocumentResponse]:
        """Create a new document after verifying KB ownership."""
        kb = await self.repo.get_knowledge_base_by_id(self.user_id, doc_data.knowledge_base_id)
        if not kb:
            return None
            
        doc = await self.repo.create_document(doc_data)
        return DocumentResponse(
            id=doc.id,
            knowledge_base_id=doc.knowledge_base_id,
            title=doc.title,
            content=doc.content,
            content_type=doc.content_type,
            metadata=doc.doc_metadata,
            tags=doc.tags,
            file_path=doc.file_path,
            file_size=doc.file_size,
            indexed_at=doc.indexed_at,
            created_at=doc.created_at,
            updated_at=doc.updated_at
        )

    async def get_document(self, doc_id: int) -> Optional[DocumentResponse]:
        """Fetch document details."""
        doc = await self.repo.get_document_by_id(self.user_id, doc_id)
        if not doc:
            return None
            
        return DocumentResponse(
            id=doc.id,
            knowledge_base_id=doc.knowledge_base_id,
            title=doc.title,
            content=doc.content,
            content_type=doc.content_type,
            metadata=doc.doc_metadata,
            tags=doc.tags,
            file_path=doc.file_path,
            file_size=doc.file_size,
            indexed_at=doc.indexed_at,
            created_at=doc.created_at,
            updated_at=doc.updated_at
        )

    async def update_document(self, doc_id: int, doc_data: DocumentUpdate) -> Optional[DocumentResponse]:
        """Update existing document."""
        doc = await self.repo.update_document(self.user_id, doc_id, doc_data)
        if not doc:
            return None
            
        return DocumentResponse(
            id=doc.id,
            knowledge_base_id=doc.knowledge_base_id,
            title=doc.title,
            content=doc.content,
            content_type=doc.content_type,
            metadata=doc.doc_metadata,
            tags=doc.tags,
            file_path=doc.file_path,
            file_size=doc.file_size,
            indexed_at=doc.indexed_at,
            created_at=doc.created_at,
            updated_at=doc.updated_at
        )

    async def delete_document(self, doc_id: int) -> bool:
        """Delete a document."""
        return await self.repo.delete_document(self.user_id, doc_id)

    async def upload_document(
        self, 
        kb_id: int, 
        file: Any, 
        filename: str, 
        content_type: str
    ) -> Optional[DocumentResponse]:
        """Upload and save a document file."""
        import os
        import aiofiles
        import hashlib
        from app.shared.schemas import DocumentCreate
        
        # 1. Verify KB ownership
        kb = await self.repo.get_knowledge_base_by_id(self.user_id, kb_id)
        if not kb:
            return None
            
        # 2. Ensure upload directory exists
        upload_dir = os.path.join("uploads", "knowledge", str(kb_id))
        os.makedirs(upload_dir, exist_ok=True)
        
        file_path = os.path.join(upload_dir, filename)
        
        # 3. Save file and calculate size/hash
        size = 0
        sha256_hash = hashlib.sha256()
        
        async with aiofiles.open(file_path, 'wb') as out_file:
            while content := await file.read(1024 * 1024):  # 1MB chunks
                size += len(content)
                sha256_hash.update(content)
                await out_file.write(content)
        
        # 4. Create document record
        doc_data = DocumentCreate(
            knowledge_base_id=kb_id,
            title=filename,
            content=None,
            content_type=content_type or "application/octet-stream",
            metadata={
                "original_filename": filename,
                "sha256": sha256_hash.hexdigest(),
            },
            tags=[],
            file_path=file_path,
            file_size=size
        )
        
        doc = await self.repo.create_document(doc_data)
        
        return DocumentResponse(
            id=doc.id,
            knowledge_base_id=doc.knowledge_base_id,
            title=doc.title,
            content=doc.content,
            content_type=doc.content_type,
            metadata=doc.doc_metadata,
            tags=doc.tags,
            file_path=doc.file_path,
            file_size=doc.file_size,
            indexed_at=doc.indexed_at,
            created_at=doc.created_at,
            updated_at=doc.updated_at
        )

    async def search_knowledge(self, query: str, kb_ids: Optional[List[int]] = None) -> List[DocumentResponse]:
        """Search for content across knowledge bases."""
        docs = await self.repo.search_across_bases(self.user_id, query, kb_ids)
        
        return [
            DocumentResponse(
                id=doc.id,
                knowledge_base_id=doc.knowledge_base_id,
                title=doc.title,
                content=doc.content,
                content_type=doc.content_type,
                metadata=doc.doc_metadata,
                tags=doc.tags,
                file_path=doc.file_path,
                file_size=doc.file_size,
                indexed_at=doc.indexed_at,
                created_at=doc.created_at,
                updated_at=doc.updated_at
            ) for doc in docs
        ]
