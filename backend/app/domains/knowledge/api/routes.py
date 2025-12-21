"""Knowledge base API routes."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, UploadFile, File, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.dependencies import get_current_active_user
from app.domains.user.models import User
from app.domains.knowledge.services import KnowledgeService
from app.shared.schemas import (
    KnowledgeBaseCreate,
    KnowledgeBaseUpdate,
    KnowledgeBaseResponse,
    DocumentCreate,
    DocumentUpdate,
    DocumentResponse,
    KnowledgeSearchRequest,
    PaginatedResponse,
    PaginationParams
)

router = APIRouter()


# Knowledge Base endpoints
@router.get("/bases/", response_model=PaginatedResponse)
async def list_knowledge_bases(
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """List user's knowledge bases."""
    service = KnowledgeService(db, current_user.id)
    return await service.list_knowledge_bases(pagination.page, pagination.size)


@router.post("/bases/", response_model=KnowledgeBaseResponse)
async def create_knowledge_base(
    kb_data: KnowledgeBaseCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Create a new knowledge base."""
    service = KnowledgeService(db, current_user.id)
    return await service.create_knowledge_base(kb_data)


@router.get("/bases/{kb_id}", response_model=KnowledgeBaseResponse)
async def get_knowledge_base(
    kb_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Get knowledge base by ID."""
    service = KnowledgeService(db, current_user.id)
    kb = await service.get_knowledge_base(kb_id)
    if not kb:
        raise HTTPException(status_code=404, detail="Knowledge base not found")
    return kb


@router.put("/bases/{kb_id}", response_model=KnowledgeBaseResponse)
async def update_knowledge_base(
    kb_id: int,
    kb_data: KnowledgeBaseUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Update knowledge base."""
    service = KnowledgeService(db, current_user.id)
    kb = await service.update_knowledge_base(kb_id, kb_data)
    if not kb:
        raise HTTPException(status_code=404, detail="Knowledge base not found")
    return kb


@router.delete("/bases/{kb_id}")
async def delete_knowledge_base(
    kb_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Delete knowledge base."""
    service = KnowledgeService(db, current_user.id)
    success = await service.delete_knowledge_base(kb_id)
    if not success:
        raise HTTPException(status_code=404, detail="Knowledge base not found")
    return {"success": True, "message": "Knowledge base deleted"}


# Document endpoints
@router.get("/bases/{kb_id}/documents/", response_model=PaginatedResponse)
async def list_documents(
    kb_id: int,
    pagination: PaginationParams = Depends(),
    search: Optional[str] = Query(None),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """List documents in a knowledge base."""
    service = KnowledgeService(db, current_user.id)
    return await service.list_documents(kb_id, pagination.page, pagination.size, search)


@router.post("/bases/{kb_id}/documents/", response_model=DocumentResponse)
async def create_document(
    kb_id: int,
    document_data: DocumentCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Create a new document."""
    if kb_id != document_data.knowledge_base_id:
        raise HTTPException(status_code=400, detail="ID mismatch")
        
    service = KnowledgeService(db, current_user.id)
    doc = await service.create_document(document_data)
    if not doc:
        raise HTTPException(status_code=404, detail="Knowledge base not found")
    return doc


@router.post("/bases/{kb_id}/documents/upload", response_model=DocumentResponse)
async def upload_document(
    kb_id: int,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Upload a document file."""
    service = KnowledgeService(db, current_user.id)
    doc = await service.upload_document(
        kb_id=kb_id,
        file=file,
        filename=file.filename,
        content_type=file.content_type
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Knowledge base not found or access denied")
    return doc


@router.get("/documents/{doc_id}", response_model=DocumentResponse)
async def get_document(
    doc_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Get document by ID."""
    service = KnowledgeService(db, current_user.id)
    doc = await service.get_document(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc


@router.put("/documents/{doc_id}", response_model=DocumentResponse)
async def update_document(
    doc_id: int,
    document_data: DocumentUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Update document."""
    service = KnowledgeService(db, current_user.id)
    doc = await service.update_document(doc_id, document_data)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc


@router.delete("/documents/{doc_id}")
async def delete_document(
    doc_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Delete document."""
    service = KnowledgeService(db, current_user.id)
    success = await service.delete_document(doc_id)
    if not success:
        raise HTTPException(status_code=404, detail="Document not found")
    return {"success": True, "message": "Document deleted"}


# Search endpoint
@router.post("/search", response_model=List[DocumentResponse])
async def search_knowledge(
    search_data: KnowledgeSearchRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Search across knowledge bases."""
    service = KnowledgeService(db, current_user.id)
    return await service.search_knowledge(search_data.query, search_data.kb_ids)