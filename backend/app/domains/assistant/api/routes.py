"""AI Assistant API routes."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from app.core.database import get_db_session
from app.core.dependencies import get_current_active_user
from app.domains.user.models import User
from app.domains.assistant.services import AssistantService
from app.shared.schemas import (
    ConversationCreate,
    ConversationUpdate,
    ConversationResponse,
    MessageCreate,
    MessageResponse,
    PaginatedResponse,
    PaginationParams
)

router = APIRouter()


# Request/Response models for endpoints not covered by shared schemas
class ChatRequest(BaseModel):
    """Request model for chat endpoint."""
    message: str = Field(..., description="User message to send")
    conversation_id: Optional[int] = Field(None, description="Existing conversation ID (creates new if not provided)")
    model_name: str = Field("gpt-3.5-turbo", description="AI model to use")
    temperature: int = Field(70, description="Temperature for AI generation (0-100)", ge=0, le=100)
    system_prompt: Optional[str] = Field(None, description="System prompt for the conversation")


class ChatResponse(BaseModel):
    """Response model for chat endpoint."""
    conversation_id: int
    user_message: MessageResponse
    assistant_message: MessageResponse
    model_used: str


class PromptTemplateCreate(BaseModel):
    """Request model for creating prompt template."""
    name: str = Field(..., min_length=1, max_length=255)
    template: str = Field(..., min_length=1)
    description: Optional[str] = None
    category: Optional[str] = None
    variables: Optional[List[str]] = []
    is_public: bool = False


class PromptTemplateResponse(BaseModel):
    """Response model for prompt template."""
    id: int
    name: str
    description: Optional[str]
    category: Optional[str]
    template: str
    variables: List[str]
    is_public: bool
    is_system: bool
    usage_count: int
    created_at: str


class TaskCreate(BaseModel):
    """Request model for creating assistant task."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    task_type: str = Field(..., description="Type of task (e.g., reminder, research, summary)")
    conversation_id: Optional[int] = None
    priority: str = Field("medium", pattern="^(low|medium|high)$")


class TaskResponse(BaseModel):
    """Response model for assistant task."""
    id: int
    title: str
    description: Optional[str]
    task_type: str
    status: str
    priority: str
    due_date: Optional[str]
    completed_at: Optional[str]
    result: Optional[str]
    created_at: str


# Conversation endpoints
@router.get("/conversations/", response_model=PaginatedResponse)
async def list_conversations(
    pagination: PaginationParams = Depends(),
    status: Optional[str] = Query(None, description="Filter by status (active, archived, deleted)"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """List user's conversations."""
    service = AssistantService(db, current_user.id)
    return await service.list_conversations(
        page=pagination.page,
        size=pagination.size,
        status=status
    )


@router.post("/conversations/", response_model=ConversationResponse)
async def create_conversation(
    conversation_data: ConversationCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Create a new conversation."""
    service = AssistantService(db, current_user.id)
    return await service.create_conversation(conversation_data)


@router.get("/conversations/{conv_id}", response_model=ConversationResponse)
async def get_conversation(
    conv_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Get conversation by ID."""
    service = AssistantService(db, current_user.id)
    result = await service.get_conversation(conv_id)
    if not result:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return result


@router.put("/conversations/{conv_id}", response_model=ConversationResponse)
async def update_conversation(
    conv_id: int,
    conversation_data: ConversationUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Update conversation."""
    service = AssistantService(db, current_user.id)
    result = await service.update_conversation(conv_id, conversation_data)
    if not result:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return result


@router.delete("/conversations/{conv_id}")
async def delete_conversation(
    conv_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Delete conversation (soft delete)."""
    service = AssistantService(db, current_user.id)
    success = await service.delete_conversation(conv_id)
    if not success:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"message": "Conversation deleted"}


@router.post("/conversations/{conv_id}/archive", response_model=ConversationResponse)
async def archive_conversation(
    conv_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Archive a conversation."""
    service = AssistantService(db, current_user.id)
    result = await service.archive_conversation(conv_id)
    if not result:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return result


# Message endpoints
@router.get("/conversations/{conv_id}/messages/", response_model=PaginatedResponse)
async def get_conversation_messages(
    conv_id: int,
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Get messages in a conversation."""
    service = AssistantService(db, current_user.id)
    return await service.get_conversation_messages(
        conv_id,
        page=pagination.page,
        size=pagination.size
    )


@router.post("/conversations/{conv_id}/messages/", response_model=MessageResponse)
async def create_message(
    conv_id: int,
    message_data: MessageCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Create a new user message."""
    service = AssistantService(db, current_user.id)
    result = await service.create_user_message(conv_id, message_data.content)
    if not result:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return result


# Chat endpoint
@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Send a message and get AI response.

    This endpoint creates or updates a conversation with AI-generated responses.
    Note: AI model integration is pending - currently returns placeholder responses.
    """
    service = AssistantService(db, current_user.id)

    try:
        result = await service.chat(
            message=request.message,
            conversation_id=request.conversation_id,
            model_name=request.model_name,
            temperature=request.temperature,
            system_prompt=request.system_prompt
        )
        return ChatResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# Prompt templates
@router.get("/prompts/", response_model=List[PromptTemplateResponse])
async def list_prompt_templates(
    category: Optional[str] = Query(None, description="Filter by category"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """List available prompt templates."""
    service = AssistantService(db, current_user.id)
    return await service.get_prompt_templates(category=category)


@router.post("/prompts/", response_model=PromptTemplateResponse)
async def create_prompt_template(
    template_data: PromptTemplateCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Create a new prompt template."""
    service = AssistantService(db, current_user.id)
    return await service.create_prompt_template(
        name=template_data.name,
        template=template_data.template,
        description=template_data.description,
        category=template_data.category,
        variables=template_data.variables,
        is_public=template_data.is_public
    )


@router.delete("/prompts/{template_id}")
async def delete_prompt_template(
    template_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Delete a prompt template."""
    service = AssistantService(db, current_user.id)
    success = await service.delete_prompt_template(template_id)
    if not success:
        raise HTTPException(status_code=404, detail="Template not found or access denied")
    return {"message": "Template deleted"}


# Task management
@router.get("/tasks/", response_model=PaginatedResponse)
async def list_tasks(
    pagination: PaginationParams = Depends(),
    status: Optional[str] = Query(None, description="Filter by status"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """List assistant tasks."""
    service = AssistantService(db, current_user.id)
    return await service.list_tasks(
        status=status,
        page=pagination.page,
        size=pagination.size
    )


@router.post("/tasks/", response_model=TaskResponse)
async def create_task(
    task_data: TaskCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Create a new assistant task."""
    service = AssistantService(db, current_user.id)
    return await service.create_task(
        title=task_data.title,
        task_type=task_data.task_type,
        description=task_data.description,
        conversation_id=task_data.conversation_id,
        priority=task_data.priority
    )


@router.post("/tasks/{task_id}/complete", response_model=TaskResponse)
async def complete_task(
    task_id: int,
    result: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Mark a task as completed."""
    service = AssistantService(db, current_user.id)
    task = await service.complete_task(task_id, result)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


# Conversation context for AI
@router.get("/conversations/{conv_id}/context")
async def get_conversation_context(
    conv_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Get conversation context including message history for AI processing."""
    service = AssistantService(db, current_user.id)
    context = await service.get_conversation_for_ai(conv_id)
    if not context:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return context
