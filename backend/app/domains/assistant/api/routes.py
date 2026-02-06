"""AI Assistant API routes."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.domains.assistant.api.dependencies import get_assistant_service
from app.domains.assistant.services import AssistantService
from app.shared.schemas import (
    ConversationCreate,
    ConversationResponse,
    ConversationUpdate,
    MessageCreate,
    MessageResponse,
    PaginatedResponse,
    PaginationParams,
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
    variables: Optional[list[str]] = []
    is_public: bool = False


class PromptTemplateResponse(BaseModel):
    """Response model for prompt template."""
    id: int
    name: str
    description: Optional[str]
    category: Optional[str]
    template: str
    variables: list[str]
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
    service: AssistantService = Depends(get_assistant_service)
):
    """List user's conversations."""
    return await service.list_conversations(
        page=pagination.page,
        size=pagination.size,
        status=status
    )


@router.post("/conversations/", response_model=ConversationResponse)
async def create_conversation(
    conversation_data: ConversationCreate,
    service: AssistantService = Depends(get_assistant_service)
):
    """Create a new conversation."""
    return await service.create_conversation(conversation_data)


@router.get("/conversations/{conv_id}", response_model=ConversationResponse)
async def get_conversation(
    conv_id: int,
    service: AssistantService = Depends(get_assistant_service)
):
    """Get conversation by ID."""
    result = await service.get_conversation(conv_id)
    if not result:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return result


@router.put("/conversations/{conv_id}", response_model=ConversationResponse)
async def update_conversation(
    conv_id: int,
    conversation_data: ConversationUpdate,
    service: AssistantService = Depends(get_assistant_service)
):
    """Update conversation."""
    result = await service.update_conversation(conv_id, conversation_data)
    if not result:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return result


@router.delete("/conversations/{conv_id}")
async def delete_conversation(
    conv_id: int,
    service: AssistantService = Depends(get_assistant_service)
):
    """Delete conversation (soft delete)."""
    success = await service.delete_conversation(conv_id)
    if not success:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"message": "Conversation deleted"}


@router.post("/conversations/{conv_id}/archive", response_model=ConversationResponse)
async def archive_conversation(
    conv_id: int,
    service: AssistantService = Depends(get_assistant_service)
):
    """Archive a conversation."""
    result = await service.archive_conversation(conv_id)
    if not result:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return result


# Message endpoints
@router.get("/conversations/{conv_id}/messages/", response_model=PaginatedResponse)
async def get_conversation_messages(
    conv_id: int,
    pagination: PaginationParams = Depends(),
    service: AssistantService = Depends(get_assistant_service)
):
    """Get messages in a conversation."""
    return await service.get_conversation_messages(
        conv_id,
        page=pagination.page,
        size=pagination.size
    )


@router.post("/conversations/{conv_id}/messages/", response_model=MessageResponse)
async def create_message(
    conv_id: int,
    message_data: MessageCreate,
    service: AssistantService = Depends(get_assistant_service)
):
    """Create a new user message."""
    result = await service.create_user_message(conv_id, message_data.content)
    if not result:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return result


# Chat endpoint
@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    service: AssistantService = Depends(get_assistant_service)
):
    """Send a message and get AI response.

    This endpoint creates or updates a conversation with AI-generated responses.
    Note: AI model integration is pending - currently returns placeholder responses.
    """

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
@router.get("/prompts/", response_model=list[PromptTemplateResponse])
async def list_prompt_templates(
    category: Optional[str] = Query(None, description="Filter by category"),
    service: AssistantService = Depends(get_assistant_service)
):
    """List available prompt templates."""
    return await service.get_prompt_templates(category=category)


@router.post("/prompts/", response_model=PromptTemplateResponse)
async def create_prompt_template(
    template_data: PromptTemplateCreate,
    service: AssistantService = Depends(get_assistant_service)
):
    """Create a new prompt template."""
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
    service: AssistantService = Depends(get_assistant_service)
):
    """Delete a prompt template."""
    success = await service.delete_prompt_template(template_id)
    if not success:
        raise HTTPException(status_code=404, detail="Template not found or access denied")
    return {"message": "Template deleted"}


# Task management
@router.get("/tasks/", response_model=PaginatedResponse)
async def list_tasks(
    pagination: PaginationParams = Depends(),
    status: Optional[str] = Query(None, description="Filter by status"),
    service: AssistantService = Depends(get_assistant_service)
):
    """List assistant tasks."""
    return await service.list_tasks(
        status=status,
        page=pagination.page,
        size=pagination.size
    )


@router.post("/tasks/", response_model=TaskResponse)
async def create_task(
    task_data: TaskCreate,
    service: AssistantService = Depends(get_assistant_service)
):
    """Create a new assistant task."""
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
    service: AssistantService = Depends(get_assistant_service)
):
    """Mark a task as completed."""
    task = await service.complete_task(task_id, result)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


# Conversation context for AI
@router.get("/conversations/{conv_id}/context")
async def get_conversation_context(
    conv_id: int,
    service: AssistantService = Depends(get_assistant_service)
):
    """Get conversation context including message history for AI processing."""
    context = await service.get_conversation_for_ai(conv_id)
    if not context:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return context
