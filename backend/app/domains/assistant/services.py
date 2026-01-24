"""Assistant domain services."""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.assistant.repositories import AssistantRepository
from app.domains.assistant.models import Conversation, Message, ConversationStatus, MessageRole
from app.shared.schemas import (
    ConversationCreate,
    ConversationUpdate,
    ConversationResponse,
    MessageCreate,
    MessageResponse,
    PaginatedResponse
)

logger = logging.getLogger(__name__)


class AssistantService:
    """Service for orchestrating AI assistant logic."""

    def __init__(self, db: AsyncSession, user_id: int):
        self.db = db
        self.user_id = user_id
        self.repo = AssistantRepository(db)

    # Conversation operations
    async def list_conversations(
        self,
        page: int = 1,
        size: int = 20,
        status: Optional[str] = None
    ) -> PaginatedResponse:
        """List user's conversations."""
        items, total = await self.repo.get_user_conversations(self.user_id, page, size, status)

        # Batch fetch message counts for all conversations (N+1 query fix)
        conv_ids = [conv.id for conv in items]
        msg_counts = await self.repo.get_message_counts_for_conversations(conv_ids)

        response_items = []
        for conv in items:
            response_items.append(ConversationResponse(
                id=conv.id,
                user_id=conv.user_id,
                title=conv.title,
                description=conv.description,
                status=conv.status,
                model_name=conv.model_name,
                system_prompt=conv.system_prompt,
                temperature=conv.temperature,
                settings=conv.settings,
                message_count=msg_counts.get(conv.id, 0),
                created_at=conv.created_at,
                updated_at=conv.updated_at
            ))

        return PaginatedResponse.create(
            items=response_items,
            total=total,
            page=page,
            size=size
        )

    async def create_conversation(
        self,
        conv_data: ConversationCreate
    ) -> ConversationResponse:
        """Create a new conversation."""
        conv = await self.repo.create_conversation(self.user_id, conv_data)
        return ConversationResponse(
            id=conv.id,
            user_id=conv.user_id,
            title=conv.title,
            description=conv.description,
            status=conv.status,
            model_name=conv.model_name,
            system_prompt=conv.system_prompt,
            temperature=conv.temperature,
            settings=conv.settings,
            message_count=0,
            created_at=conv.created_at,
            updated_at=conv.updated_at
        )

    async def get_conversation(
        self,
        conv_id: int
    ) -> Optional[ConversationResponse]:
        """Get conversation details."""
        conv = await self.repo.get_conversation_by_id(self.user_id, conv_id)
        if not conv:
            return None

        msg_count = await self.repo.get_conversation_message_count(conv_id)
        return ConversationResponse(
            id=conv.id,
            user_id=conv.user_id,
            title=conv.title,
            description=conv.description,
            status=conv.status,
            model_name=conv.model_name,
            system_prompt=conv.system_prompt,
            temperature=conv.temperature,
            settings=conv.settings,
            message_count=msg_count,
            created_at=conv.created_at,
            updated_at=conv.updated_at
        )

    async def update_conversation(
        self,
        conv_id: int,
        conv_data: ConversationUpdate
    ) -> Optional[ConversationResponse]:
        """Update conversation."""
        conv = await self.repo.update_conversation(self.user_id, conv_id, conv_data)
        if not conv:
            return None

        return await self.get_conversation(conv_id)

    async def delete_conversation(
        self,
        conv_id: int
    ) -> bool:
        """Delete (soft delete) conversation."""
        return await self.repo.delete_conversation(self.user_id, conv_id)

    async def archive_conversation(
        self,
        conv_id: int
    ) -> Optional[ConversationResponse]:
        """Archive conversation."""
        conv = await self.repo.archive_conversation(self.user_id, conv_id)
        if not conv:
            return None

        msg_count = await self.repo.get_conversation_message_count(conv_id)
        return ConversationResponse(
            id=conv.id,
            user_id=conv.user_id,
            title=conv.title,
            description=conv.description,
            status=conv.status,
            model_name=conv.model_name,
            system_prompt=conv.system_prompt,
            temperature=conv.temperature,
            settings=conv.settings,
            message_count=msg_count,
            created_at=conv.created_at,
            updated_at=conv.updated_at
        )

    # Message operations
    async def get_conversation_messages(
        self,
        conv_id: int,
        page: int = 1,
        size: int = 50
    ) -> PaginatedResponse:
        """Get messages in a conversation."""
        # Verify conversation ownership first
        conv = await self.repo.get_conversation_by_id(self.user_id, conv_id)
        if not conv:
            return PaginatedResponse.create(items=[], total=0, page=page, size=size)

        items, total = await self.repo.get_conversation_messages(conv_id, self.user_id, page, size)

        response_items = [
            MessageResponse(
                id=msg.id,
                conversation_id=msg.conversation_id,
                role=msg.role,
                content=msg.content,
                tokens=msg.tokens,
                model_name=msg.model_name,
                metadata=msg.metadata_json,
                created_at=msg.created_at,
                updated_at=msg.updated_at
            ) for msg in items
        ]

        return PaginatedResponse.create(
            items=response_items,
            total=total,
            page=page,
            size=size
        )

    async def create_user_message(
        self,
        conv_id: int,
        content: str
    ) -> Optional[MessageResponse]:
        """Create a user message."""
        # Verify conversation ownership
        conv = await self.repo.get_conversation_by_id(self.user_id, conv_id)
        if not conv:
            return None

        msg_data = MessageCreate(conversation_id=conv_id, content=content)
        msg = await self.repo.create_message(msg_data, role=MessageRole.USER)

        return MessageResponse(
            id=msg.id,
            conversation_id=msg.conversation_id,
            role=msg.role,
            content=msg.content,
            tokens=msg.tokens,
            model_name=msg.model_name,
            metadata=msg.metadata_json,
            created_at=msg.created_at,
            updated_at=msg.updated_at
        )

    async def create_assistant_message(
        self,
        conv_id: int,
        content: str,
        model_name: str,
        tokens: Optional[int] = None,
        metadata: Optional[dict] = None
    ) -> Optional[MessageResponse]:
        """Create an assistant message."""
        msg_data = MessageCreate(conversation_id=conv_id, content=content)
        msg = await self.repo.create_message(
            msg_data,
            role=MessageRole.ASSISTANT,
            tokens=tokens,
            model_name=model_name,
            metadata=metadata
        )

        return MessageResponse(
            id=msg.id,
            conversation_id=msg.conversation_id,
            role=msg.role,
            content=msg.content,
            tokens=msg.tokens,
            model_name=msg.model_name,
            metadata=msg.metadata_json,
            created_at=msg.created_at,
            updated_at=msg.updated_at
        )

    async def create_system_message(
        self,
        conv_id: int,
        content: str
    ) -> Optional[MessageResponse]:
        """Create a system message."""
        msg_data = MessageCreate(conversation_id=conv_id, content=content)
        msg = await self.repo.create_message(msg_data, role=MessageRole.SYSTEM)

        return MessageResponse(
            id=msg.id,
            conversation_id=msg.conversation_id,
            role=msg.role,
            content=msg.content,
            tokens=msg.tokens,
            model_name=msg.model_name,
            metadata=msg.metadata_json,
            created_at=msg.created_at,
            updated_at=msg.updated_at
        )

    # Chat functionality (skeleton - AI integration would go here)
    async def chat(
        self,
        message: str,
        conversation_id: Optional[int] = None,
        model_name: str = "gpt-3.5-turbo",
        temperature: int = 70,
        system_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send a message and get AI response.
        This is a skeleton implementation that would integrate with AI models.
        """
        from app.core.config import settings

        # Create conversation if not provided
        if not conversation_id:
            # Generate title from first message
            max_len = settings.ASSISTANT_TITLE_TRUNCATION_LENGTH
            title = message[:max_len] + "..." if len(message) > max_len else message
            conv_data = ConversationCreate(
                title=title,
                model_name=model_name,
                temperature=temperature,
                system_prompt=system_prompt
            )
            conv_response = await self.create_conversation(conv_data)
            conversation_id = conv_response.id
        else:
            # Verify ownership
            conv = await self.repo.get_conversation_by_id(self.user_id, conversation_id)
            if not conv:
                raise ValueError("Conversation not found")

        # Create user message
        user_msg = await self.create_user_message(conversation_id, message)
        if not user_msg:
            raise ValueError("Failed to create user message")

        # TODO: Integrate with actual AI model here
        # For now, return a placeholder response
        ai_response = "This is a placeholder AI response. AI model integration is pending."

        # Create assistant message
        assistant_msg = await self.create_assistant_message(
            conversation_id,
            ai_response,
            model_name
        )

        return {
            "conversation_id": conversation_id,
            "user_message": user_msg,
            "assistant_message": assistant_msg,
            "model_used": model_name
        }

    async def get_conversation_for_ai(
        self,
        conv_id: int
    ) -> Optional[Dict[str, Any]]:
        """
        Get conversation context for AI processing.
        Returns conversation details and message history.
        """
        conv = await self.repo.get_conversation_with_messages(self.user_id, conv_id)
        if not conv:
            return None

        messages = [
            {
                "id": msg.id,
                "role": msg.role,
                "content": msg.content,
                "created_at": msg.created_at.isoformat()
            }
            for msg in conv.messages
        ]

        return {
            "id": conv.id,
            "title": conv.title,
            "model_name": conv.model_name,
            "system_prompt": conv.system_prompt,
            "temperature": conv.temperature,
            "settings": conv.settings,
            "messages": messages
        }

    # Prompt Template operations
    async def get_prompt_templates(
        self,
        category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get available prompt templates."""
        templates = await self.repo.get_prompt_templates(
            self.user_id,
            category=category
        )

        return [
            {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "template": t.template,
                "variables": t.variables,
                "is_public": t.is_public,
                "is_system": t.is_system,
                "usage_count": t.usage_count
            }
            for t in templates
        ]

    async def create_prompt_template(
        self,
        name: str,
        template: str,
        description: Optional[str] = None,
        category: Optional[str] = None,
        variables: Optional[List[str]] = None,
        is_public: bool = False
    ) -> Dict[str, Any]:
        """Create a new prompt template."""
        t = await self.repo.create_prompt_template(
            self.user_id,
            name,
            template,
            description,
            category,
            variables,
            is_public
        )

        return {
            "id": t.id,
            "name": t.name,
            "description": t.description,
            "category": t.category,
            "template": t.template,
            "variables": t.variables,
            "is_public": t.is_public,
            "usage_count": t.usage_count,
            "created_at": t.created_at.isoformat()
        }

    async def delete_prompt_template(
        self,
        template_id: int
    ) -> bool:
        """Delete a prompt template."""
        return await self.repo.delete_prompt_template(template_id, self.user_id)

    # Task operations
    async def list_tasks(
        self,
        status: Optional[str] = None,
        page: int = 1,
        size: int = 20
    ) -> PaginatedResponse:
        """List assistant tasks."""
        items, total = await self.repo.get_user_tasks(self.user_id, status, page, size)

        response_items = [
            {
                "id": task.id,
                "title": task.title,
                "description": task.description,
                "task_type": task.task_type,
                "status": task.status,
                "priority": task.priority,
                "due_date": task.due_date.isoformat() if task.due_date else None,
                "completed_at": task.completed_at.isoformat() if task.completed_at else None,
                "result": task.result,
                "created_at": task.created_at.isoformat()
            }
            for task in items
        ]

        return PaginatedResponse.create(
            items=response_items,
            total=total,
            page=page,
            size=size
        )

    async def create_task(
        self,
        title: str,
        task_type: str,
        description: Optional[str] = None,
        conversation_id: Optional[int] = None,
        priority: str = "medium",
        due_date: Optional[datetime] = None,
        metadata: Optional[dict] = None
    ) -> Dict[str, Any]:
        """Create a new assistant task."""
        task = await self.repo.create_task(
            self.user_id,
            title,
            task_type,
            description,
            conversation_id,
            priority,
            due_date,
            metadata
        )

        return {
            "id": task.id,
            "title": task.title,
            "description": task.description,
            "task_type": task.task_type,
            "status": task.status,
            "priority": task.priority,
            "due_date": task.due_date.isoformat() if task.due_date else None,
            "created_at": task.created_at.isoformat()
        }

    async def complete_task(
        self,
        task_id: int,
        result: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Mark a task as completed."""
        task = await self.repo.update_task_status(
            task_id,
            self.user_id,
            "completed",
            result
        )

        if not task:
            return None

        return {
            "id": task.id,
            "title": task.title,
            "status": task.status,
            "result": task.result,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None
        }

    # Tool Call operations
    async def record_tool_call(
        self,
        message_id: int,
        tool_name: str,
        arguments: dict
    ) -> Dict[str, Any]:
        """Record a tool call initiated by the assistant."""
        tool_call = await self.repo.create_tool_call(message_id, tool_name, arguments)

        return {
            "id": tool_call.id,
            "tool_name": tool_call.tool_name,
            "arguments": tool_call.arguments,
            "status": tool_call.status,
            "created_at": tool_call.created_at.isoformat()
        }

    async def complete_tool_call(
        self,
        tool_call_id: int,
        result: dict,
        execution_time_ms: int
    ) -> Optional[Dict[str, Any]]:
        """Mark a tool call as completed with result."""
        tool_call = await self.repo.update_tool_call_result(
            tool_call_id,
            result=result,
            status="completed",
            execution_time=execution_time_ms
        )

        if not tool_call:
            return None

        return {
            "id": tool_call.id,
            "tool_name": tool_call.tool_name,
            "status": tool_call.status,
            "result": tool_call.result,
            "execution_time": tool_call.execution_time
        }

    async def fail_tool_call(
        self,
        tool_call_id: int,
        error_message: str
    ) -> Optional[Dict[str, Any]]:
        """Mark a tool call as failed."""
        tool_call = await self.repo.update_tool_call_result(
            tool_call_id,
            status="failed",
            error_message=error_message
        )

        if not tool_call:
            return None

        return {
            "id": tool_call.id,
            "tool_name": tool_call.tool_name,
            "status": tool_call.status,
            "error_message": tool_call.error_message
        }
