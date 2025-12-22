"""Assistant domain repositories."""

from typing import List, Optional, Tuple
from sqlalchemy import select, func, update, delete, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.domains.assistant.models import (
    Conversation, Message, PromptTemplate,
    AssistantTask, ToolCall,
    ConversationStatus, MessageRole
)
from app.shared.schemas import (
    ConversationCreate, ConversationUpdate,
    MessageCreate
)


class AssistantRepository:
    """Repository for managing AI assistant data."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # Conversation operations
    async def get_user_conversations(
        self,
        user_id: int,
        page: int = 1,
        size: int = 20,
        status: Optional[str] = None
    ) -> Tuple[List[Conversation], int]:
        """Get user's conversations with pagination."""
        skip = (page - 1) * size

        # Build base query
        base_query = select(Conversation).where(Conversation.user_id == user_id)
        if status:
            base_query = base_query.where(Conversation.status == status)

        # Get total count
        count_query = select(func.count()).select_from(base_query.subquery())
        total = await self.db.scalar(count_query) or 0

        # Get items with messages count
        query = (
            base_query
            .offset(skip)
            .limit(size)
            .order_by(Conversation.updated_at.desc())
        )
        result = await self.db.execute(query)
        items = result.scalars().all()

        return list(items), total

    async def get_conversation_by_id(
        self,
        user_id: int,
        conv_id: int
    ) -> Optional[Conversation]:
        """Get conversation by ID with user ownership verification."""
        query = select(Conversation).where(
            Conversation.id == conv_id,
            Conversation.user_id == user_id
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_conversation_with_messages(
        self,
        user_id: int,
        conv_id: int
    ) -> Optional[Conversation]:
        """Get conversation with all messages."""
        query = (
            select(Conversation)
            .options(selectinload(Conversation.messages))
            .where(
                Conversation.id == conv_id,
                Conversation.user_id == user_id
            )
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def create_conversation(
        self,
        user_id: int,
        conv_data: ConversationCreate
    ) -> Conversation:
        """Create a new conversation."""
        conv = Conversation(
            user_id=user_id,
            title=conv_data.title,
            description=conv_data.description,
            model_name=conv_data.model_name,
            system_prompt=conv_data.system_prompt,
            temperature=conv_data.temperature,
            settings=conv_data.settings,
            status=ConversationStatus.ACTIVE
        )
        self.db.add(conv)
        await self.db.commit()
        await self.db.refresh(conv)
        return conv

    async def update_conversation(
        self,
        user_id: int,
        conv_id: int,
        conv_data: ConversationUpdate
    ) -> Optional[Conversation]:
        """Update conversation."""
        conv = await self.get_conversation_by_id(user_id, conv_id)
        if not conv:
            return None

        update_data = conv_data.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            setattr(conv, key, value)

        await self.db.commit()
        await self.db.refresh(conv)
        return conv

    async def delete_conversation(
        self,
        user_id: int,
        conv_id: int
    ) -> bool:
        """Delete conversation (soft delete by setting status)."""
        conv = await self.get_conversation_by_id(user_id, conv_id)
        if not conv:
            return False

        conv.status = ConversationStatus.DELETED
        await self.db.commit()
        return True

    async def archive_conversation(
        self,
        user_id: int,
        conv_id: int
    ) -> Optional[Conversation]:
        """Archive a conversation."""
        conv = await self.get_conversation_by_id(user_id, conv_id)
        if not conv:
            return None

        conv.status = ConversationStatus.ARCHIVED
        await self.db.commit()
        await self.db.refresh(conv)
        return conv

    # Message operations
    async def get_conversation_messages(
        self,
        conversation_id: int,
        user_id: int,
        page: int = 1,
        size: int = 50
    ) -> Tuple[List[Message], int]:
        """Get messages in a conversation with pagination."""
        skip = (page - 1) * size

        # First verify conversation ownership
        conv = await self.get_conversation_by_id(user_id, conversation_id)
        if not conv:
            return [], 0

        # Get total count
        count_query = select(func.count()).select_from(Message).where(
            Message.conversation_id == conversation_id
        )
        total = await self.db.scalar(count_query) or 0

        # Get messages
        query = (
            select(Message)
            .where(Message.conversation_id == conversation_id)
            .offset(skip)
            .limit(size)
            .order_by(Message.created_at.asc())
        )
        result = await self.db.execute(query)
        items = result.scalars().all()

        return list(items), total

    async def create_message(
        self,
        message_data: MessageCreate,
        role: str = MessageRole.USER,
        tokens: Optional[int] = None,
        model_name: Optional[str] = None,
        metadata: Optional[dict] = None
    ) -> Message:
        """Create a new message."""
        msg = Message(
            conversation_id=message_data.conversation_id,
            role=role,
            content=message_data.content,
            tokens=tokens,
            model_name=model_name,
            metadata_json=metadata or {}
        )
        self.db.add(msg)
        await self.db.commit()
        await self.db.refresh(msg)

        # Update conversation's updated_at
        conv_query = select(Conversation).where(
            Conversation.id == message_data.conversation_id
        )
        conv_result = await self.db.execute(conv_query)
        conv = conv_result.scalar_one_or_none()
        if conv:
            from datetime import datetime
            conv.updated_at = datetime.utcnow()

        await self.db.commit()
        return msg

    async def get_message_by_id(
        self,
        msg_id: int,
        user_id: int
    ) -> Optional[Message]:
        """Get message by ID with user ownership verification."""
        query = (
            select(Message)
            .join(Conversation)
            .where(
                Message.id == msg_id,
                Conversation.user_id == user_id
            )
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_conversation_message_count(
        self,
        conversation_id: int
    ) -> int:
        """Get the total number of messages in a conversation."""
        query = select(func.count()).select_from(Message).where(
            Message.conversation_id == conversation_id
        )
        return await self.db.scalar(query) or 0

    # Prompt Template operations
    async def get_prompt_templates(
        self,
        user_id: int,
        category: Optional[str] = None,
        is_public: Optional[bool] = None
    ) -> List[PromptTemplate]:
        """Get prompt templates (user's and public)."""
        query = select(PromptTemplate).where(
            or_(
                PromptTemplate.user_id == user_id,
                PromptTemplate.is_public == True,
                PromptTemplate.is_system == True
            )
        )

        if category:
            query = query.where(PromptTemplate.category == category)
        if is_public is not None:
            query = query.where(PromptTemplate.is_public == is_public)

        query = query.order_by(PromptTemplate.usage_count.desc())

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_prompt_template_by_id(
        self,
        template_id: int
    ) -> Optional[PromptTemplate]:
        """Get prompt template by ID."""
        query = select(PromptTemplate).where(PromptTemplate.id == template_id)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def create_prompt_template(
        self,
        user_id: int,
        name: str,
        template: str,
        description: Optional[str] = None,
        category: Optional[str] = None,
        variables: Optional[List[str]] = None,
        is_public: bool = False
    ) -> PromptTemplate:
        """Create a new prompt template."""
        prompt_template = PromptTemplate(
            user_id=user_id,
            name=name,
            description=description,
            category=category,
            template=template,
            variables=variables or [],
            is_public=is_public,
            is_system=False
        )
        self.db.add(prompt_template)
        await self.db.commit()
        await self.db.refresh(prompt_template)
        return prompt_template

    async def update_prompt_template(
        self,
        template_id: int,
        user_id: int,
        **kwargs
    ) -> Optional[PromptTemplate]:
        """Update prompt template."""
        template = await self.get_prompt_template_by_id(template_id)
        if not template:
            return None

        # Only allow user to update their own templates
        if template.user_id != user_id and not template.is_system:
            return None

        for key, value in kwargs.items():
            if hasattr(template, key) and value is not None:
                setattr(template, key, value)

        await self.db.commit()
        await self.db.refresh(template)
        return template

    async def delete_prompt_template(
        self,
        template_id: int,
        user_id: int
    ) -> bool:
        """Delete prompt template."""
        template = await self.get_prompt_template_by_id(template_id)
        if not template:
            return False

        # Only allow user to delete their own templates
        if template.user_id != user_id:
            return False

        await self.db.delete(template)
        await self.db.commit()
        return True

    async def increment_template_usage(
        self,
        template_id: int
    ) -> None:
        """Increment the usage count of a template."""
        query = (
            update(PromptTemplate)
            .where(PromptTemplate.id == template_id)
            .values(usage_count=PromptTemplate.usage_count + 1)
        )
        await self.db.execute(query)
        await self.db.commit()

    # Task operations
    async def get_user_tasks(
        self,
        user_id: int,
        status: Optional[str] = None,
        page: int = 1,
        size: int = 20
    ) -> Tuple[List[AssistantTask], int]:
        """Get user's assistant tasks."""
        skip = (page - 1) * size

        base_query = select(AssistantTask).where(AssistantTask.user_id == user_id)
        if status:
            base_query = base_query.where(AssistantTask.status == status)

        count_query = select(func.count()).select_from(base_query.subquery())
        total = await self.db.scalar(count_query) or 0

        query = (
            base_query
            .offset(skip)
            .limit(size)
            .order_by(AssistantTask.created_at.desc())
        )
        result = await self.db.execute(query)
        items = result.scalars().all()

        return list(items), total

    async def create_task(
        self,
        user_id: int,
        title: str,
        task_type: str,
        description: Optional[str] = None,
        conversation_id: Optional[int] = None,
        priority: str = "medium",
        due_date: Optional["datetime"] = None,
        metadata: Optional[dict] = None
    ) -> AssistantTask:
        """Create a new assistant task."""
        task = AssistantTask(
            user_id=user_id,
            conversation_id=conversation_id,
            title=title,
            description=description,
            task_type=task_type,
            priority=priority,
            due_date=due_date,
            metadata_json=metadata or {}
        )
        self.db.add(task)
        await self.db.commit()
        await self.db.refresh(task)
        return task

    async def update_task_status(
        self,
        task_id: int,
        user_id: int,
        status: str,
        result: Optional[str] = None
    ) -> Optional[AssistantTask]:
        """Update task status."""
        query = select(AssistantTask).where(
            AssistantTask.id == task_id,
            AssistantTask.user_id == user_id
        )
        result_obj = await self.db.execute(query)
        task = result_obj.scalar_one_or_none()

        if not task:
            return None

        task.status = status
        if result:
            task.result = result

        if status == "completed":
            from datetime import datetime
            task.completed_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(task)
        return task

    # Tool Call operations
    async def create_tool_call(
        self,
        message_id: int,
        tool_name: str,
        arguments: dict
    ) -> ToolCall:
        """Create a new tool call record."""
        tool_call = ToolCall(
            message_id=message_id,
            tool_name=tool_name,
            arguments=arguments,
            status="pending"
        )
        self.db.add(tool_call)
        await self.db.commit()
        await self.db.refresh(tool_call)
        return tool_call

    async def update_tool_call_result(
        self,
        tool_call_id: int,
        result: Optional[dict] = None,
        status: str = "completed",
        error_message: Optional[str] = None,
        execution_time: Optional[int] = None
    ) -> Optional[ToolCall]:
        """Update tool call with result."""
        query = select(ToolCall).where(ToolCall.id == tool_call_id)
        query_result = await self.db.execute(query)
        tool_call = query_result.scalar_one_or_none()

        if not tool_call:
            return None

        tool_call.status = status
        tool_call.result = result
        tool_call.error_message = error_message
        tool_call.execution_time = execution_time

        if status in ["completed", "failed"]:
            from datetime import datetime
            tool_call.completed_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(tool_call)
        return tool_call

    async def get_message_tool_calls(
        self,
        message_id: int
    ) -> List[ToolCall]:
        """Get all tool calls for a message."""
        query = select(ToolCall).where(
            ToolCall.message_id == message_id
        ).order_by(ToolCall.created_at.asc())

        result = await self.db.execute(query)
        return list(result.scalars().all())
