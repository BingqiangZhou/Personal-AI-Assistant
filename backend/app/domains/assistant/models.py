"""AI Assistant domain models."""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime,
    ForeignKey, Boolean, JSON, Index, Enum
)
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.core.database import Base


class MessageRole(str, enum.Enum):
    """Message roles in conversations."""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ConversationStatus(str, enum.Enum):
    """Conversation status."""
    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETED = "deleted"


class Conversation(Base):
    """Conversation model for AI assistant."""

    __tablename__ = "conversations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(20), default=ConversationStatus.ACTIVE)
    model_name = Column(String(100), nullable=True, default="gpt-3.5-turbo")
    system_prompt = Column(Text, nullable=True)
    temperature = Column(Integer, default=70)  # 0-100
    max_tokens = Column(Integer, nullable=True)
    knowledge_base_ids = Column(JSON, nullable=True, default=[])  # Linked KBs
    settings = Column(JSON, nullable=True, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="conversations")
    messages = relationship("Message", back_populates="conversation", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_user_status', 'user_id', 'status'),
    )


class Message(Base):
    """Message model in conversations."""

    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id"), nullable=False)
    role = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    tokens = Column(Integer, nullable=True)
    model_name = Column(String(100), nullable=True)
    metadata_json = Column("metadata", JSON, nullable=True, default={})  # Avoid reserved name
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    conversation = relationship("Conversation", back_populates="messages")

    # Indexes
    __table_args__ = (
        Index('idx_conversation_created', 'conversation_id', 'created_at'),
    )


class PromptTemplate(Base):
    """Prompt templates for common tasks."""

    __tablename__ = "prompt_templates"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Null for system templates
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=True)
    template = Column(Text, nullable=False)
    variables = Column(JSON, nullable=True, default=[])  # List of variable names
    is_public = Column(Boolean, default=False)
    is_system = Column(Boolean, default=False)
    usage_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="prompt_templates")


class AssistantTask(Base):
    """Tasks created and managed by the assistant."""

    __tablename__ = "assistant_tasks"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    conversation_id = Column(Integer, ForeignKey("conversations.id"), nullable=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    task_type = Column(String(50), nullable=False)  # reminder, research, summary, etc.
    status = Column(String(20), default="pending")  # pending, in_progress, completed, cancelled
    priority = Column(String(20), default="medium")  # low, medium, high
    due_date = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    result = Column(Text, nullable=True)
    metadata_json = Column("metadata", JSON, nullable=True, default={})  # Avoid reserved name
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="assistant_tasks")
    conversation = relationship("Conversation")


class ToolCall(Base):
    """Tool calls made by the assistant."""

    __tablename__ = "tool_calls"

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey("messages.id"), nullable=False)
    tool_name = Column(String(100), nullable=False)
    arguments = Column(JSON, nullable=False)
    result = Column(JSON, nullable=True)
    status = Column(String(20), default="pending")  # pending, completed, failed
    error_message = Column(Text, nullable=True)
    execution_time = Column(Integer, nullable=True)  # milliseconds
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    message = relationship("Message")

    # Indexes
    __table_args__ = (
        Index('idx_message_status', 'message_id', 'status'),
    )