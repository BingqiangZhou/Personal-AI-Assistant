"""Knowledge domain models."""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime,
    ForeignKey, Boolean, JSON, Index, Float
)
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.core.database import Base


class DocumentType(str, enum.Enum):
    """Document types."""
    TEXT = "text"
    MARKDOWN = "markdown"
    PDF = "pdf"
    WORD = "word"
    HTML = "html"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"


class KnowledgeBase(Base):
    """Knowledge base model."""

    __tablename__ = "knowledge_bases"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    is_public = Column(Boolean, default=False)
    is_default = Column(Boolean, default=False)
    settings = Column(JSON, nullable=True, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="knowledge_bases")
    documents = relationship("Document", back_populates="knowledge_base", cascade="all, delete-orphan")


class Document(Base):
    """Document model for knowledge base."""

    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    knowledge_base_id = Column(Integer, ForeignKey("knowledge_bases.id"), nullable=False)
    title = Column(String(500), nullable=False)
    content = Column(Text, nullable=True)
    content_type = Column(String(50), nullable=False)
    file_path = Column(String(500), nullable=True)
    file_size = Column(Integer, nullable=True)
    checksum = Column(String(64), nullable=True)  # SHA-256
    embeddings = Column(JSON, nullable=True)  # Vector embeddings
    doc_metadata = Column(JSON, nullable=True, default={})
    tags = Column(JSON, nullable=True, default=[])
    indexed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    knowledge_base = relationship("KnowledgeBase", back_populates="documents")
    chunks = relationship("DocumentChunk", back_populates="document", cascade="all, delete-orphan")

    # Indexes are created automatically by SQLAlchemy


class DocumentChunk(Base):
    """Document chunks for vector search."""

    __tablename__ = "document_chunks"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    chunk_index = Column(Integer, nullable=False)
    content = Column(Text, nullable=False)
    embedding = Column(JSON, nullable=True)  # Vector embedding
    doc_metadata = Column(JSON, nullable=True, default={})
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    document = relationship("Document", back_populates="chunks")

    # Indexes are created automatically by SQLAlchemy


class DocumentTag(Base):
    """Tags for organizing documents."""

    __tablename__ = "document_tags"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)
    color = Column(String(7), nullable=True)  # Hex color code
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships (read-only for now to avoid back_populates issues)
    user = relationship("User", back_populates="document_tags")
    # documents is accessed through DocumentTagMapping only


class DocumentTagMapping(Base):
    """Many-to-many mapping between documents and tags."""

    __tablename__ = "document_tag_mappings"

    document_id = Column(Integer, ForeignKey("documents.id"), primary_key=True)
    tag_id = Column(Integer, ForeignKey("document_tags.id"), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class SearchHistory(Base):
    """Search history for knowledge base."""

    __tablename__ = "search_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    knowledge_base_id = Column(Integer, ForeignKey("knowledge_bases.id"), nullable=True)
    query = Column(Text, nullable=False)
    filters = Column(JSON, nullable=True, default={})
    result_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="search_history")
    knowledge_base = relationship("KnowledgeBase")

    # Indexes are created automatically by SQLAlchemy