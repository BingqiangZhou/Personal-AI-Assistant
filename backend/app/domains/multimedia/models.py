"""Multimedia domain models."""

import enum
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.core.database import Base


class MediaType(str, enum.Enum):
    """Media file types."""
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    DOCUMENT = "document"


class ProcessingStatus(str, enum.Enum):
    """Processing job status."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class MediaFile(Base):
    """Media file model."""

    __tablename__ = "media_files"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    original_filename = Column(String(500), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer, nullable=False)
    mime_type = Column(String(100), nullable=False)
    media_type = Column(String(20), nullable=False)
    duration = Column(Float, nullable=True)  # For audio/video in seconds
    width = Column(Integer, nullable=True)   # For image/video
    height = Column(Integer, nullable=True)  # For image/video
    checksum = Column(String(64), nullable=True)  # SHA-256
    media_metadata = Column(JSON, nullable=True, default={})
    processed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="media_files")
    processing_jobs = relationship("ProcessingJob", back_populates="media_file", cascade="all, delete-orphan")

    # Indexes are created automatically by SQLAlchemy


class ProcessingJob(Base):
    """Processing job for media files."""

    __tablename__ = "processing_jobs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    media_file_id = Column(Integer, ForeignKey("media_files.id"), nullable=False)
    job_type = Column(String(50), nullable=False)  # transcribe, analyze, convert, extract
    status = Column(String(20), default=ProcessingStatus.PENDING)
    progress = Column(Integer, default=0)  # 0-100
    result = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    config = Column(JSON, nullable=True, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="processing_jobs")
    media_file = relationship("MediaFile", back_populates="processing_jobs")

    # Indexes are created automatically by SQLAlchemy

