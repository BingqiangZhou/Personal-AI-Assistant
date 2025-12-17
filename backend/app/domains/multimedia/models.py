"""Multimedia domain models."""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime,
    ForeignKey, Boolean, JSON, Index, Float, Enum
)
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

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
    metadata = Column(JSON, nullable=True, default={})
    processed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="media_files")
    processing_jobs = relationship("ProcessingJob", back_populates="media_file", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_user_type', 'user_id', 'media_type'),
        Index('idx_checksum', 'checksum'),
    )


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

    # Indexes
    __table_args__ = (
        Index('idx_user_status', 'user_id', 'status'),
        Index('idx_media_type', 'media_file_id', 'job_type'),
    )


class TranscriptionResult(Base):
    """Transcription results for audio/video."""

    __tablename__ = "transcription_results"

    id = Column(Integer, primary_key=True, index=True)
    processing_job_id = Column(Integer, ForeignKey("processing_jobs.id"), nullable=False)
    text = Column(Text, nullable=False)
    confidence = Column(Float, nullable=True)
    language = Column(String(10), nullable=True)
    segments = Column(JSON, nullable=True)  # Array of time-coded segments
    summary = Column(Text, nullable=True)
    keywords = Column(JSON, nullable=True, default=[])
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    processing_job = relationship("ProcessingJob")


class ImageAnalysis(Base):
    """Analysis results for images."""

    __tablename__ = "image_analyses"

    id = Column(Integer, primary_key=True, index=True)
    processing_job_id = Column(Integer, ForeignKey("processing_jobs.id"), nullable=False)
    description = Column(Text, nullable=True)
    objects = Column(JSON, nullable=True, default=[])
    faces = Column(JSON, nullable=True, default=[])
    text_detected = Column(JSON, nullable=True, default=[])
    emotions = Column(JSON, nullable=True, default=[])
    tags = Column(JSON, nullable=True, default=[])
    confidence = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    processing_job = relationship("ProcessingJob")


class VideoAnalysis(Base):
    """Analysis results for videos."""

    __tablename__ = "video_analyses"

    id = Column(Integer, primary_key=True, index=True)
    processing_job_id = Column(Integer, ForeignKey("processing_jobs.id"), nullable=False)
    duration = Column(Float, nullable=False)
    thumbnail_path = Column(String(500), nullable=True)
    key_frames = Column(JSON, nullable=True, default=[])  # Array of timestamps and paths
    scenes = Column(JSON, nullable=True, default=[])  # Scene detection results
    objects = Column(JSON, nullable=True, default=[])
    text_detected = Column(JSON, nullable=True, default=[])
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    processing_job = relationship("ProcessingJob")