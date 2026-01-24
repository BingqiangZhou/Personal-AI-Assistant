"""Multimedia domain services."""

import logging
import os
import aiofiles
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import UploadFile

from app.domains.multimedia.repositories import MultimediaRepository
from app.domains.multimedia.models import MediaFile, ProcessingJob, MediaType, ProcessingStatus
from app.shared.schemas import PaginatedResponse
from app.core.file_validation import (
    validate_file_upload,
    get_allowed_types_for_media,
    FileValidationError
)
from app.core.config import settings

logger = logging.getLogger(__name__)


class MultimediaService:
    """Service for orchestrating multimedia logic."""

    def __init__(self, db: AsyncSession, user_id: int):
        self.db = db
        self.user_id = user_id
        self.repo = MultimediaRepository(db)

    # Media File operations
    async def list_media_files(
        self,
        page: int = 1,
        size: int = 20,
        media_type: Optional[str] = None
    ) -> PaginatedResponse:
        """List user's media files."""
        items, total = await self.repo.get_user_media_files(
            self.user_id, page, size, media_type
        )

        response_items = [
            {
                "id": mf.id,
                "user_id": mf.user_id,
                "original_filename": mf.original_filename,
                "file_path": mf.file_path,
                "file_size": mf.file_size,
                "mime_type": mf.mime_type,
                "media_type": mf.media_type,
                "duration": mf.duration,
                "width": mf.width,
                "height": mf.height,
                "checksum": mf.checksum,
                "metadata": mf.media_metadata,
                "processed": mf.processed,
                "created_at": mf.created_at.isoformat(),
                "updated_at": mf.updated_at.isoformat()
            }
            for mf in items
        ]

        return PaginatedResponse.create(
            items=response_items,
            total=total,
            page=page,
            size=size
        )

    async def upload_media_file(
        self,
        file: UploadFile,
        description: Optional[str] = None
    ) -> Dict[str, Any]:
        """Upload a media file with comprehensive security validation."""
        # Determine expected media type from file extension/MIME
        declared_mime = file.content_type or "application/octet-stream"
        temp_media_type = self.repo.determine_media_type(declared_mime)

        # Get allowed MIME types for this media category
        allowed_types = get_allowed_types_for_media(temp_media_type.value)

        # If no specific types found, allow common types for that category
        if not allowed_types:
            if temp_media_type == MediaType.IMAGE:
                allowed_types = {"image/jpeg", "image/png", "image/gif", "image/webp"}
            elif temp_media_type == MediaType.AUDIO:
                allowed_types = {"audio/mpeg", "audio/wav", "audio/ogg", "audio/m4a"}
            elif temp_media_type == MediaType.VIDEO:
                allowed_types = {"video/mp4", "video/webm", "video/ogg"}

        # Validate file upload (size, extension, MIME type)
        try:
            sanitized_filename, validated_mime = await validate_file_upload(
                file=file,
                allowed_types=allowed_types,
                max_size=settings.MAX_FILE_SIZE,
                strict_mime_check=True
            )
        except FileValidationError as e:
            logger.warning(f"File validation failed: {e.message_en}")
            raise

        # Re-determine media type based on validated MIME
        media_type = self.repo.determine_media_type(validated_mime)

        # Generate safe file path
        timestamp = datetime.utcnow().timestamp()
        safe_filename = f"{int(timestamp)}_{sanitized_filename}"
        upload_path = self.repo.get_upload_path(self.user_id, media_type.value, safe_filename)

        # Ensure directory exists
        os.makedirs(os.path.dirname(upload_path), exist_ok=True)

        # Save file and calculate checksum
        import hashlib
        sha256_hash = hashlib.sha256()
        file_size = 0

        async with aiofiles.open(upload_path, 'wb') as out_file:
            while content := await file.read(1024 * 1024):  # 1MB chunks
                file_size += len(content)
                sha256_hash.update(content)
                await out_file.write(content)

        checksum = sha256_hash.hexdigest()

        # Check for duplicate files
        existing = await self.repo.get_media_file_by_checksum(self.user_id, checksum)
        if existing:
            # Delete the uploaded file since it's a duplicate
            os.remove(upload_path)
            return {
                "id": existing.id,
                "original_filename": existing.original_filename,
                "file_path": existing.file_path,
                "message": "File already exists (deduplicated)",
                "message_zh": "文件已存在（已去重）",
                "duplicate": True
            }

        # Create media file record
        media_file = await self.repo.create_media_file(
            user_id=self.user_id,
            original_filename=sanitized_filename,
            file_path=upload_path,
            file_size=file_size,
            mime_type=validated_mime,
            media_type=media_type.value,
            checksum=checksum,
            metadata={"description": description} if description else {}
        )

        return {
            "id": media_file.id,
            "original_filename": media_file.original_filename,
            "file_path": media_file.file_path,
            "file_size": media_file.file_size,
            "mime_type": media_file.mime_type,
            "media_type": media_file.media_type,
            "checksum": media_file.checksum,
            "created_at": media_file.created_at.isoformat(),
            "duplicate": False
        }

    async def get_media_file(
        self,
        file_id: int
    ) -> Optional[Dict[str, Any]]:
        """Get media file details."""
        media_file = await self.repo.get_media_file_by_id(self.user_id, file_id)
        if not media_file:
            return None

        return {
            "id": media_file.id,
            "user_id": media_file.user_id,
            "original_filename": media_file.original_filename,
            "file_path": media_file.file_path,
            "file_size": media_file.file_size,
            "mime_type": media_file.mime_type,
            "media_type": media_file.media_type,
            "duration": media_file.duration,
            "width": media_file.width,
            "height": media_file.height,
            "checksum": media_file.checksum,
            "metadata": media_file.media_metadata,
            "processed": media_file.processed,
            "created_at": media_file.created_at.isoformat(),
            "updated_at": media_file.updated_at.isoformat()
        }

    async def delete_media_file(
        self,
        file_id: int,
        delete_physical_file: bool = True
    ) -> bool:
        """Delete a media file."""
        return await self.repo.delete_media_file(
            self.user_id, file_id, delete_physical_file
        )

    # Processing Job operations
    async def list_processing_jobs(
        self,
        page: int = 1,
        size: int = 20,
        status: Optional[str] = None,
        media_file_id: Optional[int] = None
    ) -> PaginatedResponse:
        """List processing jobs."""
        items, total = await self.repo.get_processing_jobs(
            self.user_id, page, size, status, media_file_id
        )

        response_items = [
            {
                "id": job.id,
                "user_id": job.user_id,
                "media_file_id": job.media_file_id,
                "job_type": job.job_type,
                "status": job.status,
                "progress": job.progress,
                "result": job.result,
                "error_message": job.error_message,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
                "created_at": job.created_at.isoformat()
            }
            for job in items
        ]

        return PaginatedResponse.create(
            items=response_items,
            total=total,
            page=page,
            size=size
        )

    async def get_processing_job(
        self,
        job_id: int
    ) -> Optional[Dict[str, Any]]:
        """Get processing job details."""
        job = await self.repo.get_processing_job_by_id(job_id, self.user_id)
        if not job:
            return None

        response = {
            "id": job.id,
            "user_id": job.user_id,
            "media_file_id": job.media_file_id,
            "job_type": job.job_type,
            "status": job.status,
            "progress": job.progress,
            "result": job.result,
            "error_message": job.error_message,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "created_at": job.created_at.isoformat()
        }

        # Include specific results based on job type
        if job.job_type == "transcribe":
            transcription = await self.repo.get_transcription_result(job.id)
            if transcription:
                response["transcription"] = {
                    "text": transcription.text,
                    "confidence": transcription.confidence,
                    "language": transcription.language,
                    "segments": transcription.segments,
                    "summary": transcription.summary,
                    "keywords": transcription.keywords
                }
        elif job.job_type == "analyze":
            analysis = await self.repo.get_image_analysis(job.id)
            if analysis:
                response["analysis"] = {
                    "description": analysis.description,
                    "objects": analysis.objects,
                    "faces": analysis.faces,
                    "text_detected": analysis.text_detected,
                    "emotions": analysis.emotions,
                    "tags": analysis.tags,
                    "confidence": analysis.confidence
                }

        return response

    async def cancel_processing_job(
        self,
        job_id: int
    ) -> Optional[Dict[str, Any]]:
        """Cancel a processing job."""
        job = await self.repo.cancel_job(job_id, self.user_id)
        if not job:
            return None

        return {
            "id": job.id,
            "status": job.status,
            "message": "Job cancelled"
        }

    async def delete_processing_job(
        self,
        job_id: int
    ) -> bool:
        """Delete a processing job."""
        return await self.repo.delete_job(job_id, self.user_id)

    # Transcription operations (skeleton - actual transcription would use external services)
    async def create_transcription_job(
        self,
        file_id: int,
        language: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a transcription job for audio/video."""
        # Verify media file exists and belongs to user
        media_file = await self.repo.get_media_file_by_id(self.user_id, file_id)
        if not media_file:
            raise ValueError("Media file not found")

        if media_file.media_type not in [MediaType.AUDIO, MediaType.VIDEO]:
            raise ValueError("Media file must be audio or video")

        # Create processing job
        config = {"language": language} if language else {}
        job = await self.repo.create_processing_job(
            self.user_id, file_id, "transcribe", config
        )

        # TODO: Queue actual transcription task
        # For now, mark as pending
        logger.info(f"Created transcription job {job.id} for media file {file_id}")

        return {
            "id": job.id,
            "media_file_id": job.media_file_id,
            "job_type": job.job_type,
            "status": job.status,
            "message": "Transcription job created. Processing will begin shortly."
        }

    # Image analysis operations (skeleton - actual analysis would use AI services)
    async def create_image_analysis_job(
        self,
        file_id: int,
        analysis_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create an image analysis job."""
        # Verify media file exists
        media_file = await self.repo.get_media_file_by_id(self.user_id, file_id)
        if not media_file:
            raise ValueError("Media file not found")

        if media_file.media_type != MediaType.IMAGE:
            raise ValueError("Media file must be an image")

        # Create processing job
        config = {"analysis_type": analysis_type} if analysis_type else {}
        job = await self.repo.create_processing_job(
            self.user_id, file_id, "analyze", config
        )

        # TODO: Queue actual analysis task
        logger.info(f"Created image analysis job {job.id} for media file {file_id}")

        return {
            "id": job.id,
            "media_file_id": job.media_file_id,
            "job_type": job.job_type,
            "status": job.status,
            "message": "Analysis job created. Processing will begin shortly."
        }

    # Video processing operations (skeleton)
    async def create_video_processing_job(
        self,
        file_id: int,
        extract_keyframes: bool = False,
        extract_audio: bool = False
    ) -> Dict[str, Any]:
        """Create a video processing job."""
        # Verify media file exists
        media_file = await self.repo.get_media_file_by_id(self.user_id, file_id)
        if not media_file:
            raise ValueError("Media file not found")

        if media_file.media_type != MediaType.VIDEO:
            raise ValueError("Media file must be a video")

        # Create processing job
        config = {
            "extract_keyframes": extract_keyframes,
            "extract_audio": extract_audio
        }
        job = await self.repo.create_processing_job(
            self.user_id, file_id, "process_video", config
        )

        # TODO: Queue actual video processing task
        logger.info(f"Created video processing job {job.id} for media file {file_id}")

        return {
            "id": job.id,
            "media_file_id": job.media_file_id,
            "job_type": job.job_type,
            "status": job.status,
            "message": "Video processing job created. Processing will begin shortly."
        }

    # Helper methods for external services (Celery tasks would use these)
    async def update_job_progress(
        self,
        job_id: int,
        progress: int
    ) -> Optional[ProcessingJob]:
        """Update job progress (0-100)."""
        return await self.repo.update_job_status(
            job_id,
            ProcessingStatus.PROCESSING,
            progress=progress
        )

    async def complete_transcription_job(
        self,
        job_id: int,
        text: str,
        confidence: Optional[float] = None,
        language: Optional[str] = None,
        segments: Optional[list] = None,
        summary: Optional[str] = None,
        keywords: Optional[List[str]] = None
    ) -> ProcessingJob:
        """Complete a transcription job with results."""
        # Create transcription result
        await self.repo.create_transcription_result(
            job_id, text, confidence, language, segments, summary, keywords
        )

        # Update job status
        return await self.repo.update_job_status(
            job_id,
            ProcessingStatus.COMPLETED,
            progress=100,
            result={"text": text, "summary": summary, "keywords": keywords}
        )

    async def complete_image_analysis_job(
        self,
        job_id: int,
        description: Optional[str] = None,
        objects: Optional[list] = None,
        faces: Optional[list] = None,
        text_detected: Optional[list] = None,
        emotions: Optional[list] = None,
        tags: Optional[List[str]] = None,
        confidence: Optional[float] = None
    ) -> ProcessingJob:
        """Complete an image analysis job with results."""
        # Create analysis result
        await self.repo.create_image_analysis(
            job_id, description, objects, faces, text_detected, emotions, tags, confidence
        )

        # Update job status
        return await self.repo.update_job_status(
            job_id,
            ProcessingStatus.COMPLETED,
            progress=100,
            result={
                "description": description,
                "tags": tags,
                "objects": len(objects) if objects else 0
            }
        )

    async def fail_job(
        self,
        job_id: int,
        error_message: str
    ) -> Optional[ProcessingJob]:
        """Mark a job as failed."""
        return await self.repo.update_job_status(
            job_id,
            ProcessingStatus.FAILED,
            error_message=error_message
        )
