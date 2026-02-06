"""Multimedia domain repositories."""

import hashlib
import os
from datetime import datetime
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.multimedia.models import (
    MediaFile,
    MediaType,
    ProcessingJob,
    ProcessingStatus,
)


class MultimediaRepository:
    """Repository for managing multimedia data."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # Media File operations
    async def get_user_media_files(
        self,
        user_id: int,
        page: int = 1,
        size: int = 20,
        media_type: Optional[str] = None
    ) -> tuple[list[MediaFile], int]:
        """Get user's media files with pagination."""
        skip = (page - 1) * size

        # Build base query
        base_query = select(MediaFile).where(MediaFile.user_id == user_id)
        if media_type:
            base_query = base_query.where(MediaFile.media_type == media_type)

        # Get total count
        count_query = select(func.count()).select_from(base_query.subquery())
        total = await self.db.scalar(count_query) or 0

        # Get items
        query = (
            base_query
            .offset(skip)
            .limit(size)
            .order_by(MediaFile.created_at.desc())
        )
        result = await self.db.execute(query)
        items = result.scalars().all()

        return list(items), total

    async def get_media_file_by_id(
        self,
        user_id: int,
        file_id: int
    ) -> Optional[MediaFile]:
        """Get media file by ID with user ownership verification."""
        query = select(MediaFile).where(
            MediaFile.id == file_id,
            MediaFile.user_id == user_id
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def get_media_file_by_checksum(
        self,
        user_id: int,
        checksum: str
    ) -> Optional[MediaFile]:
        """Get media file by checksum (for deduplication)."""
        query = select(MediaFile).where(
            MediaFile.user_id == user_id,
            MediaFile.checksum == checksum
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def create_media_file(
        self,
        user_id: int,
        original_filename: str,
        file_path: str,
        file_size: int,
        mime_type: str,
        media_type: str,
        checksum: str,
        duration: Optional[float] = None,
        width: Optional[int] = None,
        height: Optional[int] = None,
        metadata: Optional[dict] = None
    ) -> MediaFile:
        """Create a new media file record."""
        media_file = MediaFile(
            user_id=user_id,
            original_filename=original_filename,
            file_path=file_path,
            file_size=file_size,
            mime_type=mime_type,
            media_type=media_type,
            checksum=checksum,
            duration=duration,
            width=width,
            height=height,
            media_metadata=metadata or {},
            processed=False
        )
        self.db.add(media_file)
        await self.db.commit()
        await self.db.refresh(media_file)
        return media_file

    async def update_media_file(
        self,
        file_id: int,
        user_id: int,
        **kwargs
    ) -> Optional[MediaFile]:
        """Update media file."""
        media_file = await self.get_media_file_by_id(user_id, file_id)
        if not media_file:
            return None

        for key, value in kwargs.items():
            if hasattr(media_file, key) and value is not None:
                setattr(media_file, key, value)

        await self.db.commit()
        await self.db.refresh(media_file)
        return media_file

    async def mark_as_processed(
        self,
        file_id: int,
        user_id: int
    ) -> Optional[MediaFile]:
        """Mark media file as processed."""
        return await self.update_media_file(file_id, user_id, processed=True)

    async def delete_media_file(
        self,
        user_id: int,
        file_id: int,
        delete_physical_file: bool = False
    ) -> bool:
        """Delete media file."""
        media_file = await self.get_media_file_by_id(user_id, file_id)
        if not media_file:
            return False

        # Delete physical file if requested
        if delete_physical_file and media_file.file_path:
            try:
                if os.path.exists(media_file.file_path):
                    os.remove(media_file.file_path)
            except Exception:
                # Log error but continue with database deletion
                pass

        await self.db.delete(media_file)
        await self.db.commit()
        return True

    # Processing Job operations
    async def get_processing_jobs(
        self,
        user_id: int,
        page: int = 1,
        size: int = 20,
        status: Optional[str] = None,
        media_file_id: Optional[int] = None
    ) -> tuple[list[ProcessingJob], int]:
        """Get user's processing jobs."""
        skip = (page - 1) * size

        # Build base query
        base_query = select(ProcessingJob).where(ProcessingJob.user_id == user_id)
        if status:
            base_query = base_query.where(ProcessingJob.status == status)
        if media_file_id:
            base_query = base_query.where(ProcessingJob.media_file_id == media_file_id)

        # Get total count
        count_query = select(func.count()).select_from(base_query.subquery())
        total = await self.db.scalar(count_query) or 0

        # Get items
        query = (
            base_query
            .offset(skip)
            .limit(size)
            .order_by(ProcessingJob.created_at.desc())
        )
        result = await self.db.execute(query)
        items = result.scalars().all()

        return list(items), total

    async def get_processing_job_by_id(
        self,
        job_id: int,
        user_id: int
    ) -> Optional[ProcessingJob]:
        """Get processing job by ID."""
        query = select(ProcessingJob).where(
            ProcessingJob.id == job_id,
            ProcessingJob.user_id == user_id
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def create_processing_job(
        self,
        user_id: int,
        media_file_id: int,
        job_type: str,
        config: Optional[dict] = None
    ) -> ProcessingJob:
        """Create a new processing job."""
        job = ProcessingJob(
            user_id=user_id,
            media_file_id=media_file_id,
            job_type=job_type,
            status=ProcessingStatus.PENDING,
            progress=0,
            config=config or {}
        )
        self.db.add(job)
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def update_job_status(
        self,
        job_id: int,
        status: str,
        progress: Optional[int] = None,
        result: Optional[dict] = None,
        error_message: Optional[str] = None
    ) -> Optional[ProcessingJob]:
        """Update processing job status."""
        query = select(ProcessingJob).where(ProcessingJob.id == job_id)
        query_result = await self.db.execute(query)
        job = query_result.scalar_one_or_none()

        if not job:
            return None

        job.status = status
        if progress is not None:
            job.progress = progress
        if result is not None:
            job.result = result
        if error_message is not None:
            job.error_message = error_message

        if status == ProcessingStatus.PROCESSING and not job.started_at:
            job.started_at = datetime.utcnow()
        elif status in [ProcessingStatus.COMPLETED, ProcessingStatus.FAILED, ProcessingStatus.CANCELLED]:
            job.completed_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def cancel_job(
        self,
        job_id: int,
        user_id: int
    ) -> Optional[ProcessingJob]:
        """Cancel a processing job."""
        return await self.update_job_status(job_id, ProcessingStatus.CANCELLED)

    async def delete_job(
        self,
        job_id: int,
        user_id: int
    ) -> bool:
        """Delete a processing job."""
        job = await self.get_processing_job_by_id(job_id, user_id)
        if not job:
            return False

        await self.db.delete(job)
        await self.db.commit()
        return True

    # Utility methods
    @staticmethod
    def calculate_checksum(file_path: str) -> str:
        """Calculate SHA-256 checksum of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    @staticmethod
    def determine_media_type(mime_type: str) -> str:
        """Determine media type from MIME type."""
        if mime_type.startswith("image/"):
            return MediaType.IMAGE
        elif mime_type.startswith("audio/"):
            return MediaType.AUDIO
        elif mime_type.startswith("video/"):
            return MediaType.VIDEO
        else:
            return MediaType.DOCUMENT

    @staticmethod
    def get_upload_path(user_id: int, media_type: str, filename: str) -> str:
        """Generate upload path for media file."""
        # Create path like: uploads/media/{user_id}/{media_type}/{filename}
        return os.path.join(
            "uploads", "media", str(user_id), media_type, filename
        )
