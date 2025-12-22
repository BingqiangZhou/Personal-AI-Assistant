"""Multimedia API routes."""

from typing import List, Optional
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.core.database import get_db_session
from app.core.dependencies import get_current_active_user
from app.domains.user.models import User
from app.domains.multimedia.services import MultimediaService
from app.shared.schemas import PaginatedResponse, PaginationParams

router = APIRouter()


# Request/Response models
class MediaFileResponse(BaseModel):
    """Response model for media file."""
    id: int
    user_id: int
    original_filename: str
    file_path: str
    file_size: int
    mime_type: str
    media_type: str
    duration: Optional[float] = None
    width: Optional[int] = None
    height: Optional[int] = None
    checksum: Optional[str] = None
    metadata: dict
    processed: bool
    created_at: str
    updated_at: str


class UploadResponse(BaseModel):
    """Response model for file upload."""
    id: int
    original_filename: str
    file_path: str
    file_size: int
    mime_type: str
    media_type: str
    checksum: str
    created_at: str
    duplicate: bool


class ProcessingJobResponse(BaseModel):
    """Response model for processing job."""
    id: int
    user_id: int
    media_file_id: int
    job_type: str
    status: str
    progress: int
    result: Optional[dict] = None
    error_message: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    created_at: str


class JobCreateResponse(BaseModel):
    """Response model for job creation."""
    id: int
    media_file_id: int
    job_type: str
    status: str
    message: str


# Media file endpoints
@router.get("/files/", response_model=PaginatedResponse)
async def list_media_files(
    pagination: PaginationParams = Depends(),
    media_type: Optional[str] = Query(None, description="Filter by media type"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """List user's media files."""
    service = MultimediaService(db, current_user.id)
    return await service.list_media_files(
        page=pagination.page,
        size=pagination.size,
        media_type=media_type
    )


@router.post("/files/upload", response_model=UploadResponse)
async def upload_media_file(
    file: UploadFile = File(...),
    description: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Upload a media file.

    Supported file types:
    - Images: jpg, jpeg, png, gif, webp
    - Audio: mp3, wav, m4a, aac
    - Video: mp4, mov, avi, mkv
    - Documents: pdf, doc, docx (metadata only)
    """
    service = MultimediaService(db, current_user.id)
    try:
        result = await service.upload_media_file(file, description)
        return UploadResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@router.get("/files/{file_id}", response_model=MediaFileResponse)
async def get_media_file(
    file_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Get media file metadata."""
    service = MultimediaService(db, current_user.id)
    result = await service.get_media_file(file_id)
    if not result:
        raise HTTPException(status_code=404, detail="Media file not found")
    return MediaFileResponse(**result)


@router.delete("/files/{file_id}")
async def delete_media_file(
    file_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Delete a media file."""
    service = MultimediaService(db, current_user.id)
    success = await service.delete_media_file(file_id)
    if not success:
        raise HTTPException(status_code=404, detail="Media file not found")
    return {"message": "Media file deleted"}


# Processing job endpoints
@router.post("/files/{file_id}/transcribe", response_model=JobCreateResponse)
async def transcribe_audio(
    file_id: int,
    language: Optional[str] = Query(None, description="Language code for transcription"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Transcribe audio/video file.

    Creates a background job to transcribe the audio content.
    The job will process the file and extract text with timestamps.
    """
    service = MultimediaService(db, current_user.id)
    try:
        result = await service.create_transcription_job(file_id, language)
        return JobCreateResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/files/{file_id}/analyze", response_model=JobCreateResponse)
async def analyze_image(
    file_id: int,
    analysis_type: Optional[str] = Query(None, description="Type of analysis (objects, faces, text, emotions)"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Analyze image content.

    Creates a background job to analyze the image using AI.
    Can detect objects, faces, text, emotions, and generate descriptions.
    """
    service = MultimediaService(db, current_user.id)
    try:
        result = await service.create_image_analysis_job(file_id, analysis_type)
        return JobCreateResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/files/{file_id}/process", response_model=JobCreateResponse)
async def process_video(
    file_id: int,
    extract_keyframes: bool = Query(False, description="Extract key frames from video"),
    extract_audio: bool = Query(False, description="Extract audio track from video"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Process video file.

    Creates a background job for video processing operations
    like extracting key frames or audio tracks.
    """
    service = MultimediaService(db, current_user.id)
    try:
        result = await service.create_video_processing_job(
            file_id, extract_keyframes, extract_audio
        )
        return JobCreateResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/jobs/{job_id}")
async def get_processing_job(
    job_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Get processing job status and results."""
    service = MultimediaService(db, current_user.id)
    result = await service.get_processing_job(job_id)
    if not result:
        raise HTTPException(status_code=404, detail="Processing job not found")
    return result


@router.get("/jobs/", response_model=PaginatedResponse)
async def list_processing_jobs(
    pagination: PaginationParams = Depends(),
    status: Optional[str] = Query(None, description="Filter by status"),
    media_file_id: Optional[int] = Query(None, description="Filter by media file"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """List processing jobs."""
    service = MultimediaService(db, current_user.id)
    return await service.list_processing_jobs(
        page=pagination.page,
        size=pagination.size,
        status=status,
        media_file_id=media_file_id
    )


@router.post("/jobs/{job_id}/cancel")
async def cancel_processing_job(
    job_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Cancel a processing job."""
    service = MultimediaService(db, current_user.id)
    result = await service.cancel_processing_job(job_id)
    if not result:
        raise HTTPException(status_code=404, detail="Processing job not found")
    return result


@router.delete("/jobs/{job_id}")
async def delete_processing_job(
    job_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Delete a processing job."""
    service = MultimediaService(db, current_user.id)
    success = await service.delete_processing_job(job_id)
    if not success:
        raise HTTPException(status_code=404, detail="Processing job not found")
    return {"message": "Processing job deleted"}
