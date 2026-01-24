"""File validation utilities for secure file uploads.

This module provides functions to validate file uploads to prevent
security issues such as MIME type spoofing, malicious file uploads,
and excessive file sizes.
"""

import os
import mimetypes
from typing import Optional, Set, Tuple
from pathlib import Path
from fastapi import UploadFile
import logging

logger = logging.getLogger(__name__)


# Allowed MIME types by media category
ALLOWED_IMAGE_TYPES: Set[str] = {
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/svg+xml",
    "image/bmp",
    "image/tiff"
}

ALLOWED_AUDIO_TYPES: Set[str] = {
    "audio/mpeg",
    "audio/mp3",
    "audio/wav",
    "audio/ogg",
    "audio/flac",
    "audio/aac",
    "audio/m4a",
    "audio/webm",
    "audio/mp4"
}

ALLOWED_VIDEO_TYPES: Set[str] = {
    "video/mp4",
    "video/webm",
    "video/ogg",
    "video/quicktime",
    "video/x-msvideo",
    "video/mpeg"
}

ALLOWED_DOCUMENT_TYPES: Set[str] = {
    "application/pdf",
    "text/plain",
    "text/markdown",
    "application/json",
    "text/csv",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/xml",
    "application/xml"
}

# File extension to MIME type mapping (safe defaults)
SAFE_EXTENSIONS: dict[str, str] = {
    # Images
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".bmp": "image/bmp",
    ".tiff": "image/tiff",
    # Audio
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".flac": "audio/flac",
    ".aac": "audio/aac",
    ".m4a": "audio/m4a",
    # Video
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mov": "video/quicktime",
    ".avi": "video/x-msvideo",
    # Documents
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".json": "application/json",
    ".csv": "text/csv",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xml": "application/xml"
}


class FileValidationError(Exception):
    """Raised when file validation fails."""

    def __init__(self, message: str, message_zh: Optional[str] = None):
        self.message_en = message
        self.message_zh = message_zh or message
        super().__init__(message)


def validate_file_size(file: UploadFile, max_size: int) -> None:
    """Validate file size before reading content.

    Args:
        file: The uploaded file
        max_size: Maximum allowed file size in bytes

    Raises:
        FileValidationError: If file size exceeds limit
    """
    # Try to get file size from content-length header
    content_length = file.size
    if content_length is not None and content_length > max_size:
        max_mb = max_size / (1024 * 1024)
        raise FileValidationError(
            f"File size exceeds maximum allowed size of {max_mb:.1f}MB",
            f"文件大小超过最大允许大小 {max_mb:.1f}MB"
        )


def validate_file_extension(filename: str, allowed_extensions: Optional[Set[str]] = None) -> str:
    """Validate and extract file extension.

    Args:
        filename: The filename to validate
        allowed_extensions: Set of allowed extensions (e.g., {'.jpg', '.png'})

    Returns:
        The lowercase file extension with dot (e.g., '.jpg')

    Raises:
        FileValidationError: If extension is not allowed or missing
    """
    if not filename:
        raise FileValidationError(
            "Filename is required",
            "文件名是必需的"
        )

    ext = Path(filename).suffix.lower()

    if not ext:
        raise FileValidationError(
            "File must have an extension",
            "文件必须具有扩展名"
        )

    if allowed_extensions and ext not in allowed_extensions:
        allowed_list = ", ".join(allowed_extensions)
        raise FileValidationError(
            f"File extension '{ext}' is not allowed. Allowed extensions: {allowed_list}",
            f"文件扩展名 '{ext}' 不被允许。允许的扩展名: {allowed_list}"
        )

    return ext


def validate_mime_type(
    filename: str,
    declared_mime: str,
    allowed_types: Set[str],
    strict: bool = True
) -> str:
    """Validate MIME type against allowed types and file extension.

    This function performs multiple checks:
    1. Checks if declared MIME type is in allowed types
    2. Validates MIME type matches file extension
    3. Falls back to extension-based MIME type if strict=False

    Args:
        filename: The filename with extension
        declared_mime: The MIME type declared by the client
        allowed_types: Set of allowed MIME types
        strict: If True, reject on MIME type mismatch

    Returns:
        The validated MIME type

    Raises:
        FileValidationError: If MIME type validation fails
    """
    ext = Path(filename).suffix.lower()

    # Check if declared MIME is allowed
    if declared_mime not in allowed_types:
        # Try to get MIME from extension
        extension_mime = SAFE_EXTENSIONS.get(ext)

        if extension_mime and extension_mime in allowed_types:
            if strict:
                raise FileValidationError(
                    f"Declared MIME type '{declared_mime}' does not match file extension '{ext}'. Expected: {extension_mime}",
                    f"声明的 MIME 类型 '{declared_mime}' 与文件扩展名 '{ext}' 不匹配。期望: {extension_mime}"
                )
            # Use extension-based MIME in non-strict mode
            return extension_mime

        allowed_list = ", ".join(list(allowed_types)[:5]) + ("..." if len(allowed_types) > 5 else "")
        raise FileValidationError(
            f"MIME type '{declared_mime}' is not allowed. Allowed types: {allowed_list}",
            f"MIME 类型 '{declared_mime}' 不被允许。允许的类型: {allowed_list}"
        )

    # Additional check: ensure MIME matches extension
    extension_mime = SAFE_EXTENSIONS.get(ext)
    if extension_mime and declared_mime != extension_mime:
        logger.warning(
            f"MIME type mismatch: declared='{declared_mime}', extension suggests='{extension_mime}'"
        )
        if strict:
            raise FileValidationError(
                f"MIME type '{declared_mime}' does not match file extension '{ext}'",
                f"MIME 类型 '{declared_mime}' 与文件扩展名 '{ext}' 不匹配"
            )

    return declared_mime


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal and other attacks.

    Args:
        filename: The original filename

    Returns:
        A sanitized filename safe for storage
    """
    # Get the base name without path
    name = Path(filename).name

    # Remove any null bytes
    name = name.replace("\x00", "")

    # Limit filename length
    if len(name) > 255:
        ext = Path(name).suffix
        base = Path(name).stem[:255 - len(ext)]
        name = base + ext

    return name


async def validate_file_upload(
    file: UploadFile,
    allowed_types: Set[str],
    max_size: int,
    strict_mime_check: bool = True
) -> Tuple[str, str]:
    """Comprehensive file upload validation.

    This function validates:
    1. File size against maximum limit
    2. File extension against allowed types
    3. MIME type against allowed types
    4. Filename is sanitized

    Args:
        file: The uploaded file
        allowed_types: Set of allowed MIME types
        max_size: Maximum file size in bytes
        strict_mime_check: If True, reject on MIME/extension mismatch

    Returns:
        Tuple of (sanitized_filename, validated_mime_type)

    Raises:
        FileValidationError: If validation fails
    """
    # Validate filename
    if not file.filename:
        raise FileValidationError(
            "Filename is required",
            "文件名是必需的"
        )

    sanitized_name = sanitize_filename(file.filename)

    # Validate file size
    validate_file_size(file, max_size)

    # Validate extension
    ext = validate_file_extension(sanitized_name)

    # Validate MIME type
    declared_mime = file.content_type or "application/octet-stream"
    validated_mime = validate_mime_type(
        sanitized_name,
        declared_mime,
        allowed_types,
        strict=strict_mime_check
    )

    return sanitized_name, validated_mime


def get_allowed_types_for_media(media_type: str) -> Set[str]:
    """Get allowed MIME types for a media category.

    Args:
        media_type: Media category ('image', 'audio', 'video', 'document')

    Returns:
        Set of allowed MIME types for the category
    """
    types_map = {
        "image": ALLOWED_IMAGE_TYPES,
        "audio": ALLOWED_AUDIO_TYPES,
        "video": ALLOWED_VIDEO_TYPES,
        "document": ALLOWED_DOCUMENT_TYPES
    }
    return types_map.get(media_type.lower(), set())
