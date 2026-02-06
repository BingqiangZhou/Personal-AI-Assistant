"""Compatibility shim for file validation utilities.

The canonical implementation lives in ``app.shared.file_validation``.
"""

from fastapi import UploadFile

from app.shared.file_validation import (
    FileValidationError,
    get_allowed_types_for_media,
    sanitize_filename,
    validate_file_extension,
    validate_file_size,
    validate_file_upload,
    validate_mime_type,
)


class FileTypeError(FileValidationError):
    """Backward-compatible alias for legacy exception naming."""


class FileSizeValidator:
    """Backward-compatible wrapper for legacy API shape."""

    @staticmethod
    def validate(file: UploadFile, max_size: int) -> None:
        validate_file_size(file, max_size)


class FileValidator:
    """Backward-compatible wrapper for legacy API shape."""

    @staticmethod
    async def validate_upload(
        file: UploadFile,
        allowed_types: set[str],
        max_size: int,
        strict_mime_check: bool = True,
    ) -> tuple[str, str]:
        return await validate_file_upload(
            file=file,
            allowed_types=allowed_types,
            max_size=max_size,
            strict_mime_check=strict_mime_check,
        )


__all__ = [
    "FileValidationError",
    "FileTypeError",
    "FileValidator",
    "FileSizeValidator",
    "validate_file_size",
    "validate_file_extension",
    "validate_mime_type",
    "sanitize_filename",
    "validate_file_upload",
    "get_allowed_types_for_media",
]
