"""
Compatibility shim for file validation.

This module has been moved to app.shared.
This shim maintains backward compatibility by re-exporting the moved classes.
"""

# Re-export from new location for backward compatibility
from app.shared.file_validation import (
    FileValidator,
    FileSizeValidator,
    FileTypeError,
    validate_file_size,
    validate_file_type,
)

__all__ = [
    "FileValidator",
    "FileSizeValidator",
    "FileTypeError",
    "validate_file_size",
    "validate_file_type",
]
