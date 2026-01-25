"""
Compatibility shim for LLM privacy.

This module has been moved to app.domains.ai.
This shim maintains backward compatibility by re-exporting the moved classes.
"""

# Re-export from new location for backward compatibility
from app.domains.ai.llm_privacy import (
    ContentSanitizer,
)

__all__ = [
    "ContentSanitizer",
]
