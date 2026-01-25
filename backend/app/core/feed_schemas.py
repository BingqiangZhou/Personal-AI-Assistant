"""
Compatibility shim for feed schemas.

This module has been moved to app.domains.subscription.parsers.
This shim maintains backward compatibility by re-exporting the moved classes.
"""

# Re-export from new location for backward compatibility
from app.domains.subscription.parsers.feed_schemas import (
    ParseErrorCode,
    ParseError,
    FeedInfo,
    FeedEntry,
    FeedParseResult,
    FeedParserConfig,
    FeedParseOptions,
)

__all__ = [
    "ParseErrorCode",
    "ParseError",
    "FeedInfo",
    "FeedEntry",
    "FeedParseResult",
    "FeedParserConfig",
    "FeedParseOptions",
]
