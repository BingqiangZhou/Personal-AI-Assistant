"""
Compatibility shim for feed parser.

This module has been moved to app.domains.subscription.parsers.
This shim maintains backward compatibility by re-exporting the moved classes.
"""

# Re-export from new location for backward compatibility
from app.domains.subscription.parsers.feed_parser import (
    FeedParser,
    parse_feed_bytes,
    parse_feed_url,
    strip_html_tags,
)
from app.domains.subscription.parsers.feed_schemas import (
    FeedEntry,
    FeedInfo,
    FeedParseOptions,
    FeedParserConfig,
    FeedParseResult,
    ParseError,
    ParseErrorCode,
)


__all__ = [
    "FeedParser",
    "parse_feed_url",
    "parse_feed_bytes",
    "strip_html_tags",
    "ParseErrorCode",
    "ParseError",
    "FeedInfo",
    "FeedEntry",
    "FeedParseResult",
    "FeedParserConfig",
    "FeedParseOptions",
]
