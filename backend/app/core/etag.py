"""
ETag Utilities for HTTP Caching

Provides functions for generating and validating ETag headers
to enable 304 Not Modified responses.
"""
import hashlib
import json
from typing import Any, Optional

from app.core.json_encoder import CustomJSONEncoder


def generate_etag(content: Any, weak: bool = False) -> str:
    """Generate ETag from content using SHA256 hash.

    Args:
        content: The content to generate ETag from (dict, list, or str)
        weak: If True, prefix with W/ for weak ETag validation

    Returns:
        ETag string (e.g., "abc123..." or "W/abc123...")
    """
    # Convert content to JSON string with consistent ordering
    json_str = json.dumps(content, cls=CustomJSONEncoder, sort_keys=True, ensure_ascii=False)

    # Generate SHA256 hash
    hash_value = hashlib.sha256(json_str.encode("utf-8")).hexdigest()

    # Return weak or strong ETag
    return f"W/{hash_value}" if weak else hash_value


def parse_if_none_match(header: Optional[str]) -> set[str]:
    """Parse If-None-Match header into set of ETags.

    Args:
        header: The If-None-Match header value (e.g., '"abc123", "def456"')

    Returns:
        Set of ETag strings (with quotes removed)
    """
    if not header:
        return set()

    # Split by comma and clean up each ETag
    etags = set()
    for tag in header.split(','):
        # Remove whitespace and quotes
        cleaned = tag.strip().strip('"')
        if cleaned:
            etags.add(cleaned)

    return etags


def validate_etag(request_etag: str, current_etag: str) -> bool:
    """Check if request ETag matches current ETag.

    Args:
        request_etag: ETag from If-None-Match header (may be "*" for wildcard)
        current_etag: The current ETag for the resource

    Returns:
        True if ETags match (or wildcard used), False otherwise
    """
    # Wildcard matches everything
    if request_etag == "*":
        return True

    # Exact match (handle weak ETags by stripping W/ prefix for comparison)
    request_clean = request_etag.removeprefix("W/")
    current_clean = current_etag.removeprefix("W/")

    return request_clean == current_clean


def matches_any_etag(current_etag: str, if_none_match_header: Optional[str]) -> bool:
    """Check if current ETag matches any ETag in If-None-Match header.

    Args:
        current_etag: The current ETag for the resource
        if_none_match_header: The If-None-Match header value

    Returns:
        True if current ETag matches any in header (or wildcard), False otherwise
    """
    etags = parse_if_none_match(if_none_match_header)
    if not etags:
        return False

    # Check wildcard
    if "*" in etags:
        return True

    # Check if current ETag matches any in the set
    for request_etag in etags:
        if validate_etag(request_etag, current_etag):
            return True

    return False
