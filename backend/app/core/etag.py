"""
ETag Utilities for HTTP Caching

Provides functions for generating and validating ETag headers
to enable 304 Not Modified responses.
"""
import hashlib
import json
from typing import Any

from app.core.json_encoder import CustomJSONEncoder


def _normalize_etag(etag: str) -> str:
    """Normalize an ETag token to RFC-style canonical format.

    Canonical formats:
    - Strong: "opaque-tag"
    - Weak: W/"opaque-tag"
    - Wildcard: *
    """
    token = etag.strip()
    if not token:
        return ""

    if token == "*":
        return "*"

    is_weak = token[:2].lower() == "w/"
    if is_weak:
        token = token[2:].strip()

    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        opaque_tag = token[1:-1]
    else:
        # Be tolerant to legacy/non-standard unquoted values.
        opaque_tag = token.strip('"')

    if not opaque_tag:
        return ""

    if is_weak:
        return f'W/"{opaque_tag}"'
    return f'"{opaque_tag}"'


def _opaque_tag_value(etag: str) -> str | None:
    """Return the opaque tag value from a strong/weak ETag token."""
    normalized = _normalize_etag(etag)
    if not normalized or normalized == "*":
        return None

    if normalized.startswith('W/"'):
        return normalized[3:-1]
    return normalized[1:-1]


def generate_etag(content: Any, weak: bool = False) -> str:
    """Generate ETag from content using SHA256 hash.

    Args:
        content: The content to generate ETag from (dict, list, or str)
        weak: If True, prefix with W/ for weak ETag validation

    Returns:
        ETag string (e.g., '"abc123..."' or 'W/"abc123..."')
    """
    # Convert content to JSON string with consistent ordering
    json_str = json.dumps(content, cls=CustomJSONEncoder, sort_keys=True, ensure_ascii=False)

    # Generate SHA256 hash
    hash_value = hashlib.sha256(json_str.encode("utf-8")).hexdigest()

    # Return weak or strong ETag in RFC-compatible format.
    strong_etag = f'"{hash_value}"'
    return f"W/{strong_etag}" if weak else strong_etag


def parse_if_none_match(header: str | None) -> set[str]:
    """Parse If-None-Match header into set of ETags.

    Args:
        header: The If-None-Match header value (e.g., '"abc123", "def456"')

    Returns:
        Set of normalized ETag strings
    """
    if not header:
        return set()

    # Split by comma and normalize each ETag token.
    etags = set()
    for tag in header.split(","):
        normalized = _normalize_etag(tag)
        if normalized:
            etags.add(normalized)

    return etags


def validate_etag(request_etag: str, current_etag: str) -> bool:
    """Check if request ETag matches current ETag.

    Args:
        request_etag: ETag from If-None-Match header (may be "*" for wildcard)
        current_etag: The current ETag for the resource

    Returns:
        True if ETags match (or wildcard used), False otherwise
    """
    # Wildcard matches everything.
    if request_etag.strip() == "*":
        return True

    # If-None-Match uses weak comparison semantics.
    request_clean = _opaque_tag_value(request_etag)
    current_clean = _opaque_tag_value(current_etag)

    if request_clean is None or current_clean is None:
        return False

    return request_clean == current_clean


def matches_any_etag(current_etag: str, if_none_match_header: str | None) -> bool:
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

    # Check if current ETag matches any in the set.
    return any(validate_etag(request_etag, current_etag) for request_etag in etags)
