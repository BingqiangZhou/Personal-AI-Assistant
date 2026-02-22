"""
ETag Utilities for HTTP Caching

Provides functions for generating and validating ETag headers
to enable 304 Not Modified responses.
Also includes ETagResponse class for automatic ETag header generation.
"""
import hashlib
import json
from typing import Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse

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


def serialize_etag_content(content: Any) -> Any:
    """Serialize content once for both ETag generation and JSON rendering."""
    if hasattr(content, "model_dump"):
        return content.model_dump(mode="json")
    if hasattr(content, "dict"):
        return content.dict()
    return content


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


# ==================== ETag Response Classes ====================

class ETagResponse(JSONResponse):
    """Custom JSONResponse with automatic ETag header generation.

    This response class automatically:
    1. Generates an ETag from the response content
    2. Adds the ETag header to the response
    3. Sets appropriate Cache-Control headers
    4. Returns 304 Not Modified if If-None-Match matches

    Usage:
        ```python
        return ETagResponse(
            content=response_data,
            max_age=300,
            weak=False
        )
        ```
    """

    def __init__(
        self,
        content: Any,
        *,
        max_age: int = 300,
        weak: bool = False,
        cache_control: str | None = None,
        precomputed_etag: str | None = None,
        content_is_serialized: bool = False,
        **kwargs
    ):
        """Initialize ETagResponse.

        Args:
            content: The response content (will be converted to dict if it's a Pydantic model)
            max_age: Cache-Control max-age in seconds (default: 300)
            weak: If True, use weak ETag validation (prefixed with W/)
            **kwargs: Additional arguments passed to JSONResponse
        """
        # Convert content at most once.
        if content_is_serialized:
            self._etag_content = content
            json_content = content
        else:
            serialized = serialize_etag_content(content)
            self._etag_content = serialized
            json_content = serialized

        # Generate ETag
        self._etag = precomputed_etag or generate_etag(self._etag_content, weak=weak)

        # Prepare headers
        headers = kwargs.pop('headers', {})
        headers['ETag'] = self._etag
        if cache_control is None:
            cache_control = f'public, max-age={max_age}'
        headers['Cache-Control'] = cache_control

        # Store content for rendering with custom encoder
        self._original_content = json_content
        super().__init__(json_content, headers=headers, **kwargs)

    def render(self, content: Any) -> bytes:
        """Render content using CustomJSONEncoder for proper datetime serialization."""
        return json.dumps(
            content,
            cls=CustomJSONEncoder,
            sort_keys=True,
            ensure_ascii=False,
        ).encode('utf-8')


async def check_etag_precondition(
    request: Request,
    content: Any,
    weak: bool = False,
    max_age: int = 300,
    cache_control: str | None = None,
    content_is_serialized: bool = False,
) -> Response | None:
    """Check If-None-Match header and return 304 if match.

    This function should be called in endpoints before generating
    the full response. If the client's ETag matches, returns 304
    Not Modified response immediately.

    Args:
        request: The FastAPI request object
        content: The response content (for ETag generation)
        weak: If True, use weak ETag validation

    Returns:
        Response with 304 status if ETag matches, None otherwise

    Example:
        ```python
        @router.get("/items")
        async def get_items(
            request: Request,
            db: AsyncSession = Depends(get_db_session)
        ):
            # Fetch data
            items = await service.get_items()

            # Check ETag - return 304 if match
            etag_response = await check_etag_precondition(request, items)
            if etag_response:
                return etag_response

            # Return full response with ETag
            return ETagResponse(content=items)
        ```
    """
    # Get If-None-Match header
    if_none_match = request.headers.get('if-none-match')

    if not if_none_match:
        return None

    etag_content = content if content_is_serialized else serialize_etag_content(content)

    # Generate ETag for current content
    current_etag = generate_etag(etag_content, weak=weak)

    # Check if any ETag matches
    if matches_any_etag(current_etag, if_none_match):
        if cache_control is None:
            cache_control = f'public, max-age={max_age}'
        return Response(
            status_code=304,
            headers={
                'ETag': current_etag,
                'Cache-Control': cache_control
            }
        )

    return None


def build_conditional_etag_response(
    request: Request,
    content: Any,
    *,
    max_age: int = 300,
    weak: bool = False,
    cache_control: str | None = None,
) -> Response:
    """Build 304/200 ETag response while serializing and hashing content once."""
    serialized = serialize_etag_content(content)
    current_etag = generate_etag(serialized, weak=weak)
    if_none_match = request.headers.get("if-none-match")

    if if_none_match and matches_any_etag(current_etag, if_none_match):
        if cache_control is None:
            cache_control = f"public, max-age={max_age}"
        return Response(
            status_code=304,
            headers={
                "ETag": current_etag,
                "Cache-Control": cache_control,
            },
        )

    return ETagResponse(
        content=serialized,
        max_age=max_age,
        weak=weak,
        cache_control=cache_control,
        precomputed_etag=current_etag,
        content_is_serialized=True,
    )


def etag_response_wrapper(
    content: Any,
    max_age: int = 300,
    weak: bool = False
) -> ETagResponse:
    """Convenience function to create an ETagResponse.

    Args:
        content: The response content
        max_age: Cache-Control max-age in seconds
        weak: If True, use weak ETag validation

    Returns:
        ETagResponse instance
    """
    return ETagResponse(content=content, max_age=max_age, weak=weak)
