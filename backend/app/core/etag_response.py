"""
ETag Response Wrapper

Custom response class that automatically adds ETag headers to JSON responses.
"""
import json
from typing import Any, Optional

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from app.core.etag import generate_etag, matches_any_etag
from app.core.json_encoder import CustomJSONEncoder


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
        cache_control: Optional[str] = None,
        **kwargs
    ):
        """Initialize ETagResponse.

        Args:
            content: The response content (will be converted to dict if it's a Pydantic model)
            max_age: Cache-Control max-age in seconds (default: 300)
            weak: If True, use weak ETag validation (prefixed with W/)
            **kwargs: Additional arguments passed to JSONResponse
        """
        # Convert Pydantic models to dict for ETag generation and serialization
        if hasattr(content, 'model_dump'):
            # Pydantic v2 - use mode='json' to serialize datetime/datetime objects
            self._etag_content = content.model_dump(mode='json')
            # Update content to JSON-serializable dict for JSONResponse
            json_content = content.model_dump(mode='json')
        elif hasattr(content, 'dict'):
            # Pydantic v1 fallback
            self._etag_content = content.dict()
            json_content = content.dict()
        else:
            self._etag_content = content
            json_content = content

        # Generate ETag
        self._etag = generate_etag(self._etag_content, weak=weak)

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
        return json.dumps(content, cls=CustomJSONEncoder, ensure_ascii=False).encode('utf-8')


async def check_etag_precondition(
    request: Request,
    content: Any,
    weak: bool = False,
    max_age: int = 300,
    cache_control: Optional[str] = None
) -> Optional[Response]:
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

    # Convert Pydantic model to dict for ETag generation
    if hasattr(content, 'model_dump'):
        etag_content = content.model_dump(mode='json')
    elif hasattr(content, 'dict'):
        etag_content = content.dict()
    else:
        etag_content = content

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
