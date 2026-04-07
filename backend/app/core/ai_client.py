"""Shared AI API client with retry and fallback logic.

This module provides a unified AIClientService that handles:
- Single-shot AI API calls (call_ai_api)
- Per-model retry with exponential backoff (call_ai_api_with_retry)
- Cross-model fallback chains with model resolution (AIClientService)

Note: This client uses raw aiohttp instead of the openai SDK because the system
supports multiple OpenAI-compatible providers (not just OpenAI). The raw HTTP
approach allows configurable base URLs for any compatible endpoint.
"""

import asyncio
import json
import logging
import random
import time
from collections.abc import Callable, Coroutine
from typing import Any

import aiohttp
from fastapi import HTTPException

from app.core.config import settings
from app.core.http_client import get_shared_http_session


logger = logging.getLogger(__name__)


class RetryableAIModelError(Exception):
    """Transient AI model invocation error that can be retried."""


class AIClientError(Exception):
    """Error raised when an AI model invocation fails after all retries."""

    def __init__(self, message, model_name=None, provider=None, original_error=None):
        super().__init__(message)
        self.model_name = model_name
        self.provider = provider
        self.original_error = original_error


def is_retryable_http_status(status_code: int) -> bool:
    """Check if HTTP status code indicates a retryable error.

    Retryable status codes:
    - 5xx: Server errors
    - 408: Request Timeout
    - 409: Conflict
    - 425: Too Early
    - 429: Too Many Requests
    """
    return status_code >= 500 or status_code in {408, 409, 425, 429}


def looks_like_html_error_page(text: str) -> bool:
    """Check if response content looks like an HTML error page.

    This detects cases where a proxy (e.g., Cloudflare) returns
    an HTML error page instead of the expected JSON response.
    """
    lowered = text.lower()
    markers = (
        "<!doctype html",
        "<html",
        "<head",
        "cloudflare",
        "524: a timeout occurred",
        "/cdn-cgi/",
    )
    return any(marker in lowered for marker in markers)


async def call_ai_api(
    model_config: Any,
    api_key: str,
    prompt: str,
    *,
    max_prompt_length: int | None = None,
) -> str:
    """Make a raw AI API call and return the response content.

    Args:
        model_config: Model configuration object with attributes:
            - api_url: Base API URL
            - model_id: Model identifier
            - timeout_seconds: Request timeout
            - max_tokens: Optional max tokens
            - extra_config: Optional extra configuration dict
            - temperature: Optional temperature parameter
        api_key: API key for authentication
        prompt: The prompt to send
        max_prompt_length: Maximum prompt length before truncation (defaults to settings.AI_CLIENT_MAX_PROMPT_LENGTH)

    Returns:
        The content string from the AI response

    Raises:
        HTTPException: For non-retryable errors
        RetryableAIModelError: For retryable errors
    """
    if max_prompt_length is None:
        max_prompt_length = settings.AI_CLIENT_MAX_PROMPT_LENGTH
    # Truncate prompt if too long
    if len(prompt) > max_prompt_length:
        prompt = prompt[:max_prompt_length] + "\n\n[Content too long, truncated]"

    # Build API URL
    api_url = model_config.api_url
    if not api_url.endswith("/chat/completions"):
        api_url = (
            f"{api_url}chat/completions"
            if api_url.endswith("/")
            else f"{api_url}/chat/completions"
        )

    # Build request
    timeout = aiohttp.ClientTimeout(total=model_config.timeout_seconds)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    data = {
        "model": model_config.model_id,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": model_config.temperature or 0.7,
    }
    if model_config.max_tokens is not None:
        data["max_tokens"] = model_config.max_tokens
    if model_config.extra_config:
        data.update(model_config.extra_config)

    # Make request
    session = await get_shared_http_session()
    async with session.post(
        api_url,
        headers=headers,
        json=data,
        timeout=timeout,
    ) as response:
        response_text = await response.text()
        content_type = response.headers.get("Content-Type", "")

        # Check for HTML error page
        if "text/html" in content_type.lower() or (
            looks_like_html_error_page(response_text)
            and "application/json" not in content_type.lower()
        ):
            raise HTTPException(
                status_code=500,
                detail="AI provider returned an HTML error page instead of JSON response",
            )

        # Handle non-200 status codes
        if response.status != 200:
            error_text = response_text
            if is_retryable_http_status(response.status):
                raise RetryableAIModelError(
                    f"AI API transient error: {response.status} - {error_text[:200]}",
                )
            # Non-retryable errors
            if response.status == 400:
                logger.error(
                    "AI API bad request (400) for model %s: %s",
                    model_config.model_id,
                    error_text,
                )
                raise HTTPException(
                    status_code=502,
                    detail="AI service error. Please try again later.",
                )
            if response.status == 401:
                logger.error(
                    "AI API authentication failed (401) for model %s",
                    model_config.model_id,
                )
                raise HTTPException(
                    status_code=502,
                    detail="AI service error. Please try again later.",
                )
            logger.error(
                "AI API error %d for model %s: %s",
                response.status,
                model_config.model_id,
                error_text,
            )
            raise HTTPException(
                status_code=502,
                detail="AI service error. Please try again later.",
            )

        # Parse JSON response
        try:
            result = json.loads(response_text)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=500,
                detail="AI provider returned non-JSON response",
            ) from exc

        # Validate response structure
        if "choices" not in result or not result["choices"]:
            raise HTTPException(
                status_code=500,
                detail="Invalid response from AI API",
            )

        content = result["choices"][0].get("message", {}).get("content")
        if not content or not isinstance(content, str):
            raise HTTPException(
                status_code=500,
                detail="AI API returned empty or invalid content",
            )

        # Check for HTML error in content
        if looks_like_html_error_page(content):
            raise HTTPException(
                status_code=500,
                detail="AI provider returned HTML error content inside the completion payload",
            )

        return content


async def call_ai_api_with_retry(
    model_config: Any,
    api_key: str,
    prompt: str,
    response_parser: Callable[[str], Coroutine[Any, Any, Any]],
    ai_model_repo: Any,
    *,
    operation_name: str = "AI API",
    max_retries: int | None = None,
    base_delay: int | None = None,
    max_prompt_length: int | None = None,
) -> tuple[Any, float, int]:
    """Call AI API with exponential backoff retry logic.

    Args:
        model_config: Model configuration object
        api_key: API key for authentication
        prompt: The prompt to send
        response_parser: Async callable to parse the response content
        ai_model_repo: Repository for tracking usage (must have increment_usage method)
        operation_name: Name for logging (e.g., "Highlight extraction", "Summary generation")
        max_retries: Maximum retry attempts (defaults to settings.AI_CLIENT_MAX_RETRIES)
        base_delay: Base delay in seconds for exponential backoff (defaults to settings.AI_CLIENT_BASE_DELAY)
        max_prompt_length: Maximum prompt length before truncation (defaults to settings.AI_CLIENT_MAX_PROMPT_LENGTH)

    Returns:
        Tuple of (parsed_response, processing_time, tokens_used)

    Raises:
        Exception: If all retries fail or non-retryable error occurs
    """
    if max_retries is None:
        max_retries = settings.AI_CLIENT_MAX_RETRIES
    if base_delay is None:
        base_delay = settings.AI_CLIENT_BASE_DELAY
    if max_prompt_length is None:
        max_prompt_length = settings.AI_CLIENT_MAX_PROMPT_LENGTH
    for attempt in range(max_retries):
        attempt_start = time.time()
        try:
            # Make API call
            response_content = await call_ai_api(
                model_config=model_config,
                api_key=api_key,
                prompt=prompt,
                max_prompt_length=max_prompt_length,
            )

            # Parse response
            parsed_response = await response_parser(response_content)

            # Calculate metrics
            processing_time = time.time() - attempt_start
            tokens_used = len(prompt.split()) + len(str(response_content).split())

            # Track successful usage
            await ai_model_repo.increment_usage(
                model_config.id,
                success=True,
                tokens_used=tokens_used,
            )

            return parsed_response, processing_time, tokens_used

        except (
            RetryableAIModelError,
            TimeoutError,
            aiohttp.ClientError,
        ) as exc:
            # Track failed usage
            await ai_model_repo.increment_usage(model_config.id, success=False)

            if attempt < max_retries - 1:
                backoff = base_delay * (2**attempt)
                logger.warning(
                    "%s transient error model=%s provider=%s attempt=%s/%s retryable=true error_type=%s error=%s",
                    operation_name,
                    model_config.name,
                    model_config.provider,
                    attempt + 1,
                    max_retries,
                    type(exc).__name__,
                    exc,
                )
                await asyncio.sleep(backoff + random.uniform(0, 0.5 * backoff))
                continue

            # Retries exhausted
            logger.error(
                "%s transient retries exhausted model=%s provider=%s attempts=%s error_type=%s error=%s",
                operation_name,
                model_config.name,
                model_config.provider,
                max_retries,
                type(exc).__name__,
                exc,
            )
            raise AIClientError(
                f"Model {model_config.name} failed after {max_retries} attempts: {exc}",
                model_name=model_config.name,
                provider=model_config.provider,
                original_error=exc,
            ) from exc

        except Exception as exc:
            # Track failed usage
            await ai_model_repo.increment_usage(model_config.id, success=False)

            logger.error(
                "%s non-retryable failure model=%s provider=%s retryable=false error_type=%s error=%s",
                operation_name,
                model_config.name,
                model_config.provider,
                type(exc).__name__,
                exc,
            )
            raise AIClientError(
                f"Model {model_config.name} failed without retry: {exc}",
                model_name=model_config.name,
                provider=model_config.provider,
                original_error=exc,
            ) from exc

    raise AIClientError("Unexpected error in call_ai_api_with_retry")


class AIClientService:
    """Unified AI invocation service with model resolution, retry, and fallback.

    Consolidates the duplicated patterns across model_runtime_service,
    text_generation_service, and conversation_service into a single
    service that handles:
    - Model resolution by name or priority list
    - Per-model retry with exponential backoff (delegates to call_ai_api_with_retry)
    - Cross-model fallback chain
    - Thinking content filtering and HTML sanitization
    - Optional fallback handler when all models fail
    - Usage tracking via the repository

    Usage::

        service = AIClientService(repo, security_service)
        result = await service.call_with_fallback(
            messages=[...],
            model_type=ModelType.TEXT_GENERATION,
            model_name="gpt-4o-mini",   # optional
        )
    """

    def __init__(
        self,
        repo: Any,
        security_service: Any,
    ):
        """Initialize the unified AI client service.

        Args:
            repo: AIModelConfigRepository for model resolution and usage tracking.
            security_service: AIModelSecurityService for API key decryption.
        """
        self.repo = repo
        self.security_service = security_service

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def call_with_fallback(
        self,
        messages: list[dict[str, str]],
        *,
        model_type: Any = None,
        model_name: str | None = None,
        model_id: int | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        operation_name: str = "AI text generation",
        fallback_handler: Callable[[], Coroutine[Any, Any, str]] | None = None,
        post_process: Callable[[str], Coroutine[Any, Any, str]] | None = None,
    ) -> tuple[str, Any]:
        """Call an AI model with full fallback chain.

        Resolves candidate models by name/id or priority, then tries each
        model with per-model retry. If all models fail and a fallback_handler
        is provided, invokes it instead of raising.

        Args:
            messages: Chat-style messages list [{"role": ..., "content": ...}].
            model_type: ModelType enum value for resolving candidates.
            model_name: Optional specific model name.
            model_id: Optional specific model database id.
            max_tokens: Override max_tokens from model config.
            temperature: Override temperature from model config.
            operation_name: Label used in log messages.
            fallback_handler: Optional async callable invoked when every model fails.
            post_process: Optional async callable to transform the raw response
                (e.g., filter_thinking_content + sanitize_html). When *None*, the
                default pipeline (filter_thinking_content + sanitize_html) is applied.

        Returns:
            Tuple of (response_content, model_config_or_None).

        Raises:
            ValidationError: If no models are available or all models fail
                and no fallback_handler is provided.
        """
        from app.core.exceptions import ValidationError

        models = await self._resolve_candidate_models(
            model_type=model_type,
            model_name=model_name,
            model_id=model_id,
        )

        last_error: Exception | None = None
        for idx, model in enumerate(models):
            try:
                logger.info(
                    "%s model attempt model=%s provider=%s priority=%s order=%s/%s",
                    operation_name,
                    model.display_name
                    if hasattr(model, "display_name")
                    else model.name,
                    model.provider,
                    model.priority,
                    idx + 1,
                    len(models),
                )
                api_key = await self.security_service.get_decrypted_api_key(model)
                if not api_key:
                    logger.warning(
                        "%s skipped model=%s reason=empty_api_key",
                        operation_name,
                        model.name,
                    )
                    continue

                content = await self._invoke_single_model(
                    model=model,
                    messages=messages,
                    api_key=api_key,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    operation_name=operation_name,
                )

                # Post-process (filter thinking, sanitize html)
                if post_process is not None:
                    content = await post_process(content)
                else:
                    content = await self._default_post_process(content)

                await self.repo.increment_usage(model.id, success=True)
                logger.info(
                    "%s succeeded model=%s provider=%s",
                    operation_name,
                    model.name,
                    model.provider,
                )
                return content, model

            except Exception as exc:
                last_error = exc
                await self.repo.increment_usage(model.id, success=False)
                logger.warning(
                    "%s failed model=%s provider=%s error_type=%s error=%s",
                    operation_name,
                    model.name,
                    model.provider,
                    type(exc).__name__,
                    exc,
                )

        # All models exhausted — try fallback handler
        if fallback_handler is not None:
            logger.info(
                "%s: all models failed, invoking fallback handler",
                operation_name,
            )
            return await fallback_handler(), None

        raise ValidationError(
            f"All {len(models)} {operation_name.lower()} models failed. "
            f"Last error: {last_error!s}",
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _resolve_candidate_models(
        self,
        *,
        model_type: Any = None,
        model_name: str | None = None,
        model_id: int | None = None,
    ) -> list[Any]:
        """Resolve a list of candidate models to try in priority order."""
        from app.core.exceptions import ValidationError

        if model_id is not None:
            model = await self.repo.get_by_id(model_id)
            if not model or not model.is_active:
                raise ValidationError(f"Model {model_id} not found or not active")
            return [model]

        if model_name is not None:
            model = await self.repo.get_by_name(model_name)
            if (
                not model
                or not model.is_active
                or (model_type is not None and model.model_type != model_type)
            ):
                raise ValidationError(
                    f"Model '{model_name}' not found or not active",
                )
            return [model]

        if model_type is not None:
            models = await self.repo.get_active_models_by_priority(model_type)
            if not models:
                raise ValidationError(
                    f"No active {model_type.value} models available",
                )
            return models

        raise ValidationError("One of model_type, model_name, or model_id is required")

    async def _invoke_single_model(
        self,
        model: Any,
        messages: list[dict[str, str]],
        api_key: str,
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
        operation_name: str = "AI text generation",
    ) -> str:
        """Call a single model with per-model retry.

        Builds the request from the model config + overrides, then
        delegates to ``call_ai_api_with_retry``.
        """
        # Build a synthetic prompt for call_ai_api compatibility
        # (call_ai_api expects a single prompt string; we wrap messages)
        # We use the lower-level call_ai_api directly to support messages.
        max_retries = settings.AI_CLIENT_MAX_RETRIES
        base_delay = settings.AI_CLIENT_BASE_DELAY

        # Build URL
        api_url = model.api_url
        if not api_url.endswith("/chat/completions"):
            api_url = (
                f"{api_url}chat/completions"
                if api_url.endswith("/")
                else f"{api_url}/chat/completions"
            )

        # Build request payload
        data: dict[str, Any] = {
            "model": model.model_id,
            "messages": messages,
            "max_tokens": max_tokens or model.max_tokens or 1000,
            "temperature": temperature or model.temperature or 0.7,
        }
        if hasattr(model, "extra_config") and model.extra_config:
            data.update(model.extra_config)

        timeout = aiohttp.ClientTimeout(total=model.timeout_seconds)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        session = await get_shared_http_session()
        last_error: Exception | None = None

        for attempt in range(max_retries):
            try:
                async with session.post(
                    api_url,
                    headers=headers,
                    json=data,
                    timeout=timeout,
                ) as response:
                    response_text = await response.text()
                    content_type = response.headers.get("Content-Type", "")

                    # Detect HTML error pages
                    if "text/html" in content_type.lower() or (
                        looks_like_html_error_page(response_text)
                        and "application/json" not in content_type.lower()
                    ):
                        raise HTTPException(
                            status_code=500,
                            detail="AI provider returned an HTML error page instead of JSON response",
                        )

                    if response.status != 200:
                        error_msg = f"HTTP {response.status}: {response_text[:200]}"
                        if is_retryable_http_status(response.status):
                            raise RetryableAIModelError(error_msg)
                        raise HTTPException(
                            status_code=500,
                            detail=error_msg,
                        )

                    try:
                        result = json.loads(response_text)
                    except json.JSONDecodeError as exc:
                        raise HTTPException(
                            status_code=500,
                            detail="AI provider returned non-JSON response",
                        ) from exc

                    if "choices" not in result or not result["choices"]:
                        raise HTTPException(
                            status_code=500,
                            detail="Invalid response from AI API",
                        )

                    content = result["choices"][0].get("message", {}).get("content")
                    if not content or not isinstance(content, str):
                        raise HTTPException(
                            status_code=500,
                            detail="AI API returned empty or invalid content",
                        )

                    return content.strip()

            except (aiohttp.ClientError, TimeoutError, RetryableAIModelError) as exc:
                last_error = exc
                if attempt >= max_retries - 1:
                    logger.error(
                        "%s transient retries exhausted model=%s provider=%s attempts=%s error_type=%s error=%s",
                        operation_name,
                        model.name,
                        model.provider,
                        max_retries,
                        type(exc).__name__,
                        exc,
                    )
                    raise
                backoff = base_delay * (2**attempt)
                await asyncio.sleep(backoff + random.uniform(0, 0.5 * backoff))
                logger.warning(
                    "%s transient error model=%s provider=%s attempt=%s/%s retryable=true error_type=%s error=%s",
                    operation_name,
                    model.name,
                    model.provider,
                    attempt + 1,
                    max_retries,
                    type(exc).__name__,
                    exc,
                )

            except HTTPException:
                raise

        # Should not be reached
        raise last_error or Exception(f"{operation_name} failed unexpectedly")

    @staticmethod
    async def _default_post_process(content: str) -> str:
        """Default post-processing: filter thinking content and sanitize HTML."""
        from app.core.utils import filter_thinking_content, sanitize_html

        cleaned = filter_thinking_content(content)
        return sanitize_html(cleaned)
