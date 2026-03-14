"""Response assembly helpers for AI model APIs."""

from __future__ import annotations

from collections.abc import Iterable

from app.domains.ai.schemas import AIModelConfigList, AIModelConfigResponse


def build_ai_model_config_response(model) -> AIModelConfigResponse:
    """Build the public response schema for an AI model config."""
    success_rate = 0.0
    if model.usage_count > 0:
        success_rate = (model.success_count / model.usage_count) * 100

    return AIModelConfigResponse(
        id=model.id,
        name=model.name,
        display_name=model.display_name,
        description=model.description,
        model_type=model.model_type,
        api_url=model.api_url,
        api_key=model.api_key,
        api_key_encrypted=model.api_key_encrypted,
        model_id=model.model_id,
        provider=model.provider,
        max_tokens=model.max_tokens,
        temperature=model.temperature,
        timeout_seconds=model.timeout_seconds,
        max_retries=model.max_retries,
        max_concurrent_requests=model.max_concurrent_requests,
        rate_limit_per_minute=model.rate_limit_per_minute,
        cost_per_input_token=model.cost_per_input_token,
        cost_per_output_token=model.cost_per_output_token,
        extra_config=model.extra_config,
        is_active=model.is_active,
        is_default=model.is_default,
        is_system=model.is_system,
        usage_count=model.usage_count,
        success_count=model.success_count,
        error_count=model.error_count,
        total_tokens_used=model.total_tokens_used,
        success_rate=success_rate,
        created_at=model.created_at,
        updated_at=model.updated_at,
        last_used_at=model.last_used_at,
    )


def build_ai_model_config_responses(models: Iterable[object]) -> list[AIModelConfigResponse]:
    """Build response schemas for a sequence of AI model configs."""
    return [build_ai_model_config_response(model) for model in models]


def build_ai_model_config_list_response(
    *,
    models: Iterable[object],
    total: int,
    page: int,
    size: int,
) -> AIModelConfigList:
    """Build the paginated AI model config list response."""
    return AIModelConfigList(
        models=build_ai_model_config_responses(models),
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size,
    )
