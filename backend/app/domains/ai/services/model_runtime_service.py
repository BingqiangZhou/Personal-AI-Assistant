"""Runtime validation and invocation for AI model services."""

from __future__ import annotations

import logging
import time
from typing import Any

from app.core.exceptions import ValidationError
from app.domains.ai.model_testing import (
    test_text_generation_model,
    test_transcription_model,
    validate_api_key,
)
from app.domains.ai.models import AIModelConfig, ModelType
from app.domains.ai.repositories import AIModelConfigRepository
from app.domains.ai.schemas import APIKeyValidationResponse, ModelTestResponse

from .model_security_service import AIModelSecurityService


logger = logging.getLogger(__name__)


class AIModelRuntimeService:
    """Handle model testing, validation, and runtime fallback invocations."""

    def __init__(
        self,
        repo: AIModelConfigRepository,
        security_service: AIModelSecurityService,
    ):
        self.repo = repo
        self.security_service = security_service

    async def test_model(
        self,
        model_id: int,
        test_data: dict[str, Any] | None = None,
    ) -> ModelTestResponse:
        if test_data is None:
            test_data = {}

        model = await self.repo.get_by_id(model_id)
        if not model:
            raise ValidationError(f"Model {model_id} not found")
        if not model.is_active:
            raise ValidationError(f"Model {model_id} is not active")

        api_key = await self.security_service.get_decrypted_api_key(model)
        started_at = time.time()

        try:
            if model.model_type == ModelType.TRANSCRIPTION:
                result = await test_transcription_model(model, api_key, test_data)
            else:
                result = await test_text_generation_model(model, api_key, test_data)

            await self.repo.increment_usage(model_id, success=True)
            return ModelTestResponse(
                success=True,
                response_time_ms=(time.time() - started_at) * 1000,
                result=result,
            )
        except Exception as exc:
            await self.repo.increment_usage(model_id, success=False)
            logger.error("Model test failed: %s", exc)
            return ModelTestResponse(
                success=False,
                response_time_ms=(time.time() - started_at) * 1000,
                error_message=str(exc),
            )

    async def validate_api_key(
        self,
        api_url: str,
        api_key: str,
        model_id: str | None,
        model_type: ModelType,
    ) -> APIKeyValidationResponse:
        return await validate_api_key(api_url, api_key, model_id, model_type)

    async def call_transcription_with_fallback(
        self,
        audio_file_path: str,
        language: str = "zh",
        model_id: str | None = None,
    ) -> tuple[str, AIModelConfig | None]:
        models = await self._resolve_candidate_models(
            model_type=ModelType.TRANSCRIPTION,
            model_id=model_id,
        )
        last_error = None
        for model in models:
            try:
                logger.info(
                    "Trying transcription model: %s (priority: %s)",
                    model.name,
                    model.priority,
                )
                result = await self._call_transcription_model(model, audio_file_path, language)
                await self.repo.increment_usage(model.id, success=True)
                logger.info("Transcription succeeded with model: %s", model.name)
                return result, model
            except Exception as exc:
                last_error = exc
                await self.repo.increment_usage(model.id, success=False)
                logger.warning(
                    "Transcription failed with model %s: %s",
                    model.name,
                    exc,
                )

        raise ValidationError(
            f"All transcription models failed. Last error: {str(last_error)}"
        )

    async def call_text_generation_with_fallback(
        self,
        messages: list[dict[str, str]],
        max_tokens: int | None = None,
        temperature: float | None = None,
        model_id: str | None = None,
    ) -> tuple[str, AIModelConfig | None]:
        models = await self._resolve_candidate_models(
            model_type=ModelType.TEXT_GENERATION,
            model_id=model_id,
        )
        last_error = None
        for model in models:
            try:
                logger.info(
                    "Trying text generation model: %s (priority: %s)",
                    model.name,
                    model.priority,
                )
                result = await self._call_text_generation_model(
                    model,
                    messages,
                    max_tokens,
                    temperature,
                )
                await self.repo.increment_usage(model.id, success=True)
                logger.info("Text generation succeeded with model: %s", model.name)
                return result, model
            except Exception as exc:
                last_error = exc
                await self.repo.increment_usage(model.id, success=False)
                logger.warning(
                    "Text generation failed with model %s: %s",
                    model.name,
                    exc,
                )

        raise ValidationError(
            f"All text generation models failed. Last error: {str(last_error)}"
        )

    async def _resolve_candidate_models(
        self,
        *,
        model_type: ModelType,
        model_id: str | None,
    ) -> list[AIModelConfig]:
        if model_id:
            model = await self.repo.get_by_id(model_id)
            if not model or not model.is_active:
                raise ValidationError(f"Model {model_id} not found or not active")
            return [model]

        models = await self.repo.get_active_models_by_priority(model_type)
        if not models:
            if model_type == ModelType.TRANSCRIPTION:
                raise ValidationError("No active transcription models available")
            raise ValidationError("No active text generation models available")
        return models

    async def _call_transcription_model(
        self,
        model: AIModelConfig,
        audio_file_path: str,
        language: str = "zh",
    ) -> str:
        import os

        import aiohttp

        api_key = await self.security_service.get_decrypted_api_key(model)
        headers = {"Authorization": f"Bearer {api_key}"}
        timeout = aiohttp.ClientTimeout(total=model.timeout_seconds)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            with open(audio_file_path, "rb") as audio_file:
                data = aiohttp.FormData()
                data.add_field(
                    "file",
                    audio_file,
                    filename=os.path.basename(audio_file_path),
                    content_type="audio/mpeg",
                )
                data.add_field("model", model.model_id)
                data.add_field("language", language)

                api_endpoint = (
                    "https://api.openai.com/v1/audio/transcriptions"
                    if model.provider == "openai"
                    else model.api_url
                )
                async with session.post(api_endpoint, headers=headers, data=data) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"API error: {response.status} - {error_text}")

                    result = await response.json()
                    if "text" not in result:
                        raise Exception("Invalid response format: missing 'text' field")
                    return result["text"].strip()

    async def _call_text_generation_model(
        self,
        model: AIModelConfig,
        messages: list[dict[str, str]],
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> str:
        import aiohttp

        from app.core.utils import filter_thinking_content, sanitize_html

        api_key = await self.security_service.get_decrypted_api_key(model)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        data = {
            "model": model.model_id,
            "messages": messages,
            "max_tokens": max_tokens or model.max_tokens or 1000,
            "temperature": temperature or model.get_temperature_float() or 0.7,
        }
        timeout = aiohttp.ClientTimeout(total=model.timeout_seconds)

        async with aiohttp.ClientSession(timeout=timeout) as session, session.post(
            f"{model.api_url}/chat/completions",
            headers=headers,
            json=data,
        ) as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"API error: {response.status} - {error_text}")

            result = await response.json()
            if "choices" not in result or not result["choices"]:
                raise Exception("Invalid response from API")

            raw_content = result["choices"][0]["message"]["content"].strip()
            cleaned_content = filter_thinking_content(raw_content)
            safe_content = sanitize_html(cleaned_content)
            logger.debug(
                "Filtered and sanitized content: %s -> %s chars",
                len(raw_content),
                len(safe_content),
            )
            return safe_content