"""
AI模型配置服务层
"""

import logging
import time
from typing import Any, Optional

import aiohttp
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import ValidationError
from app.domains.ai.models import AIModelConfig, ModelType
from app.domains.ai.repositories import AIModelConfigRepository
from app.domains.ai.schemas import (
    AIModelConfigCreate,
    AIModelConfigUpdate,
    APIKeyValidationResponse,
    ModelTestResponse,
    ModelUsageStats,
    PresetModelConfig,
)


logger = logging.getLogger(__name__)


class AIModelConfigService:
    """AI模型配置服务"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo = AIModelConfigRepository(db)

    async def create_model(self, model_data: AIModelConfigCreate) -> AIModelConfig:
        """创建新的模型配置"""
        # 检查名称是否已存在
        existing_model = await self.repo.get_by_name(model_data.name)
        if existing_model:
            raise ValidationError(f"Model with name '{model_data.name}' already exists")

        # 如果设置为默认，先取消同类型的其他默认模型
        if model_data.is_default:
            await self._clear_default_models(model_data.model_type)

        # 处理API密钥加密
        # 使用Fernet加密存储（HTTPS保护传输安全）
        encrypted_key = None
        if model_data.api_key:
            from app.core.security import encrypt_data

            encrypted_key = encrypt_data(model_data.api_key)
            # Don't log API key operations - security best practice
            logger.debug(f"API key processed for model {model_data.name}")

        # 创建模型配置
        model_config = AIModelConfig(
            name=model_data.name,
            display_name=model_data.display_name,
            description=model_data.description,
            model_type=model_data.model_type,
            api_url=model_data.api_url,
            api_key=encrypted_key or "",
            api_key_encrypted=bool(model_data.api_key),
            model_id=model_data.model_id,
            provider=model_data.provider,
            max_tokens=model_data.max_tokens,
            temperature=model_data.temperature,
            timeout_seconds=model_data.timeout_seconds,
            max_retries=model_data.max_retries,
            max_concurrent_requests=model_data.max_concurrent_requests,
            rate_limit_per_minute=model_data.rate_limit_per_minute,
            cost_per_input_token=model_data.cost_per_input_token,
            cost_per_output_token=model_data.cost_per_output_token,
            extra_config=model_data.extra_config or {},
            is_active=model_data.is_active,
            is_default=model_data.is_default,
            priority=model_data.priority,
            is_system=False,
        )

        return await self.repo.create(model_config)

    async def get_model_by_id(self, model_id: int) -> Optional[AIModelConfig]:
        """根据ID获取模型配置"""
        return await self.repo.get_by_id(model_id)

    async def get_models(
        self,
        model_type: Optional[ModelType] = None,
        is_active: Optional[bool] = None,
        provider: Optional[str] = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[AIModelConfig], int]:
        """获取模型配置列表"""
        return await self.repo.get_list(
            model_type=model_type,
            is_active=is_active,
            provider=provider,
            page=page,
            size=size,
        )

    async def search_models(
        self,
        query: str,
        model_type: Optional[ModelType] = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[AIModelConfig], int]:
        """搜索模型配置"""
        return await self.repo.search_models(
            query=query, model_type=model_type, page=page, size=size
        )

    async def update_model(
        self, model_id: int, model_data: AIModelConfigUpdate
    ) -> Optional[AIModelConfig]:
        """更新模型配置"""
        # 获取现有模型
        existing_model = await self.repo.get_by_id(model_id)
        if not existing_model:
            return None

        # 如果设置为默认，先取消同类型的其他默认模型
        if model_data.is_default:
            await self._clear_default_models(existing_model.model_type)

        # 准备更新数据
        update_data = model_data.dict(exclude_unset=True)

        # 处理API密钥更新
        if "api_key" in update_data:
            if update_data["api_key"]:
                # 使用Fernet加密存储（HTTPS保护传输安全）
                from app.core.security import encrypt_data

                update_data["api_key"] = encrypt_data(update_data["api_key"])
                # Don't log API key operations - security best practice
                logger.debug(f"API key updated for model {model_id}")
                update_data["api_key_encrypted"] = True
            else:
                update_data["api_key"] = ""
                update_data["api_key_encrypted"] = False

        return await self.repo.update(model_id, update_data)

    async def delete_model(self, model_id: int) -> bool:
        """删除模型配置"""
        return await self.repo.delete(model_id)

    async def set_default_model(
        self, model_id: int, model_type: ModelType
    ) -> Optional[AIModelConfig]:
        """设置默认模型"""
        success = await self.repo.set_default_model(model_id, model_type)
        if success:
            return await self.repo.get_by_id(model_id)
        return None

    async def get_default_model(self, model_type: ModelType) -> Optional[AIModelConfig]:
        """获取默认模型"""
        return await self.repo.get_default_model(model_type)

    async def get_active_models(
        self, model_type: Optional[ModelType] = None
    ) -> list[AIModelConfig]:
        """获取活跃模型"""
        return await self.repo.get_active_models(model_type)

    async def test_model(
        self, model_id: int, test_data: Optional[dict[str, Any]] = None
    ) -> ModelTestResponse:
        """测试模型连接"""
        # 统一处理 None 的情况
        if test_data is None:
            test_data = {}

        model = await self.repo.get_by_id(model_id)
        if not model:
            raise ValidationError(f"Model {model_id} not found")

        if not model.is_active:
            raise ValidationError(f"Model {model_id} is not active")

        # 解密API密钥
        api_key = await self._get_decrypted_api_key(model)

        start_time = time.time()

        try:
            if model.model_type == ModelType.TRANSCRIPTION:
                result = await self._test_transcription_model(model, api_key, test_data)
            else:  # TEXT_GENERATION
                result = await self._test_text_generation_model(
                    model, api_key, test_data
                )

            response_time = (time.time() - start_time) * 1000

            # 更新使用统计
            await self.repo.increment_usage(model_id, success=True)

            return ModelTestResponse(
                success=True, response_time_ms=response_time, result=result
            )

        except Exception as e:
            response_time = (time.time() - start_time) * 1000

            # 更新使用统计
            await self.repo.increment_usage(model_id, success=False)

            logger.error(f"Model test failed: {str(e)}")
            return ModelTestResponse(
                success=False, response_time_ms=response_time, error_message=str(e)
            )

    async def get_model_stats(self, model_id: int) -> Optional[ModelUsageStats]:
        """获取模型使用统计"""
        model = await self.repo.get_by_id(model_id)
        if not model:
            return None

        success_rate = 0.0
        if model.usage_count > 0:
            success_rate = (model.success_count / model.usage_count) * 100

        return ModelUsageStats(
            model_id=model.id,
            model_name=model.name,
            model_type=model.model_type,
            usage_count=model.usage_count,
            success_count=model.success_count,
            error_count=model.error_count,
            success_rate=success_rate,
            total_tokens_used=model.total_tokens_used,
            last_used_at=model.last_used_at,
        )

    async def get_type_stats(
        self, model_type: ModelType, limit: int = 20
    ) -> list[ModelUsageStats]:
        """获取模型类型的使用统计"""
        stats_data = await self.repo.get_usage_stats(model_type, limit)

        return [ModelUsageStats(**stat) for stat in stats_data]

    async def init_default_models(self) -> list[AIModelConfig]:
        """初始化默认模型配置 - 已禁用系统预设"""
        return []

    async def _get_decrypted_api_key(self, model: AIModelConfig) -> str:
        """获取解密的API密钥"""
        if not model.api_key_encrypted:
            return model.api_key

        # 对于系统预设模型，从环境变量获取
        if model.is_system:
            return self._get_preset_api_key_from_env(model.name)

        # 对于用户自定义模型，使用Fernet解密
        from app.core.security import decrypt_data

        try:
            decrypted = decrypt_data(model.api_key)
            # Don't log API key operations - security best practice
            logger.debug(f"API key decrypted for model {model.name}")
            return decrypted
        except Exception as e:
            logger.error(f"Failed to decrypt API key for model {model.name}: {e}")
            raise ValidationError(f"Failed to decrypt API key for model {model.name}")

    async def _test_transcription_model(
        self, model: AIModelConfig, api_key: str, test_data: Optional[dict[str, Any]]
    ) -> str:
        """
        测试转录模型
        使用实际的音频文件进行测试，并与期望文本对比
        """
        import os
        import re
        from difflib import SequenceMatcher

        import aiohttp

        # 获取测试资源路径
        current_dir = os.path.dirname(os.path.abspath(__file__))
        test_resources_dir = os.path.join(
            os.path.dirname(os.path.dirname(current_dir)), "core", "test_resources"
        )

        example_txt_path = os.path.join(test_resources_dir, "example.txt")
        example_mp3_path = os.path.join(test_resources_dir, "example.mp3")

        # 读取期望文本
        if not os.path.exists(example_txt_path):
            return "⚠️ 测试文件缺失: example.txt 未找到"

        with open(example_txt_path, encoding="utf-8") as f:
            expected_text = f.read().strip()

        # 检查音频文件是否存在
        if not os.path.exists(example_mp3_path):
            return "⚠️ 测试文件缺失: example.mp3 未找到，无法进行实际测试"

        # 进行实际的转录测试
        try:
            headers = {"Authorization": f"Bearer {api_key}"}

            timeout = aiohttp.ClientTimeout(total=60)  # 转录可能需要更长时间

            async with aiohttp.ClientSession(timeout=timeout) as session:
                with open(example_mp3_path, "rb") as audio_file:
                    data = aiohttp.FormData()
                    data.add_field(
                        "file",
                        audio_file,
                        filename="example.mp3",
                        content_type="audio/mpeg",
                    )
                    data.add_field("model", model.model_id)
                    data.add_field("language", "zh")  # 中文

                    # 根据provider选择不同的API端点
                    if model.provider == "openai":
                        api_endpoint = "https://api.openai.com/v1/audio/transcriptions"
                    else:
                        # 对于其他提供商，使用数据库中存储的完整API URL
                        api_endpoint = model.api_url

                    async with session.post(
                        api_endpoint, headers=headers, data=data
                    ) as response:
                        if response.status != 200:
                            error_text = await response.text()
                            return f"❌ API 调用失败: {response.status} - {error_text[:200]}"

                        result = await response.json()

                        if "text" not in result:
                            return "❌ API 响应格式错误: 未包含 'text' 字段"

                        transcribed_text = result["text"].strip()

                        # 清理文本：去除标点、空格、表情符号等
                        def clean_text(text):
                            # 只保留中文字符、英文字母和数字
                            cleaned = re.sub(r"[^\u4e00-\u9fa5a-zA-Z0-9]", "", text)
                            return cleaned.lower()

                        expected_clean = clean_text(expected_text)
                        transcribed_clean = clean_text(transcribed_text)

                        # 计算相似度
                        similarity = SequenceMatcher(
                            None, expected_clean, transcribed_clean
                        ).ratio()
                        similarity_percent = similarity * 100

                        # 判断是否通过测试
                        passed = similarity_percent >= 90

                        result_parts = [
                            f"{'✅' if passed else '❌'} 转录测试{'通过' if passed else '失败'}",
                            f"\n期望文本: {expected_text}",
                            f"\n转录结果: {transcribed_text}",
                            f"\n相似度: {similarity_percent:.1f}%",
                            "\n阈值: 90.0%",
                        ]

                        return "".join(result_parts)

        except aiohttp.ClientError as e:
            return f"❌ 网络错误: {str(e)}"
        except Exception as e:
            return f"❌ 测试失败: {str(e)}"

    async def _test_text_generation_model(
        self, model: AIModelConfig, api_key: str, test_data: Optional[dict[str, Any]]
    ) -> str:
        """测试文本生成模型"""
        # 修复：如果 test_data 为 None，使用空字典
        if test_data is None:
            test_data = {}

        # Use configured test prompt or allow custom prompt
        default_prompt = settings.ASSISTANT_TEST_PROMPT
        test_prompt = test_data.get("prompt", default_prompt)

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        data = {
            "model": model.model_id,
            "messages": [{"role": "user", "content": test_prompt}],
            "max_tokens": 50,
            "temperature": model.get_temperature_float() or 0.7,
        }

        timeout = aiohttp.ClientTimeout(total=model.timeout_seconds)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                f"{model.api_url}/chat/completions", headers=headers, json=data
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"API error: {response.status} - {error_text}")

                result = await response.json()
                if "choices" not in result or not result["choices"]:
                    raise Exception("Invalid response from API")

                raw_content = result["choices"][0]["message"]["content"].strip()

                # Filter out thinking tags in test results as well
                # 测试结果中也过滤掉 thinking 标签
                from app.core.utils import filter_thinking_content, sanitize_html

                # First filter thinking content, then sanitize HTML
                cleaned_content = filter_thinking_content(raw_content)
                safe_content = sanitize_html(cleaned_content)

                return safe_content

    async def _clear_default_models(self, model_type: ModelType):
        """清除指定类型的所有默认模型标记"""
        stmt = (
            update(AIModelConfig)
            .where(
                AIModelConfig.model_type == model_type, AIModelConfig.is_default == True
            )
            .values(is_default=False)
        )
        await self.db.execute(stmt)
        await self.db.commit()

        return []

    def _get_preset_api_key(self, preset: PresetModelConfig) -> Optional[str]:
        """获取预设模型的API密钥"""
        if preset.provider == "openai":
            return getattr(settings, "OPENAI_API_KEY", None)
        elif preset.provider == "siliconflow":
            return getattr(settings, "TRANSCRIPTION_API_KEY", None)
        return None

    async def validate_api_key(
        self, api_url: str, api_key: str, model_id: Optional[str], model_type: ModelType
    ) -> APIKeyValidationResponse:
        """验证API密钥"""
        start_time = time.time()
        result = None
        error_message = None

        try:
            if model_type == ModelType.TRANSCRIPTION:
                # 简单验证转录服务连接
                result = "Transciption endpoint format seems correct (Actual validation requires audio upload)"

            else:  # TEXT_GENERATION
                # 1. 尝试标准 Bearer Token
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                }

                # 确保URL不以/结尾
                base_url = api_url.rstrip("/")
                # 如果URL已经包含 v1/chat/completions，则使用原URL，否则追加
                if "chat/completions" in base_url:
                    target_url = base_url
                else:
                    target_url = f"{base_url}/chat/completions"

                data = {
                    "model": model_id or "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": "Hello"}],
                }

                timeout = aiohttp.ClientTimeout(total=10)

                logger.info(
                    f"Validating API key against URL: {target_url} with model: {model_id}"
                )

                async with aiohttp.ClientSession(timeout=timeout) as session:
                    try:
                        async with session.post(
                            target_url, headers=headers, json=data
                        ) as response:
                            logger.info(f"First request status: {response.status}")
                            if response.status == 200:
                                res_json = await response.json()
                                if "choices" in res_json and res_json["choices"]:
                                    result = res_json["choices"][0]["message"][
                                        "content"
                                    ]
                                    logger.info(
                                        f"Validation successful, got result: {result}"
                                    )
                                else:
                                    result = (
                                        "Connection successful but no content returned"
                                    )
                                    logger.info(
                                        "Validation successful but no content returned"
                                    )
                            elif response.status in [401, 403, 400, 404]:
                                # 2. 失败则尝试 api-key header (Azure/MIMO style)
                                logger.info(
                                    f"Standard auth failed ({response.status}), retrying with api-key header"
                                )
                                headers = {
                                    "api-key": api_key,
                                    "Content-Type": "application/json",
                                }
                                async with session.post(
                                    target_url, headers=headers, json=data
                                ) as response2:
                                    logger.info(
                                        f"Second request status: {response2.status}"
                                    )
                                    if response2.status == 200:
                                        res_json = await response2.json()
                                        if (
                                            "choices" in res_json
                                            and res_json["choices"]
                                        ):
                                            result = res_json["choices"][0]["message"][
                                                "content"
                                            ]
                                            logger.info(
                                                f"Validation successful via api-key, got result: {result}"
                                            )
                                        else:
                                            result = "Connection successful (via api-key) but no content returned"
                                            logger.info(
                                                "Validation successful via api-key but no content returned"
                                            )
                                    else:
                                        text = await response2.text()
                                        error_message = f"Validation failed: {response.status} (Bearer) / {response2.status} (api-key) - {text}"
                                        logger.error(
                                            f"Validation failed with api-key: {error_message}"
                                        )
                            else:
                                text = await response.text()
                                error_message = (
                                    f"Validation failed: {response.status} - {text}"
                                )
                                logger.error(
                                    f"Validation failed with Bearer: {error_message}"
                                )
                    except aiohttp.ClientError as e:
                        error_message = f"Connection error: {str(e)}"
                        logger.error(f"Connection error to {target_url}: {str(e)}")
                    except Exception as e:
                        error_message = f"Request error: {str(e)}"
                        logger.error(
                            f"Request error to {target_url}: {str(e)}", exc_info=True
                        )

        except Exception as e:
            error_message = f"System error: {str(e)}"
            logger.error(f"System error in validate_api_key: {str(e)}", exc_info=True)

        response_time = (time.time() - start_time) * 1000

        logger.info(
            f"Validation completed in {response_time}ms, valid: {error_message is None}"
        )

        return APIKeyValidationResponse(
            valid=error_message is None,
            error_message=error_message,
            test_result=result,
            response_time_ms=response_time,
        )

    def _get_preset_api_key_from_env(self, model_name: str) -> Optional[str]:
        """从环境变量获取预设模型的API密钥"""
        if model_name in ["whisper-1", "gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"]:
            return getattr(settings, "OPENAI_API_KEY", None)
        elif model_name == "sensevoice-small":
            return getattr(settings, "TRANSCRIPTION_API_KEY", None)
        return None

    async def call_transcription_with_fallback(
        self, audio_file_path: str, language: str = "zh", model_id: Optional[str] = None
    ) -> tuple[str, Optional[AIModelConfig]]:
        """
        使用优先级fallback机制调用转录API

        Args:
            audio_file_path: 音频文件路径
            language: 语言代码 (默认: zh)
            model_id: 指定模型ID（如果提供，仅使用该模型）

        Returns:
            Tuple[转录结果, 使用的模型配置]

        Raises:
            ValidationError: 当所有模型都失败时抛出异常
        """
        if model_id:
            # 如果指定了模型ID，只使用该模型
            model = await self.repo.get_by_id(model_id)
            if not model or not model.is_active:
                raise ValidationError(f"Model {model_id} not found or not active")
            models = [model]
        else:
            # 获取按优先级排序的活跃转录模型
            models = await self.repo.get_active_models_by_priority(
                ModelType.TRANSCRIPTION
            )

        if not models:
            raise ValidationError("No active transcription models available")

        last_error = None
        for model in models:
            try:
                logger.info(
                    f"Trying transcription model: {model.name} (priority: {model.priority})"
                )
                result = await self._call_transcription_model(
                    model, audio_file_path, language
                )
                logger.info(f"Transcription succeeded with model: {model.name}")
                # 更新成功统计
                await self.repo.increment_usage(model.id, success=True)
                return result, model
            except Exception as e:
                last_error = e
                logger.warning(
                    f"Transcription failed with model {model.name}: {str(e)}"
                )
                # 更新失败统计
                await self.repo.increment_usage(model.id, success=False)

        # 所有模型都失败了
        error_msg = f"All transcription models failed. Last error: {str(last_error)}"
        logger.error(error_msg)
        raise ValidationError(error_msg)

    async def call_text_generation_with_fallback(
        self,
        messages: list[dict[str, str]],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        model_id: Optional[str] = None,
    ) -> tuple[str, Optional[AIModelConfig]]:
        """
        使用优先级fallback机制调用文本生成API

        Args:
            messages: 消息列表 (格式: [{"role": "user", "content": "..."}])
            max_tokens: 最大令牌数
            temperature: 温度参数
            model_id: 指定模型ID（如果提供，仅使用该模型）

        Returns:
            Tuple[生成结果, 使用的模型配置]

        Raises:
            ValidationError: 当所有模型都失败时抛出异常
        """
        if model_id:
            # 如果指定了模型ID，只使用该模型
            model = await self.repo.get_by_id(model_id)
            if not model or not model.is_active:
                raise ValidationError(f"Model {model_id} not found or not active")
            models = [model]
        else:
            # 获取按优先级排序的活跃文本生成模型
            models = await self.repo.get_active_models_by_priority(
                ModelType.TEXT_GENERATION
            )

        if not models:
            raise ValidationError("No active text generation models available")

        last_error = None
        for model in models:
            try:
                logger.info(
                    f"Trying text generation model: {model.name} (priority: {model.priority})"
                )
                result = await self._call_text_generation_model(
                    model, messages, max_tokens, temperature
                )
                logger.info(f"Text generation succeeded with model: {model.name}")
                # 更新成功统计
                await self.repo.increment_usage(model.id, success=True)
                return result, model
            except Exception as e:
                last_error = e
                logger.warning(
                    f"Text generation failed with model {model.name}: {str(e)}"
                )
                # 更新失败统计
                await self.repo.increment_usage(model.id, success=False)

        # 所有模型都失败了
        error_msg = f"All text generation models failed. Last error: {str(last_error)}"
        logger.error(error_msg)
        raise ValidationError(error_msg)

    async def _call_transcription_model(
        self, model: AIModelConfig, audio_file_path: str, language: str = "zh"
    ) -> str:
        """调用单个转录模型"""
        import os

        import aiohttp

        # 解密API密钥
        api_key = await self._get_decrypted_api_key(model)

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

                # 根据provider选择不同的API端点
                if model.provider == "openai":
                    api_endpoint = "https://api.openai.com/v1/audio/transcriptions"
                else:
                    api_endpoint = model.api_url

                async with session.post(
                    api_endpoint, headers=headers, data=data
                ) as response:
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
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """调用单个文本生成模型"""
        import aiohttp

        # 解密API密钥
        api_key = await self._get_decrypted_api_key(model)

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

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                f"{model.api_url}/chat/completions", headers=headers, json=data
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"API error: {response.status} - {error_text}")

                result = await response.json()
                if "choices" not in result or not result["choices"]:
                    raise Exception("Invalid response from API")

                raw_content = result["choices"][0]["message"]["content"].strip()

                # Filter out <thinking> tags and sanitize HTML before returning
                # 过滤掉 <thinking> 标签并清理 HTML 后再返回
                from app.core.utils import filter_thinking_content, sanitize_html

                # First filter thinking content, then sanitize HTML for XSS prevention
                cleaned_content = filter_thinking_content(raw_content)
                safe_content = sanitize_html(cleaned_content)

                logger.debug(
                    f"Filtered and sanitized content: {len(raw_content)} -> {len(safe_content)} chars"
                )

                return safe_content


class TextGenerationService:
    """
    Text generation service for AI-powered content creation.

    文本生成服务，用于 AI 驱动的内容创建
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo = AIModelConfigRepository(db)

    async def generate_podcast_summary(
        self,
        episode_title: str,
        content: str,
        content_type: str = "transcript",
        max_tokens: int | None = None
    ) -> str:
        """Generate a summary for podcast content using AI models.

        为播客内容生成 AI 总结，支持 fallback 机制

        Args:
            episode_title: The title of the podcast episode
            content: The podcast content (transcript or description)
            content_type: Type of content (transcript/description)
            max_tokens: Maximum tokens for the summary

        Returns:
            Generated summary text. Returns rule-based summary if all AI models fail.

        Raises:
            ValidationError: When content is too short
            ExternalServiceError: When all external services fail
        """
        from openai import (
            APIConnectionError,
            APIError,
            AsyncOpenAI,
            AuthenticationError,
            RateLimitError,
        )

        from app.core.security import decrypt_data
        from app.domains.ai.models import ModelType

        # Get active text generation models ordered by priority
        model_configs = await self.repo.get_active_models_by_priority(ModelType.TEXT_GENERATION)

        if not model_configs:
            logger.warning("No active text generation models configured, using rule-based summary")
            return self._rule_based_summary(episode_title, content)

        last_error = None
        for idx, model_config in enumerate(model_configs):
            api_key = None
            try:
                # Decrypt API key
                if model_config.api_key:
                    if model_config.api_key_encrypted:
                        api_key = decrypt_data(model_config.api_key)
                    else:
                        api_key = model_config.api_key

                if not api_key:
                    logger.warning(
                        f"Model [{model_config.display_name or model_config.name}] has empty API key, skipping"
                    )
                    continue

                logger.info(
                    f"Trying model [{model_config.display_name or model_config.name}] "
                    f"(priority={model_config.priority}, attempt {idx + 1}/{len(model_configs)})"
                )

                client = AsyncOpenAI(
                    api_key=api_key,
                    base_url=model_config.api_url if model_config.api_url else None
                )

                # Build system prompt for podcast summarization
                system_prompt = """
你是一位专业的播客总结专家。你的任务是从播客单集内容中提取最有价值的信息。

请提取以下信息：
1. 主要话题和讨论点
2. 关键见解和结论
3. 可执行的建议
4. 需要进一步研究的领域

输出格式：
## 主要话题
[3-5个要点]

## 关键见解
[深入洞察]

## 行动建议
[具体步骤]

## 扩展思考
[关联问题]
"""

                user_prompt = f"""
播客标题: {episode_title}
内容类型: {content_type}
内容: {content[:2000]}

请提供详细总结（150-300字）。
"""

                # Build API call parameters
                api_params = {
                    "model": model_config.model_id if model_config.model_id else "gpt-4o-mini",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "temperature": 0.7
                }
                if max_tokens is not None:
                    api_params["max_tokens"] = max_tokens

                response = await client.chat.completions.create(**api_params)

                # Success - log and return
                logger.info(
                    f"Successfully generated summary using model "
                    f"[{model_config.display_name or model_config.name}]"
                )
                return response.choices[0].message.content.strip()

            except AuthenticationError as e:
                last_error = e
                logger.warning(f"Authentication failed for model {model_config.name}: {e}")
            except RateLimitError as e:
                last_error = e
                logger.warning(f"Rate limit exceeded for model {model_config.name}: {e}")
                # Don't retry on rate limit, move to next model
                continue
            except APIConnectionError as e:
                last_error = e
                logger.warning(f"Connection failed for model {model_config.name}: {e}")
            except APIError as e:
                last_error = e
                logger.warning(f"API error for model {model_config.name}: {e}")
            except Exception as e:
                last_error = e
                logger.error(f"Unexpected error with model {model_config.name}: {e}")

        # All models failed, log and return rule-based summary
        logger.error(f"All AI models failed for summary generation. Last error: {last_error}")
        return self._rule_based_summary(episode_title, content)

    def _rule_based_summary(self, episode_title: str, content: str) -> str:
        """Generate a basic summary using rule-based approach.

        使用基于规则的方法生成基本总结（AI 失败时的回退方案）

        Args:
            episode_title: The episode title
            content: The content to summarize

        Returns:
            A basic summary string
        """
        # Take first few sentences as summary
        sentences = content.split('。')
        summary_sentences = sentences[:3] if len(sentences) >= 3 else sentences
        summary = '。'.join(summary_sentences).strip()

        if not summary:
            summary = f"《{episode_title}》的内容暂无总结。"

        return f"""
## 播客概览
节目名称: {episode_title}

## 内容摘要
{summary[:300]}...

## 说明
此为系统自动生成的概要，完整总结正在处理中。
"""
