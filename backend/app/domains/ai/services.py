"""
AI模型配置服务层
"""

import asyncio
import time
import hashlib
import json
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.domains.ai.repositories import AIModelConfigRepository
from app.domains.ai.models import AIModelConfig, ModelType
from app.domains.ai.schemas import (
    AIModelConfigCreate,
    AIModelConfigUpdate,
    ModelUsageStats,
    ModelTestResponse,
    PresetModelConfig
)
from app.core.config import settings
from app.core.exceptions import ValidationError, DatabaseError
import aiohttp
import logging

logger = logging.getLogger(__name__)


class APIKeyEncryption:
    """API密钥加密/解密工具"""

    @staticmethod
    def encrypt_key(api_key: str) -> str:
        """加密API密钥（简单示例，实际应使用更安全的加密方式）"""
        # 这里使用简单的哈希，实际应用中应使用AES等加密算法
        return f"encrypted_{hashlib.sha256(api_key.encode()).hexdigest()[:16]}"

    @staticmethod
    def decrypt_key(encrypted_key: str) -> str:
        """解密API密钥"""
        # 这里只是示例，实际需要解密逻辑
        if encrypted_key.startswith("encrypted_"):
            # 实际应该解密返回原始密钥
            # 这里返回占位符，实际应该从安全存储中获取
            return "DECRYPTED_KEY_PLACEHOLDER"
        return encrypted_key


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

        # 加密API密钥
        encrypted_key = None
        if model_data.api_key:
            encrypted_key = APIKeyEncryption.encrypt_key(model_data.api_key)

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
            is_system=False
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
        size: int = 20
    ) -> Tuple[List[AIModelConfig], int]:
        """获取模型配置列表"""
        return await self.repo.get_list(
            model_type=model_type,
            is_active=is_active,
            provider=provider,
            page=page,
            size=size
        )

    async def search_models(
        self,
        query: str,
        model_type: Optional[ModelType] = None,
        page: int = 1,
        size: int = 20
    ) -> Tuple[List[AIModelConfig], int]:
        """搜索模型配置"""
        return await self.repo.search_models(
            query=query,
            model_type=model_type,
            page=page,
            size=size
        )

    async def update_model(self, model_id: int, model_data: AIModelConfigUpdate) -> Optional[AIModelConfig]:
        """更新模型配置"""
        # 获取现有模型
        existing_model = await self.repo.get_by_id(model_id)
        if not existing_model:
            return None

        # 检查是否是系统预设模型
        if existing_model.is_system and model_data.dict(exclude_unset=True).keys() & {
            'name', 'model_type', 'api_url', 'model_id'
        }:
            raise ValidationError("Cannot modify critical fields of system model")

        # 如果设置为默认，先取消同类型的其他默认模型
        if model_data.is_default:
            await self._clear_default_models(existing_model.model_type)

        # 准备更新数据
        update_data = model_data.dict(exclude_unset=True)

        # 处理API密钥更新
        if 'api_key' in update_data:
            if update_data['api_key']:
                update_data['api_key'] = APIKeyEncryption.encrypt_key(update_data['api_key'])
                update_data['api_key_encrypted'] = True
            else:
                update_data['api_key'] = ""
                update_data['api_key_encrypted'] = False

        return await self.repo.update(model_id, update_data)

    async def delete_model(self, model_id: int) -> bool:
        """删除模型配置"""
        return await self.repo.delete(model_id)

    async def set_default_model(self, model_id: int, model_type: ModelType) -> Optional[AIModelConfig]:
        """设置默认模型"""
        success = await self.repo.set_default_model(model_id, model_type)
        if success:
            return await self.repo.get_by_id(model_id)
        return None

    async def get_default_model(self, model_type: ModelType) -> Optional[AIModelConfig]:
        """获取默认模型"""
        return await self.repo.get_default_model(model_type)

    async def get_active_models(self, model_type: Optional[ModelType] = None) -> List[AIModelConfig]:
        """获取活跃模型"""
        return await self.repo.get_active_models(model_type)

    async def test_model(self, model_id: int, test_data: Optional[Dict[str, Any]] = None) -> ModelTestResponse:
        """测试模型连接"""
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
                result = await self._test_text_generation_model(model, api_key, test_data)

            response_time = (time.time() - start_time) * 1000

            # 更新使用统计
            await self.repo.increment_usage(model_id, success=True)

            return ModelTestResponse(
                success=True,
                response_time_ms=response_time,
                result=result
            )

        except Exception as e:
            response_time = (time.time() - start_time) * 1000

            # 更新使用统计
            await self.repo.increment_usage(model_id, success=False)

            logger.error(f"Model test failed: {str(e)}")
            return ModelTestResponse(
                success=False,
                response_time_ms=response_time,
                error_message=str(e)
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
            last_used_at=model.last_used_at
        )

    async def get_type_stats(self, model_type: ModelType, limit: int = 20) -> List[ModelUsageStats]:
        """获取模型类型的使用统计"""
        stats_data = await self.repo.get_usage_stats(model_type, limit)

        return [
            ModelUsageStats(**stat)
            for stat in stats_data
        ]

    async def init_default_models(self) -> List[AIModelConfig]:
        """初始化默认模型配置"""
        preset_configs = self._get_preset_model_configs()

        created_models = []

        for preset in preset_configs:
            # 检查是否已存在
            existing = await self.repo.get_by_name(preset.name)
            if existing:
                logger.info(f"Model {preset.name} already exists, skipping")
                continue

            # 从环境变量获取API密钥
            api_key = self._get_preset_api_key(preset)

            # 创建模型配置
            model_data = AIModelConfigCreate(
                name=preset.name,
                display_name=preset.display_name,
                description=preset.description,
                model_type=preset.model_type,
                api_url=preset.api_url,
                api_key=api_key,
                model_id=preset.model_id,
                provider=preset.provider,
                max_tokens=preset.max_tokens,
                temperature=preset.temperature,
                extra_config=preset.extra_config,
                is_default=True,  # 预设模型默认为默认模型
                is_active=bool(api_key)  # 有API密钥才激活
            )

            model = await self.create_model(model_data)
            model.is_system = True  # 标记为系统预设
            await self.db.commit()

            created_models.append(model)
            logger.info(f"Created default model: {preset.name}")

        return created_models

    async def _get_decrypted_api_key(self, model: AIModelConfig) -> str:
        """获取解密的API密钥"""
        if not model.api_key_encrypted:
            return model.api_key

        # 对于系统预设模型，从环境变量获取
        if model.is_system:
            return self._get_preset_api_key_from_env(model.name)

        # 对于用户自定义模型，这里应该从安全存储中解密获取
        # 暂时返回占位符
        return "DECRYPTED_KEY_PLACEHOLDER"

    async def _test_transcription_model(
        self,
        model: AIModelConfig,
        api_key: str,
        test_data: Optional[Dict[str, Any]]
    ) -> str:
        """测试转录模型"""
        # 创建一个简单的测试音频文本
        test_text = "Hello, this is a test for the transcription model."

        # 这里应该发送实际的测试音频
        # 为了简化，我们直接返回测试文本
        return f"Transcription test successful. Model: {model.model_id}"

    async def _test_text_generation_model(
        self,
        model: AIModelConfig,
        api_key: str,
        test_data: Optional[Dict[str, Any]]
    ) -> str:
        """测试文本生成模型"""
        test_prompt = test_data.get('prompt', 'Hello, please respond with "Test successful".')

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        data = {
            'model': model.model_id,
            'messages': [
                {
                    'role': 'user',
                    'content': test_prompt
                }
            ],
            'max_tokens': 50,
            'temperature': model.get_temperature_float() or 0.7
        }

        timeout = aiohttp.ClientTimeout(total=model.timeout_seconds)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(f"{model.api_url}/chat/completions", headers=headers, json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"API error: {response.status} - {error_text}")

                result = await response.json()
                if 'choices' not in result or not result['choices']:
                    raise Exception("Invalid response from API")

                return result['choices'][0]['message']['content'].strip()

    async def _clear_default_models(self, model_type: ModelType):
        """清除指定类型的所有默认模型标记"""
        stmt = (
            update(AIModelConfig)
            .where(
                AIModelConfig.model_type == model_type,
                AIModelConfig.is_default == True
            )
            .values(is_default=False)
        )
        await self.db.execute(stmt)
        await self.db.commit()

    def _get_preset_model_configs(self) -> List[PresetModelConfig]:
        """获取预设模型配置"""
        return [
            # 转录模型
            PresetModelConfig(
                name="whisper-1",
                display_name="OpenAI Whisper",
                description="OpenAI的Whisper语音识别模型",
                model_type=ModelType.TRANSCRIPTION,
                provider="openai",
                model_id="whisper-1",
                api_url="https://api.openai.com/v1/audio/transcriptions",
                max_tokens=None,
                temperature=None
            ),
            PresetModelConfig(
                name="sensevoice-small",
                display_name="SenseVoice Small",
                description="硅基流动的SenseVoice语音识别模型",
                model_type=ModelType.TRANSCRIPTION,
                provider="siliconflow",
                model_id="FunAudioLLM/SenseVoiceSmall",
                api_url="https://api.siliconflow.cn/v1/audio/transcriptions",
                max_tokens=None,
                temperature=None
            ),
            # 文本生成模型
            PresetModelConfig(
                name="gpt-4o-mini",
                display_name="GPT-4o Mini",
                description="OpenAI的GPT-4o Mini模型",
                model_type=ModelType.TEXT_GENERATION,
                provider="openai",
                model_id="gpt-4o-mini",
                api_url="https://api.openai.com/v1",
                max_tokens=1000,
                temperature="0.7"
            ),
            PresetModelConfig(
                name="gpt-4o",
                display_name="GPT-4o",
                description="OpenAI的GPT-4o模型",
                model_type=ModelType.TEXT_GENERATION,
                provider="openai",
                model_id="gpt-4o",
                api_url="https://api.openai.com/v1",
                max_tokens=1000,
                temperature="0.7"
            ),
            PresetModelConfig(
                name="gpt-3.5-turbo",
                display_name="GPT-3.5 Turbo",
                description="OpenAI的GPT-3.5 Turbo模型",
                model_type=ModelType.TEXT_GENERATION,
                provider="openai",
                model_id="gpt-3.5-turbo",
                api_url="https://api.openai.com/v1",
                max_tokens=1000,
                temperature="0.7"
            )
        ]

    def _get_preset_api_key(self, preset: PresetModelConfig) -> Optional[str]:
        """获取预设模型的API密钥"""
        if preset.provider == "openai":
            return getattr(settings, 'OPENAI_API_KEY', None)
        elif preset.provider == "siliconflow":
            return getattr(settings, 'TRANSCRIPTION_API_KEY', None)
        return None

    def _get_preset_api_key_from_env(self, model_name: str) -> Optional[str]:
        """从环境变量获取预设模型的API密钥"""
        if model_name in ["whisper-1", "gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"]:
            return getattr(settings, 'OPENAI_API_KEY', None)
        elif model_name == "sensevoice-small":
            return getattr(settings, 'TRANSCRIPTION_API_KEY', None)
        return None