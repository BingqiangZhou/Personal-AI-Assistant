"""
AI模型配置的Pydantic模式定义
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator

from app.domains.ai.models import ModelType


# 基础模式
class AIModelConfigBase(BaseModel):
    """AI模型配置基础模式"""
    name: str = Field(..., min_length=1, max_length=100, description="模型名称")
    display_name: str = Field(..., min_length=1, max_length=200, description="显示名称")
    description: Optional[str] = Field(None, description="模型描述")
    model_type: ModelType = Field(..., description="模型类型")
    api_url: str = Field(..., min_length=1, max_length=500, description="API端点URL")
    api_key: Optional[str] = Field(None, max_length=500, description="API密钥")
    model_id: str = Field(..., min_length=1, max_length=200, description="模型标识符")
    provider: str = Field(default="custom", max_length=100, description="提供商")
    max_tokens: Optional[int] = Field(None, gt=0, description="最大令牌数")
    temperature: Optional[str] = Field(None, description="温度参数")
    timeout_seconds: int = Field(default=300, gt=0, description="请求超时时间（秒）")
    max_retries: int = Field(default=3, ge=0, description="最大重试次数")
    max_concurrent_requests: int = Field(default=1, gt=0, description="最大并发请求数")
    rate_limit_per_minute: int = Field(default=60, gt=0, description="每分钟请求限制")
    cost_per_input_token: Optional[str] = Field(None, description="每输入令牌成本")
    cost_per_output_token: Optional[str] = Field(None, description="每输出令牌成本")
    extra_config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="额外配置参数")
    is_active: bool = Field(default=True, description="是否启用")
    is_default: bool = Field(default=False, description="是否为默认模型")

    @validator('temperature')
    def validate_temperature(cls, v):
        if v is not None:
            try:
                temp = float(v)
                if not 0 <= temp <= 2:
                    raise ValueError('温度参数必须在0-2之间')
            except ValueError:
                raise ValueError('温度参数必须是数字')
        return v

    @validator('cost_per_input_token', 'cost_per_output_token')
    def validate_cost(cls, v):
        if v is not None:
            try:
                float(v)
                if float(v) < 0:
                    raise ValueError('成本不能为负数')
            except ValueError:
                raise ValueError('成本必须是数字')
        return v


# 请求模式
class AIModelConfigCreate(AIModelConfigBase):
    """创建AI模型配置请求模式"""
    pass


class AIModelConfigUpdate(BaseModel):
    """更新AI模型配置请求模式"""
    display_name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    api_url: Optional[str] = Field(None, min_length=1, max_length=500)
    api_key: Optional[str] = Field(None, max_length=500)
    model_id: Optional[str] = Field(None, min_length=1, max_length=200)
    max_tokens: Optional[int] = Field(None, gt=0)
    temperature: Optional[str] = None
    timeout_seconds: Optional[int] = Field(None, gt=0)
    max_retries: Optional[int] = Field(None, ge=0)
    max_concurrent_requests: Optional[int] = Field(None, gt=0)
    rate_limit_per_minute: Optional[int] = Field(None, gt=0)
    cost_per_input_token: Optional[str] = None
    cost_per_output_token: Optional[str] = None
    extra_config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None
    is_default: Optional[bool] = None

    @validator('temperature')
    def validate_temperature(cls, v):
        if v is not None:
            try:
                temp = float(v)
                if not 0 <= temp <= 2:
                    raise ValueError('温度参数必须在0-2之间')
            except ValueError:
                raise ValueError('温度参数必须是数字')
        return v

    @validator('cost_per_input_token', 'cost_per_output_token')
    def validate_cost(cls, v):
        if v is not None:
            try:
                float(v)
                if float(v) < 0:
                    raise ValueError('成本不能为负数')
            except ValueError:
                raise ValueError('成本必须是数字')
        return v


# 响应模式
class AIModelConfigResponse(AIModelConfigBase):
    """AI模型配置响应模式"""
    id: int
    api_key_encrypted: bool
    usage_count: int
    success_count: int
    error_count: int
    total_tokens_used: int
    success_rate: float = 0.0  # 默认值，避免from_orm失败
    created_at: datetime
    updated_at: datetime
    last_used_at: Optional[datetime] = None
    is_system: bool = False

    class Config:
        from_attributes = True


class AIModelConfigList(BaseModel):
    """AI模型配置列表响应模式"""
    models: List[AIModelConfigResponse]
    total: int
    page: int
    size: int
    pages: int


# 统计模式
class ModelUsageStats(BaseModel):
    """模型使用统计模式"""
    model_id: int
    model_name: str
    model_type: str
    usage_count: int
    success_count: int
    error_count: int
    success_rate: float
    total_tokens_used: int
    last_used_at: Optional[datetime]
    total_cost: Optional[float] = None


# 测试模式
class ModelTestRequest(BaseModel):
    """模型测试请求模式"""
    model_id: int
    test_data: Optional[Dict[str, Any]] = Field(default=dict, description="测试数据")


class ModelTestResponse(BaseModel):
    """模型测试响应模式"""
    success: bool
    response_time_ms: float
    result: Optional[str] = None
    error_message: Optional[str] = None


# 预设模型配置
class PresetModelConfig(BaseModel):
    """预设模型配置"""
    name: str
    display_name: str
    description: str
    model_type: ModelType
    provider: str
    model_id: str
    api_url: str
    max_tokens: Optional[int] = None
    temperature: Optional[str] = None
    extra_config: Optional[Dict[str, Any]] = None


# 导出配置
class ModelExportConfig(BaseModel):
    """模型配置导出格式"""
    models: List[Dict[str, Any]]
    export_time: datetime
    version: str = "1.0"


class ModelImportConfig(BaseModel):
    """模型配置导入格式"""
    models: List[AIModelConfigCreate]
    overwrite_existing: bool = Field(default=False, description="是否覆盖已存在的模型")
    mark_as_system: bool = Field(default=False, description="是否标记为系统预设")


# API密钥验证
class APIKeyValidationRequest(BaseModel):
    """API密钥验证请求"""
    api_url: str
    api_key: str
    model_id: Optional[str] = None
    model_type: ModelType


class APIKeyValidationResponse(BaseModel):
    """API密钥验证响应"""
    valid: bool
    error_message: Optional[str] = None
    test_result: Optional[str] = None
    response_time_ms: float