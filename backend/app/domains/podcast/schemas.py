"""
播客相关的Pydantic schemas - API请求和响应模型
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict


# === Base Schemas ===

class PodcastBaseSchema(BaseModel):
    """播客基础schema"""
    model_config = ConfigDict(from_attributes=True)


class PodcastTimestampedSchema(PodcastBaseSchema):
    """带时间戳的播客schema"""
    created_at: datetime
    updated_at: Optional[datetime] = None


# === Subscription相关 ===

class PodcastSubscriptionCreate(PodcastBaseSchema):
    """创建播客订阅请求"""
    feed_url: str = Field(..., description="RSS feed URL", min_length=10, max_length=500)
    category_ids: Optional[List[int]] = Field(default_factory=list, description="分类ID列表")

    @field_validator('feed_url')
    @classmethod
    def validate_feed_url(cls, v):
        """验证RSS feed URL格式"""
        if not v.startswith(('http://', 'https://')):
            raise ValueError('Feed URL必须以http://或https://开头')
        if 'rss' not in v.lower() and 'feed' not in v.lower():
            # 不强制要求URL中包含rss或feed，但给出警告
            pass
        return v


class PodcastSubscriptionUpdate(PodcastBaseSchema):
    """更新播客订阅请求"""
    custom_name: Optional[str] = Field(None, max_length=255)
    fetch_interval: Optional[int] = Field(None, ge=300, le=86400, description="抓取间隔(秒)")
    is_active: Optional[bool] = None
    category_ids: Optional[List[int]] = None


class PodcastSubscriptionResponse(PodcastTimestampedSchema):
    """播客订阅响应"""
    id: int
    user_id: int
    title: str
    description: Optional[str] = None
    source_url: str
    status: str
    last_fetched_at: Optional[datetime] = None
    error_message: Optional[str] = None
    fetch_interval: Optional[int] = None
    episode_count: Optional[int] = 0
    unplayed_count: Optional[int] = 0
    latest_episode: Optional[Dict[str, Any]] = None
    categories: Optional[List[Dict[str, Any]]] = []
    image_url: Optional[str] = None
    author: Optional[str] = None

    @field_validator('categories', mode='before')
    @classmethod
    def validate_categories(cls, v):
        """处理categories字段，支持字符串列表和字典列表"""
        if not v:
            return []

        # 确保v是列表
        if isinstance(v, str):
            # 如果是单个字符串，转换为列表
            v = [v]
        elif not isinstance(v, list):
            # 如果不是列表，尝试转换
            v = [str(v)]

        result = []
        for item in v:
            if isinstance(item, str):
                result.append({"name": item})
            elif isinstance(item, dict):
                result.append(item)
            else:
                result.append({"name": str(item)})
        return result

    @model_validator(mode='before')
    @classmethod
    def validate_all_fields(cls, data):
        """对所有字段进行预验证"""
        if isinstance(data, dict):
            # 特别处理categories字段
            if 'categories' in data:
                categories = data['categories']
                if categories:
                    # 确保categories是字典列表格式
                    processed_categories = []
                    if isinstance(categories, list):
                        for cat in categories:
                            if isinstance(cat, str):
                                processed_categories.append({"name": cat})
                            elif isinstance(cat, dict):
                                processed_categories.append(cat)
                            else:
                                processed_categories.append({"name": str(cat)})
                        data['categories'] = processed_categories
                    elif isinstance(categories, str):
                        data['categories'] = [{"name": categories}]
                    else:
                        data['categories'] = [{"name": str(categories)}]
        return data


class PodcastSubscriptionListResponse(PodcastBaseSchema):
    """播客订阅列表响应"""
    subscriptions: List[PodcastSubscriptionResponse]
    total: int
    page: int
    size: int
    pages: int


# === Episode相关 ===

class PodcastEpisodeResponse(PodcastTimestampedSchema):
    """播客单集响应"""
    id: int
    subscription_id: int
    title: str
    description: Optional[str] = None
    audio_url: str
    audio_duration: Optional[int] = None
    audio_file_size: Optional[int] = None
    published_at: datetime
    image_url: Optional[str] = None
    subscription_image_url: Optional[str] = None
    transcript_url: Optional[str] = None
    transcript_content: Optional[str] = None
    ai_summary: Optional[str] = None
    summary_version: Optional[str] = None
    ai_confidence_score: Optional[float] = None
    play_count: int = 0
    last_played_at: Optional[datetime] = None
    season: Optional[int] = None
    episode_number: Optional[int] = None
    explicit: bool = False
    status: str
    metadata: Optional[Dict[str, Any]] = {}

    # 播放状态（如果用户有收听记录）
    subscription_title: Optional[str] = None
    playback_position: Optional[int] = None
    is_playing: bool = False
    playback_rate: float = 1.0
    is_played: Optional[bool] = None


class PodcastEpisodeListResponse(PodcastBaseSchema):
    """播客单集列表响应"""
    episodes: List[PodcastEpisodeResponse]
    total: int
    page: int
    size: int
    pages: int
    subscription_id: int


class PodcastEpisodeDetailResponse(PodcastEpisodeResponse):
    """播客单集详情响应（包含更多信息）"""
    subscription: Optional[Dict[str, Any]] = None
    related_episodes: Optional[List[Dict[str, Any]]] = []


class PodcastFeedResponse(PodcastBaseSchema):
    """播客信息流响应"""
    items: List[PodcastEpisodeResponse]
    has_more: bool
    next_page: Optional[int] = None
    total: int


# === Playback相关 ===

class PodcastPlaybackUpdate(PodcastBaseSchema):
    """播放进度更新请求"""
    position: int = Field(..., ge=0, description="当前播放位置(秒)")
    is_playing: bool = Field(default=False, description="是否正在播放")
    playback_rate: float = Field(default=1.0, ge=0.5, le=3.0, description="播放倍速")


class PodcastPlaybackStateResponse(PodcastBaseSchema):
    """播放状态响应"""
    episode_id: int
    current_position: int
    is_playing: bool
    playback_rate: float
    play_count: int
    last_updated_at: datetime

    # 计算字段
    progress_percentage: float = Field(description="播放进度百分比")
    remaining_time: int = Field(description="剩余时间(秒)")


# === Category相关 ===

class PodcastCategoryCreate(PodcastBaseSchema):
    """创建播客分类请求"""
    name: str = Field(..., min_length=1, max_length=100, description="分类名称")
    description: Optional[str] = Field(None, max_length=500, description="分类描述")
    color: Optional[str] = Field(None, pattern=r'^#[0-9A-Fa-f]{6}$', description="十六进制颜色代码")


class PodcastCategoryUpdate(PodcastBaseSchema):
    """更新播客分类请求"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    color: Optional[str] = Field(None, pattern=r'^#[0-9A-Fa-f]{6}$')


class PodcastCategoryResponse(PodcastTimestampedSchema):
    """播客分类响应"""
    id: int
    user_id: int
    name: str
    description: Optional[str] = None
    color: Optional[str] = None
    subscription_count: Optional[int] = 0


# === Summary相关 ===

class PodcastSummaryRequest(PodcastBaseSchema):
    """生成AI总结请求"""
    force_regenerate: bool = Field(default=False, description="是否强制重新生成")
    use_transcript: Optional[bool] = Field(None, description="是否使用转录文本（如果有）")
    summary_model: Optional[str] = Field(None, description="AI总结模型名称")
    custom_prompt: Optional[str] = Field(None, description="自定义提示词")


class PodcastSummaryResponse(PodcastBaseSchema):
    """AI总结响应"""
    episode_id: int
    summary: str
    version: str
    confidence_score: Optional[float] = None
    transcript_used: bool
    generated_at: datetime
    word_count: int
    model_used: Optional[str] = None  # 使用的模型名称
    processing_time: Optional[float] = None  # 处理时间（秒）


class SummaryModelInfo(PodcastBaseSchema):
    """AI总结模型信息"""
    id: int
    name: str
    display_name: str
    provider: str
    model_id: str
    is_default: bool


class SummaryModelsResponse(PodcastBaseSchema):
    """可用总结模型列表响应"""
    models: List[SummaryModelInfo]
    total: int


class PodcastSummaryPendingResponse(PodcastBaseSchema):
    """待总结列表响应"""
    count: int
    episodes: List[Dict[str, Any]]


# === Search/Filter相关 ===

class PodcastSearchFilter(PodcastBaseSchema):
    """播客搜索过滤器"""
    query: Optional[str] = Field(None, description="搜索关键词")
    category_id: Optional[int] = Field(None, description="分类ID")
    status: Optional[str] = Field(None, description="状态筛选")
    has_summary: Optional[bool] = Field(None, description="是否有AI总结")
    date_from: Optional[datetime] = Field(None, description="开始日期")
    date_to: Optional[datetime] = Field(None, description="结束日期")


class PodcastEpisodeFilter(PodcastSearchFilter):
    """播客单集过滤器"""
    subscription_id: Optional[int] = Field(None, description="订阅ID")
    is_played: Optional[bool] = Field(None, description="是否已播放")
    duration_min: Optional[int] = Field(None, ge=0, description="最小时长(秒)")
    duration_max: Optional[int] = Field(None, ge=0, description="最大时长(秒)")


# === Statistics相关 ===

class PodcastStatsResponse(PodcastBaseSchema):
    """播客统计响应"""
    total_subscriptions: int
    total_episodes: int
    total_playtime: int  # 总播放时间(秒)
    summaries_generated: int
    pending_summaries: int
    recently_played: List[Dict[str, Any]]
    top_categories: List[Dict[str, Any]]
    listening_streak: int  # 连续收听天数


# === Import/Export相关 ===

class PodcastOPMLImport(PodcastBaseSchema):
    """OPML导入请求"""
    opml_content: str = Field(..., description="OPML格式内容")
    category_mapping: Optional[Dict[str, int]] = Field(default_factory=dict, description="分类映射")


class PodcastOPMLExport(PodcastBaseSchema):
    """OPML导出响应"""
    opml_content: str
    exported_at: datetime
    subscription_count: int


# === Bulk Operations相关 ===

class PodcastBulkAction(PodcastBaseSchema):
    """批量操作请求"""
    action: str = Field(..., description="操作类型: refresh, delete, mark_played, mark_unplayed")
    subscription_ids: List[int] = Field(..., description="订阅ID列表")
    episode_ids: Optional[List[int]] = Field(None, description="单集ID列表（用于单集操作）")


class PodcastBulkActionResponse(PodcastBaseSchema):
    """批量操作响应"""
    success_count: int
    failed_count: int
    errors: List[str] = []


class PodcastSubscriptionBatchResponse(PodcastBaseSchema):
    """播客批量订阅响应"""
    results: List[Dict[str, Any]]
    total_requested: int
    success_count: int
    skipped_count: int
    error_count: int


# === Transcription相关 ===

class PodcastTranscriptionRequest(PodcastBaseSchema):
    """启动转录请求"""
    force_regenerate: bool = Field(default=False, description="是否强制重新转录")
    chunk_size_mb: Optional[int] = Field(None, ge=1, le=100, description="分片大小（MB）")
    transcription_model: Optional[str] = Field(None, description="转录模型名称")


class PodcastTranscriptionResponse(PodcastBaseSchema):
    """转录任务响应"""
    id: int
    episode_id: int
    status: str
    progress_percentage: float = 0.0
    original_audio_url: str
    original_file_size: Optional[int] = None
    transcript_word_count: Optional[int] = None
    transcript_duration: Optional[int] = None
    transcript_content: Optional[str] = None  # ← 添加缺失的字段
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    download_time: Optional[float] = None
    conversion_time: Optional[float] = None
    transcription_time: Optional[float] = None
    chunk_size_mb: int = 10
    model_used: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    # AI总结信息
    summary_content: Optional[str] = None
    summary_model_used: Optional[str] = None
    summary_word_count: Optional[int] = None
    summary_processing_time: Optional[float] = None
    summary_error_message: Optional[str] = None

    # Debug info
    debug_message: Optional[str] = None

    # 计算字段
    duration_seconds: Optional[int] = None
    total_processing_time: Optional[float] = None

    # 关联信息
    episode: Optional[Dict[str, Any]] = None

    @field_validator('status', mode='before')
    @classmethod
    def validate_status(cls, v):
        """确保状态是字符串"""
        if hasattr(v, 'value'):  # 处理枚举值
            return v.value
        return str(v) if v else None


class PodcastTranscriptionDetailResponse(PodcastTranscriptionResponse):
    """转录任务详情响应"""
    chunk_info: Optional[Dict[str, Any]] = None
    transcript_content: Optional[str] = None
    original_file_path: Optional[str] = None

    # 格式化后的时间信息
    formatted_duration: Optional[str] = None
    formatted_processing_time: Optional[str] = None
    formatted_created_at: Optional[str] = None
    formatted_started_at: Optional[str] = None
    formatted_completed_at: Optional[str] = None


class PodcastTranscriptionListResponse(PodcastBaseSchema):
    """转录任务列表响应"""
    tasks: List[PodcastTranscriptionResponse]
    total: int
    page: int
    size: int
    pages: int


class PodcastTranscriptionStatusResponse(PodcastBaseSchema):
    """转录状态响应"""
    task_id: int
    episode_id: int
    status: str
    progress: float = 0.0
    message: str = ""
    current_chunk: int = 0
    total_chunks: int = 0
    eta_seconds: Optional[int] = None  # 预计剩余时间（秒）

    @field_validator('status', mode='before')
    @classmethod
    def validate_status(cls, v):
        if hasattr(v, 'value'):
            return v.value
        return str(v) if v else None


class PodcastTranscriptionChunkInfo(PodcastBaseSchema):
    """转录分片信息"""
    index: int
    start_time: float
    duration: float
    transcript: Optional[str] = None
    word_count: int = 0


# === Conversation相关 ===

class PodcastConversationMessage(PodcastBaseSchema):
    """对话消息"""
    id: int
    role: str  # 'user' or 'assistant'
    content: str
    conversation_turn: int
    created_at: str
    parent_message_id: Optional[int] = None


class PodcastConversationSendRequest(PodcastBaseSchema):
    """发送对话消息请求"""
    message: str = Field(..., min_length=1, max_length=5000, description="用户消息内容")
    model_name: Optional[str] = Field(None, description="使用的AI模型名称")


class PodcastConversationSendResponse(PodcastBaseSchema):
    """发送对话消息响应"""
    id: int
    role: str
    content: str
    conversation_turn: int
    processing_time: Optional[float] = None
    created_at: str


class PodcastConversationHistoryResponse(PodcastBaseSchema):
    """对话历史响应"""
    episode_id: int
    messages: List[PodcastConversationMessage]
    total: int


class PodcastConversationClearResponse(PodcastBaseSchema):
    """清除对话历史响应"""
    episode_id: int
    deleted_count: int

# === Schedule Configuration Schemas ===

class ScheduleConfigUpdate(BaseModel):
    """Update subscription schedule configuration"""
    update_frequency: str = Field(..., description="Update frequency: HOURLY, DAILY, WEEKLY")
    update_time: Optional[str] = Field(None, description="Update time in HH:MM format (24-hour)")
    update_day_of_week: Optional[int] = Field(None, ge=1, le=7, description="Day of week (1=Monday, 7=Sunday)")
    fetch_interval: Optional[int] = Field(None, ge=300, le=86400, description="Fetch interval in seconds (for HOURLY frequency)")

    @field_validator('update_frequency')
    @classmethod
    def validate_frequency(cls, v):
        valid_values = ['HOURLY', 'DAILY', 'WEEKLY']
        if v not in valid_values:
            raise ValueError(f'update_frequency must be one of {valid_values}')
        return v

    @field_validator('update_time')
    @classmethod
    def validate_time_format(cls, v):
        if v is not None:
            try:
                hour, minute = map(int, v.split(':'))
                if not (0 <= hour <= 23 and 0 <= minute <= 59):
                    raise ValueError('Invalid time')
            except (ValueError, AttributeError):
                raise ValueError('update_time must be in HH:MM format (24-hour)')
        return v

    @model_validator(mode='after')
    def validate_schedule_config(self):
        """Validate that required fields are present for each frequency type"""
        if self.update_frequency == 'DAILY' and not self.update_time:
            raise ValueError('update_time is required for DAILY frequency')
        if self.update_frequency == 'WEEKLY' and (not self.update_time or not self.update_day_of_week):
            raise ValueError('update_time and update_day_of_week are required for WEEKLY frequency')
        if self.update_frequency == 'HOURLY' and not self.fetch_interval:
            # Set default fetch_interval if not provided
            self.fetch_interval = 3600
        return self


class ScheduleConfigResponse(PodcastBaseSchema):
    """Schedule configuration response"""
    id: int
    title: str
    update_frequency: str
    update_time: Optional[str] = None
    update_day_of_week: Optional[int] = None
    fetch_interval: Optional[int] = None
    next_update_at: Optional[datetime] = None
    last_updated_at: Optional[datetime] = None


# === Bulk Delete Schemas ===

class PodcastSubscriptionBulkDelete(PodcastBaseSchema):
    """批量删除播客订阅请求"""
    subscription_ids: List[int] = Field(..., description="订阅ID列表", min_length=1, max_length=100)

    @field_validator('subscription_ids')
    @classmethod
    def validate_subscription_ids(cls, v):
        """验证订阅ID列表"""
        if not v:
            raise ValueError('订阅ID列表不能为空')
        if len(v) > 100:
            raise ValueError('一次最多删除100个订阅')
        # 去重
        unique_ids = list(set(v))
        if len(unique_ids) != len(v):
            # 只警告，不抛出错误
            pass
        return unique_ids


class PodcastSubscriptionBulkDeleteResponse(PodcastBaseSchema):
    """批量删除播客订阅响应"""
    success_count: int = Field(..., description="成功删除的订阅数量")
    failed_count: int = Field(..., description="删除失败的订阅数量")
    errors: List[Dict[str, Any]] = Field(default_factory=list, description="删除失败的错误信息列表")
    deleted_subscription_ids: List[int] = Field(default_factory=list, description="成功删除的订阅ID列表")
