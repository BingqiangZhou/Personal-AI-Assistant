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
    custom_name: Optional[str] = Field(None, description="自定义订阅名称", max_length=255)
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
    fetch_interval: int
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


class PodcastSummaryResponse(PodcastBaseSchema):
    """AI总结响应"""
    episode_id: int
    summary: str
    version: str
    confidence_score: Optional[float] = None
    transcript_used: bool
    generated_at: datetime
    word_count: int


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