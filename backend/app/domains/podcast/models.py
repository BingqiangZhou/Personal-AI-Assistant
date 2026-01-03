"""
播客数据模型 - 扩展订阅域

基于现有subscription实体进行扩展，新增播客特定字段
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, JSON, Index, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import List, Optional
import enum

from app.core.database import Base
from app.domains.subscription.models import Subscription


class PodcastEpisode(Base):
    """
    播客单集数据模型

    设计说明:
    - 不直接使用继承，而是通过外键关联到Subscription
    - 复用部分SubscriptionItem字段但独立管理播客特有的音频/总结字段
    - 保持与现有schema兼容，同时避免复杂的SQLAlchemy继承配置
    """
    __tablename__ = "podcast_episodes"

    id = Column(Integer, primary_key=True, index=True)
    subscription_id = Column(Integer, ForeignKey("subscriptions.id"), nullable=False)

    # 准唯一标识
    guid = Column(String(500), unique=True, nullable=False, index=True)  # RSS原始ID

    # 播客基本信息
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    published_at = Column(DateTime, nullable=False)

    # 音频信息
    audio_url = Column(String(500), nullable=False)
    audio_duration = Column(Integer)  # 秒
    audio_file_size = Column(Integer)  # 字节

    # 转录文本
    transcript_url = Column(String(500))
    transcript_content = Column(Text)

    # AI总结
    ai_summary = Column(Text)
    summary_version = Column(String(50))  # 用于跟踪总结版本
    ai_confidence_score = Column(Float)  # AI总结质量评分

    # 分集图像
    image_url = Column(String(500))  # 分集封面图URL

    # 分集详情页链接
    item_link = Column(String(500))  # <item><link> 标签内容，指向分集详情页

    # 播放统计（全局）
    play_count = Column(Integer, default=0)
    last_played_at = Column(DateTime)

    # 节目信息
    season = Column(Integer)  # 季节
    episode_number = Column(Integer)  # 集数序号
    explicit = Column(Boolean, default=False)

    # 状态和元数据
    status = Column(String(50), default="pending_summary")  # pending, summarized, failed
    metadata_json = Column("metadata", JSON, nullable=True, default={})  # Renamed to avoid SQLAlchemy reserved attribute
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    subscription = relationship("Subscription", back_populates="podcast_episodes")
    playback_states = relationship("PodcastPlaybackState", back_populates="episode", cascade="all, delete")

    # Indexes
    __table_args__ = (
        Index('idx_podcast_subscription', 'subscription_id'),
        Index('idx_podcast_status', 'status'),
        Index('idx_podcast_published', 'published_at'),
        Index('idx_podcast_episode_image', 'image_url'),
    )

    def __repr__(self):
        return f"<PodcastEpisode(id={self.id}, title='{self.title[:30]}...', status='{self.status}')>"


# 在Subscription中添加反向关系
def _add_podcast_relationship():
    """为Subscription添加podcast_episodes关系"""
    capsule = relationship(
        "PodcastEpisode",
        back_populates="subscription",
        cascade="all, delete-orphan",
        uselist=False  # 不直接使用，通过方法访问
    )

# 直接用赋值方式添加
from app.domains.subscription.models import Subscription
Subscription.podcast_episodes = relationship(
    "PodcastEpisode",
    back_populates="subscription",
    cascade="all, delete-orphan"
)


class PodcastPlaybackState(Base):
    """
    用户播放状态 - 跟踪每个用户的播客播放进度
    """
    __tablename__ = "podcast_playback_states"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    episode_id = Column(Integer, ForeignKey("podcast_episodes.id"), nullable=False)

    # 播放状态
    current_position = Column(Integer, default=0)  # 当前播放位置(秒)
    is_playing = Column(Boolean, default=False)
    playback_rate = Column(Float, default=1.0)  # 播放速度
    last_updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # 统计
    play_count = Column(Integer, default=0)

    # 关系
    episode = relationship("PodcastEpisode", back_populates="playback_states")
    # 注意：由于User模型未导入，仅通过repositories访问

    __table_args__ = (
        # 确保每个用户-episode组合唯一
        Index('idx_user_episode_unique', 'user_id', 'episode_id', unique=True),
    )

    def __repr__(self):
        return f"<PlaybackState(user={self.user_id}, ep={self.episode_id}, pos={self.current_position}s)>"


# 转录任务状态枚举（简化版）
class TranscriptionStatus(str, enum.Enum):
    """转录任务状态枚举（简化版）"""
    PENDING = "pending"  # 等待开始
    IN_PROGRESS = "in_progress"  # 处理中
    COMPLETED = "completed"  # 已完成
    FAILED = "failed"  # 失败
    CANCELLED = "cancelled"  # 已取消


# 转录任务步骤枚举
class TranscriptionStep(str, enum.Enum):
    """转录任务执行步骤枚举"""
    NOT_STARTED = "not_started"  # 未开始
    DOWNLOADING = "downloading"  # 下载音频文件
    CONVERTING = "converting"  # 格式转换为MP3
    SPLITTING = "splitting"  # 切割音频文件
    TRANSCRIBING = "transcribing"  # 语音识别转录
    MERGING = "merging"  # 合并转录结果


class TranscriptionTask(Base):
    """
    播客音频转录任务模型

    跟踪音频转录的整个生命周期，包括下载、转换、分割、转录和合并等阶段

    状态管理：
    - status: 整体任务状态 (PENDING, IN_PROGRESS, COMPLETED, FAILED, CANCELLED)
    - current_step: 当前执行到的步骤 (NOT_STARTED, DOWNLOADING, CONVERTING, SPLITTING, TRANSCRIBING, MERGING)
    """
    __tablename__ = "transcription_tasks"

    id = Column(Integer, primary_key=True, index=True)
    episode_id = Column(Integer, ForeignKey("podcast_episodes.id"), nullable=False, unique=True)

    # 任务状态（简化版）- Use explicit values to match database enum
    status = Column(
        Enum('pending', 'in_progress', 'completed', 'failed', 'cancelled', name='transcriptionstatus'),
        default='pending',
        nullable=False
    )

    # 当前执行步骤 - Use explicit values to match database enum
    current_step = Column(
        Enum('not_started', 'downloading', 'converting', 'splitting', 'transcribing', 'merging', name='transcriptionstep'),
        default='not_started',
        nullable=False
    )

    # 进度百分比 0-100
    progress_percentage = Column(Float, default=0.0)

    # 文件信息
    original_audio_url = Column(String(500), nullable=False)
    original_file_path = Column(String(1000))  # 原始下载文件路径
    original_file_size = Column(Integer)  # 原始文件大小（字节）

    # 处理结果
    transcript_content = Column(Text)  # 最终转录文本
    transcript_word_count = Column(Integer)  # 转录字数
    transcript_duration = Column(Integer)  # 实际转录时长（秒）

    # AI总结结果
    summary_content = Column(Text)  # AI总结内容
    summary_model_used = Column(String(100))  # 使用的AI总结模型
    summary_word_count = Column(Integer)  # 总结字数
    summary_processing_time = Column(Float)  # 总结处理时间（秒）
    summary_error_message = Column(Text)  # 总结错误信息

    # 分片信息（JSON格式存储）
    chunk_info = Column(JSON, default=dict)  # 存储分片信息，如：{"chunks": [{"index": 1, "file": "path", "size": 1024, "transcript": "..."}]}

    # 错误信息
    error_message = Column(Text)  # 错误详情
    error_code = Column(String(50))  # 错误代码

    # 性能统计
    download_time = Column(Float)  # 下载耗时（秒）
    conversion_time = Column(Float)  # 转换耗时（秒）
    transcription_time = Column(Float)  # 转录总耗时（秒）
    download_method = Column(String(20), default='aiohttp', nullable=False)  # 下载方法: aiohttp, browser, none

    # 配置信息（记录任务使用的配置）
    chunk_size_mb = Column(Integer, default=10)  # 分片大小（MB）
    model_used = Column(String(100))  # 使用的转录模型

    # 时间戳
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)  # 任务开始时间
    completed_at = Column(DateTime)  # 任务完成时间
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    episode = relationship("PodcastEpisode", backref="transcription_task")

    # Indexes
    __table_args__ = (
        Index('idx_transcription_episode', 'episode_id', unique=True),
        Index('idx_transcription_status', 'status'),
        Index('idx_transcription_created', 'created_at'),
    )

    @property
    def duration_seconds(self) -> Optional[int]:
        """获取任务执行时长（秒）"""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return None

    @property
    def total_processing_time(self) -> Optional[float]:
        """获取总处理时间（秒）"""
        total = 0
        if self.download_time:
            total += self.download_time
        if self.conversion_time:
            total += self.conversion_time
        if self.transcription_time:
            total += self.transcription_time
        return total if total > 0 else None

    def __repr__(self):
        return f"<TranscriptionTask(id={self.id}, episode_id={self.episode_id}, status='{self.status}')>"


class PodcastConversation(Base):
    """
    播客单集对话交互模型

    存储用户与AI基于播客摘要的对话历史，支持上下文保持的交互
    """
    __tablename__ = "podcast_conversations"

    id = Column(Integer, primary_key=True, index=True)
    episode_id = Column(Integer, ForeignKey("podcast_episodes.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # 对话内容
    role = Column(String(20), nullable=False)  # 'user' or 'assistant'
    content = Column(Text, nullable=False)

    # 上下文管理
    parent_message_id = Column(Integer, ForeignKey("podcast_conversations.id"), nullable=True)  # 父消息ID，用于构建对话树
    conversation_turn = Column(Integer, default=0)  # 对话轮次

    # 元数据
    tokens_used = Column(Integer)  # 本次消息使用的token数
    model_used = Column(String(100))  # 使用的AI模型
    processing_time = Column(Float)  # 处理时间（秒）

    # 时间戳
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    episode = relationship("PodcastEpisode", backref="conversations")
    parent_message = relationship("PodcastConversation", remote_side=[id], backref="replies")

    # Indexes
    __table_args__ = (
        Index('idx_conversation_episode', 'episode_id'),
        Index('idx_conversation_user', 'user_id'),
        Index('idx_conversation_created', 'created_at'),
        Index('idx_conversation_turn', 'episode_id', 'conversation_turn'),
    )

    def __repr__(self):
        return f"<PodcastConversation(id={self.id}, episode_id={self.episode_id}, role='{self.role}')>"


# 辅助方法：判断订阅是否播客
def is_podcast_subscription(subscription) -> bool:
    """判断Subscription是否播客类型"""
    return subscription.source_type == "podcast-rss"
