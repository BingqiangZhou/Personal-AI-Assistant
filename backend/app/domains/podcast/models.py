"""
播客数据模型 - 扩展订阅域

基于现有subscription实体进行扩展，新增播客特定字段
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, JSON, Index
from sqlalchemy.orm import relationship
from datetime import datetime
from typing import List, Optional

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


# 辅助方法：判断订阅是否播客
def is_podcast_subscription(subscription) -> bool:
    """判断Subscription是否播客类型"""
    return subscription.source_type == "podcast-rss"
