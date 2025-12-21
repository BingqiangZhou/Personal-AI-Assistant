# 播客音频转录功能需求文档

**文档ID**: PRD-2025-001
**创建日期**: 2025-12-21
**负责人**: 产品经理
**状态**: 草稿

## 1. 需求概述

### 1.1 问题陈述
用户需要将播客音频内容转换为文本，以便：
- 快速浏览播客内容
- 搜索特定信息
- 生成内容摘要
- 提高可访问性

### 1.2 目标用户
- 播客订阅者
- 内容研究者
- 需要快速查找信息的用户
- 听力障碍用户

### 1.3 业务价值
- 提升用户体验和参与度
- 增强内容可搜索性
- 为AI功能提供数据基础
- 扩大用户群体

## 2. 功能需求

### 2.1 核心功能

#### 2.1.1 音频文件处理
**功能描述**: 自动下载、转换和切割播客音频文件

**用户故事**:
- 作为系统，我需要自动下载播客音频文件
- 作为系统，我需要将音频文件转换为MP3格式（如果不是MP3）
- 作为系统，我需要将大文件切割成指定大小的小文件（默认10MB）

**验收标准**:
- [ ] 支持从URL下载音频文件
- [ ] 自动检测音频格式并转换为MP3
- [ ] 支持配置文件大小阈值（默认10MB）
- [ ] 按配置大小切割文件，保持音频完整性
- [ ] 临时文件管理（自动清理）

#### 2.1.2 音频转录
**功能描述**: 使用硅基流动API进行音频转录

**用户故事**:
- 作为系统，我需要调用硅基流动API转录音频
- 作为系统，我需要支持多线程并发转录
- 作为系统，我需要合并多个音频片段的转录结果

**验收标准**:
- [ ] 集成硅基流动转录API
- [ ] 支持配置最大线程数
- [ ] 实现任务队列机制（超过线程数时排队）
- [ ] 智能合并转录结果，保持上下文连贯
- [ ] 错误处理和重试机制

#### 2.1.3 文件存储管理
**功能描述**: 按照规范存储音频文件和转录文本

**用户故事**:
- 作为系统，我需要按照目录结构存储文件
- 作为系统，我需要关联音频文件和转录文本

**验收标准**:
- [ ] 目录结构：`存储根目录/播客名称/分集名称/`
- [ ] 原始音频文件保存
- [ ] 转录文本保存
- [ ] 数据库记录更新

### 2.2 配置管理

#### 2.2.1 环境变量配置
**功能描述**: 通过.env文件管理转录功能配置

**配置项**:
```env
# 转录API配置
TRANSCRIPTION_API_URL=https://api.siliconflow.cn/v1/audio/transcriptions
TRANSCRIPTION_API_KEY=your_api_key_here

# 文件处理配置
TRANSCRIPTION_CHUNK_SIZE_MB=10
TRANSCRIPTION_TARGET_FORMAT=mp3
TRANSCRIPTION_TEMP_DIR=./temp/transcription
TRANSCRIPTION_STORAGE_DIR=./storage/podcasts

# 并发控制
TRANSCRIPTION_MAX_THREADS=4
```

#### 2.2.2 动态配置
- 支持运行时修改部分配置
- 配置验证和默认值
- 配置变更通知

### 2.3 API接口

#### 2.3.1 转录任务接口
```
POST /api/v1/podcast/episodes/{episode_id}/transcribe
响应：
{
  "task_id": "uuid",
  "status": "queued|processing|completed|failed",
  "progress": 0-100
}
```

#### 2.3.2 转录状态查询
```
GET /api/v1/podcast/episodes/{episode_id}/transcription
响应：
{
  "status": "queued|processing|completed|failed",
  "progress": 0-100,
  "transcript_content": "转录文本",
  "error_message": "错误信息（如果有）"
}
```

## 3. 技术需求

### 3.1 后端技术栈
- **框架**: FastAPI
- **音频处理**: FFmpeg
- **异步任务**: Celery + Redis
- **外部API**: 硅基流动转录服务
- **存储**: 本地文件系统 + 数据库

### 3.2 性能要求
- 支持并发转录（可配置线程数）
- 大文件处理（>100MB音频）
- 任务队列管理
- 优雅的错误恢复

### 3.3 安全要求
- API密钥安全存储
- 临时文件加密（可选）
- 访问权限控制

## 4. 数据模型扩展

### 4.1 PodcastEpisode模型更新
```python
class PodcastEpisode(Base):
    # 现有字段...

    # 转录相关字段
    transcription_status = Column(String(50), default="not_started")
    transcription_progress = Column(Integer, default=0)
    transcription_task_id = Column(String(100))
    transcription_started_at = Column(DateTime)
    transcription_completed_at = Column(DateTime)
    transcription_error = Column(Text)

    # 文件路径
    local_audio_path = Column(String(500))
    transcript_file_path = Column(String(500))
```

### 4.2 新增TranscriptionTask模型
```python
class TranscriptionTask(Base):
    __tablename__ = "transcription_tasks"

    id = Column(String(100), primary_key=True)  # UUID
    episode_id = Column(Integer, ForeignKey("podcast_episodes.id"))
    status = Column(String(50))
    progress = Column(Integer, default=0)
    chunk_count = Column(Integer)
    completed_chunks = Column(Integer, default=0)
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
```

## 5. 实现计划

### 阶段1：基础架构（2天）
1. 创建转录服务模块
2. 实现FFmpeg音频处理
3. 集成硅基流动API
4. 基础任务队列

### 阶段2：核心功能（3天）
1. 完整转录流程实现
2. 文件存储管理
3. API接口开发
4. 数据库模型更新

### 阶段3：优化完善（2天）
1. 错误处理增强
2. 性能优化
3. 监控和日志
4. 单元测试

## 6. 风险与依赖

### 6.1 风险
- 硅基流动API限制和费用
- 大文件处理性能
- 并发控制复杂度

### 6.2 依赖
- FFmpeg安装和配置
- 硅基流动API访问权限
- 足够的存储空间

## 7. 成功指标

### 7.1 技术指标
- 转录准确率 > 95%
- 平均处理时间 < 音频时长 * 0.3
- 系统可用性 > 99%

### 7.2 业务指标
- 用户功能使用率
- 转录内容搜索使用率
- 用户满意度

## 8. 后续优化

- 支持更多音频格式
- 转录结果编辑功能
- 多语言转录支持
- 转录质量评分