# Backend 完整参考文档

## 项目概览

**Personal AI Assistant Backend** - 基于 **Domain-Driven Design (DDD)** 架构的 FastAPI 应用

### 技术栈
- **框架**: FastAPI 0.104+
- **Python**: 3.10+
- **数据库**: PostgreSQL + SQLAlchemy 2.0 (async)
- **缓存**: Redis 5.0+
- **任务队列**: Celery 5.3+
- **数据库迁移**: Alembic 1.12+
- **包管理**: uv (现代化 Python 包管理器)

### 代码统计
- **总代码行数**: ~21,795 行 Python 代码
- **配置文件**: pyproject.toml (使用 uv)
- **依赖数量**: 41 个生产依赖 + 4 个开发依赖

---

## 目录结构

```
backend/
├── app/
│   ├── main.py                          # FastAPI 应用入口
│   ├── core/                            # 核心基础设施层 (19个文件)
│   ├── shared/                          # 共享工具和基类 (8个文件)
│   ├── domains/                         # 领域层 (DDD)
│   │   ├── ai/                          # AI 服务领域 (5个文件)
│   │   ├── assistant/                   # AI 助手领域 (4个文件)
│   │   ├── podcast/                     # 播客领域 (18个文件) - 最大模块
│   │   ├── multimedia/                  # 多媒体领域 (4个文件)
│   │   ├── subscription/                # 订阅领域 (7个文件)
│   │   └── user/                        # 用户领域 (8个文件)
│   ├── admin/                           # 管理模块 (15个文件)
│   └── scripts/                         # 实用脚本
├── alembic/                             # 数据库迁移 (21个版本)
├── tests/                               # 测试文件
├── data/                                # 数据存储目录
├── docs/                                # 文档
├── logs/                                # 应用日志
└── upload/                              # 上传文件目录
```

---

## 一、Core Layer (核心基础设施层)

### 1.1 main.py - 应用入口

**功能**: FastAPI 应用主入口，配置中间件和路由

**关键组件**:
- `lifespan()` - 应用生命周期管理 (启动/关闭)
- `create_application()` - 创建和配置 FastAPI 应用
- 中间件配置: CORS, 日志, 性能监控, 安全
- 路由注册: 各领域 API 路由
- 健康检查端点: `/health`, `/metrics`

**代码概览**:
```python
# 启动时执行
- init_db() - 初始化数据库
- reset_stale_tasks() - 重置过期转录任务

# 路由前缀
/api/v1/auth         # 用户认证
/api/v1/subscriptions # 订阅管理
/api/v1/podcasts     # 播客功能
/api/v1/assistant    # AI 助手
/api/v1/multimedia   # 多媒体
/api/v1/ai           # AI 模型配置
/super               # 管理后台
```

---

### 1.2 config.py - 配置管理

**功能**: 应用配置管理，使用 Pydantic Settings

**配置类别**:

| 类别 | 配置项 | 默认值 |
|------|--------|--------|
| **基本** | PROJECT_NAME, VERSION, ENVIRONMENT | Personal AI Assistant |
| **数据库** | DATABASE_URL, POOL_SIZE, MAX_OVERFLOW | pool=20, overflow=40 |
| **JWT** | ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS | 30分钟, 7天 |
| **播客** | MAX_PODCAST_SUBSCRIPTIONS, RSS_POLL_INTERVAL | 999999, 60分钟 |
| **转录** | TRANSCRIPTION_API_URL, MAX_THREADS | 4线程, 100队列 |
| **2FA** | ADMIN_2FA_ENABLED | True |

**核心类**:
- `SecretKeyManager` - SECRET_KEY 生成和持久化
- `Settings` - 主配置类，从环境变量加载
- `get_settings()` - 缓存的配置获取函数

---

### 1.3 database.py - 数据库连接

**功能**: PostgreSQL 异步数据库连接管理

**关键特性**:
```python
# 连接池优化
pool_size=20                   # 基础连接数
max_overflow=40                # 溢出连接数 (总计最多60)
pool_pre_ping=True             # 连接健康检查
pool_recycle=3600              # 1小时回收连接
isolation_level="READ COMMITTED"  # 读优化隔离级别

# 函数
- get_db_session()     # 获取数据库会话
- init_db()            # 初始化数据库表
- close_db()           # 关闭数据库连接
- check_db_health()    # 健康检查
```

---

### 1.4 security.py - 安全认证

**功能**: 认证和授权相关工具

**核心功能**:

| 功能 | 函数 | 说明 |
|------|------|------|
| **JWT Token** | `create_access_token()` | 创建访问令牌 (30分钟) |
| | `create_refresh_token()` | 创建刷新令牌 (7天) |
| | `verify_token()` | 验证 JWT 令牌 |
| **密码** | `get_password_hash()` | bcrypt 密码哈希 |
| | `verify_password()` | 验证密码 |
| **重置** | `generate_password_reset_token()` | 生成重置令牌 |
| | `verify_password_reset_token()` | 验证重置令牌 |
| **加密** | `encrypt_data()` | Fernet 对称加密 |
| | `decrypt_data()` | 解密数据 |
| **RSA** | `get_or_generate_rsa_keys()` | RSA 密钥对管理 |
| | `decrypt_rsa_data()` | RSA 解密 |
| **类型安全** | `require_user_id()` | FastAPI 依赖注入 |
| | `get_user_id_from_token()` | 从 token 获取 user_id |

**性能优化**:
- `TokenOptimizer` - 预计算 token claims 减少 CPU 周期
- HMAC key 缓存 - JWT 操作优化
- 支持 500+ 请求/秒吞吐量

---

### 1.5 container.py - 依赖注入容器

**功能**: 使用 dependency-injector 管理服务依赖

**注册的服务**:

```python
# 数据库和缓存
- database: AsyncSession
- redis: PodcastRedis
- content_sanitizer: ContentSanitizer

# 仓储
- user_repository: UserRepository
- subscription_repository: SubscriptionRepository
- podcast_repository: PodcastRepository

# 服务工厂函数
- get_podcast_service(db, user_id)
- get_podcast_subscription_service(db, user_id)
- get_podcast_episode_service(db, user_id)
- get_podcast_playback_service(db, user_id)
- get_podcast_summary_service(db, user_id)
- get_podcast_search_service(db, user_id)
```

---

### 1.6 其他核心文件

| 文件 | 功能 |
|------|------|
| `dependencies.py` | FastAPI 依赖注入函数 |
| `exceptions.py` | 自定义异常类 |
| `middleware.py` | 自定义中间件 |
| `logging_config.py` | 日志配置 |
| `logging_middleware.py` | 日志中间件 |
| `security_middleware.py` | 安全中间件 |
| `feed_parser.py` | 通用 feed 解析器 |
| `feed_schemas.py` | Feed 数据模型 |
| `file_validation.py` | 文件验证工具 |
| `json_encoder.py` | JSON 编码器 (处理 datetime) |
| `llm_privacy.py` | LLM 隐私工具 |
| `datetime_utils.py` | 日期时间工具 |
| `email.py` | 邮件工具 |
| `types.py` | 类型定义 |
| `utils.py` | 通用工具 |

---

## 二、Shared Layer (共享层)

### 2.1 base_repository.py - 基础仓储类

**功能**: 通用数据访问操作，泛型实现

**方法列表**:
```python
# 单个操作
async get_by_id(id, options=None)         # 按 ID 获取
async get_by_ids(ids, options=None)       # 批量获取
async get_list(skip, limit, filters, order_by, options)  # 列表查询
async count(filters=None)                 # 计数

# 创建
async create(**kwargs)                    # 创建单个
async create_many(items)                  # 批量创建

# 更新
async update(id, **kwargs)                # 单个更新
async update_many(ids, **kwargs)          # 批量更新

# 删除
async delete(id)                          # 单个删除
async delete_many(ids)                    # 批量删除

# 其他
async exists(id)                          # 检查存在
async get_paginated(page, size, filters, order_by, options)  # 分页查询
```

---

### 2.2 base_service.py - 基础服务类

**功能**: 通用业务逻辑操作，泛型实现

**方法列表**:
```python
async get_by_id(id)                       # 按 ID 获取
async get_list(skip, limit, filters)      # 列表查询
async count(filters=None)                 # 计数
async create(**kwargs)                    # 创建
async update(id, **kwargs)                # 更新
async delete(id)                          # 删除
async exists(id)                          # 检查存在
```

---

### 2.3 其他共享文件

| 文件 | 功能 |
|------|------|
| `pagination.py` | 分页工具 |
| `response_builder.py` | API 响应构建器 |
| `schemas.py` | 共享 Pydantic 模型 |
| `mappers.py` | 数据映射器 |
| `file_validation.py` | 文件验证工具 |

---

## 三、Domain Layer (领域层)

### 3.1 User Domain (用户领域)

#### 数据模型 (models.py)

**User 表**:
```python
id: Integer (PK)
email: String(255) (unique, indexed)
username: String(100) (unique, indexed)
account_name: String(255)              # 账户名称
hashed_password: String(255)
avatar_url: String(500)
status: String(20)                     # active/inactive/suspended
is_superuser: Boolean
is_verified: Boolean
last_login_at: DateTime
settings: JSON
preferences: JSON
api_key: String(255) (unique)

# 2FA 字段
totp_secret: String(32)                # Base32 编码的 TOTP 密钥
is_2fa_enabled: Boolean

created_at, updated_at: DateTime
```

**UserSession 表**:
```python
id: Integer (PK)
user_id: Integer (indexed)
session_token: String(255) (unique, indexed)
refresh_token: String(255) (unique, indexed)
device_info: JSON
ip_address: String(45)                 # IPv6 兼容
user_agent: Text
expires_at: DateTime
last_activity_at: DateTime
is_active: Boolean
```

**PasswordReset 表**:
```python
id: Integer (PK)
email: String(255) (indexed)
token: String(255) (unique, indexed)
expires_at: DateTime
is_used: Boolean
```

#### 服务 (services/auth_service.py)

**功能**: 用户认证服务

**主要方法**:
- 用户注册
- 用户登录
- 密码重置
- Token 刷新
- 2FA 验证

#### API 路由 (api/routes.py)

| 端点 | 方法 | 功能 |
|------|------|------|
| `/register` | POST | 用户注册 |
| `/login` | POST | 用户登录 |
| `/refresh` | POST | 刷新 token |
| `/me` | GET | 获取当前用户信息 |
| `/me` | PUT | 更新用户信息 |
| `/forgot-password` | POST | 忘记密码 |
| `/reset-password` | POST | 重置密码 |

---

### 3.2 Subscription Domain (订阅领域)

#### 数据模型 (models.py)

**Subscription 表**:
```python
id: Integer (PK)
user_id: Integer (FK to users)
title: String(255)
description: Text
source_type: String(50)                 # rss/api/social/email/website
source_url: String(500)
config: JSON                            # 元数据存储
status: String(20)                      # active/inactive/error/pending
last_fetched_at: DateTime
latest_item_published_at: DateTime      # 最新项目发布时间
error_message: Text
fetch_interval: Integer                 # 抓取间隔 (秒)

# 调度相关
update_frequency: String(10)            # HOURLY/DAILY/WEEKLY
update_time: String(5)                  # HH:MM 格式
update_day_of_week: Integer             # 1-7 (周一到周日)

created_at, updated_at: DateTime
```

**SubscriptionItem 表**:
```python
id: Integer (PK)
subscription_id: Integer (FK)
external_id: String(255)
title: String(500)
content: Text
summary: Text
author: String(255)
source_url: String(500)
image_url: String(500)
tags: JSON
metadata_json: JSON
published_at: DateTime
read_at: DateTime
bookmarked: Boolean
created_at, updated_at: DateTime
```

**SubscriptionCategory 表**:
```python
id: Integer (PK)
user_id: Integer (FK)
name: String(100)
description: Text
color: String(7)                        # Hex 颜色
created_at, updated_at: DateTime
```

#### Feed 解析器 (parsers/feed_parser.py)

**功能**: RSS Feed 解析

**核心类**:
- `FeedParser` - 通用 feed 解析
- `FeedData` - Feed 数据模型
- `FeedEpisode` - 剧集数据模型

#### API 路由 (api/routes.py)

| 端点 | 方法 | 功能 |
|------|------|------|
| `/` | GET | 列出订阅 |
| `/` | POST | 创建订阅 |
| `/{id}` | GET | 获取订阅详情 |
| `/{id}` | PUT | 更新订阅 |
| `/{id}` | DELETE | 删除订阅 |
| `/{id}/refresh` | POST | 刷新订阅 |
| `/{id}/items` | GET | 获取订阅项目 |

---

### 3.3 Podcast Domain (播客领域) - 最大模块

#### 数据模型 (models.py)

**PodcastEpisode 表**:
```python
id: Integer (PK)
subscription_id: Integer (FK to subscriptions)

# 基本信息
title: String(500)
description: Text
published_at: DateTime

# 音频信息
audio_url: String(500)
audio_duration: Integer                 # 秒
audio_file_size: Integer                # 字节

# 转录和总结
transcript_url: String(500)
transcript_content: Text
ai_summary: Text
summary_version: String(50)
ai_confidence_score: Float

# 分集信息
image_url: String(500)                  # 分集封面图
item_link: String(500) (unique)         # 分集详情页链接

# 播放统计
play_count: Integer (default=0)
last_played_at: DateTime

# 节目信息
season: Integer                         # 季节
episode_number: Integer                 # 集数序号
explicit: Boolean

# 状态
status: String(50)                      # pending/summarized/failed
metadata_json: JSON
created_at, updated_at: DateTime
```

**PodcastPlaybackState 表**:
```python
id: Integer (PK)
user_id: Integer (FK to users)
episode_id: Integer (FK to podcast_episodes, ondelete=CASCADE)

# 播放状态
current_position: Integer               # 当前播放位置(秒)
is_playing: Boolean
playback_rate: Float (default=1.0)      # 播放速度
last_updated_at: DateTime

# 统计
play_count: Integer (default=0)
```

**TranscriptionTask 表**:
```python
id: Integer (PK)
episode_id: Integer (FK to podcast_episodes, unique)

# 任务状态
status: Enum                            # pending/in_progress/completed/failed/cancelled
current_step: Enum                      # not_started/downloading/converting/splitting/transcribing/merging
progress_percentage: Float (0-100)

# 文件信息
original_audio_url: String(500)
original_file_path: String(1000)
original_file_size: Integer

# 处理结果
transcript_content: Text
transcript_word_count: Integer
transcript_duration: Integer
summary_content: Text
summary_model_used: String(100)
summary_word_count: Integer
summary_processing_time: Float
summary_error_message: Text

chunk_info: JSON                        # 分片信息
error_message: Text
error_code: String(50)

# 性能统计
download_time: Float
conversion_time: Float
transcription_time: Float

# 配置
chunk_size_mb: Integer (default=10)
model_used: String(100)

# 时间戳
created_at, started_at, completed_at, updated_at: DateTime
```

**PodcastConversation 表**:
```python
id: Integer (PK)
episode_id: Integer (FK to podcast_episodes)
user_id: Integer (FK to users)

# 对话内容
role: String(20)                        # user/assistant
content: Text

# 上下文管理
parent_message_id: Integer (FK to podcast_conversations)
conversation_turn: Integer (default=0)

# 元数据
tokens_used: Integer
model_used: String(100)
processing_time: Float

created_at: DateTime
```

#### 服务层 (services/)

**subscription_service.py** - 订阅管理
```python
class PodcastSubscriptionService:
    async add_subscription(feed_url, category_ids) -> tuple[Subscription, list[PodcastEpisode]]
    async add_subscriptions_batch(subscriptions_data) -> list[dict]
    async list_subscriptions(filters, page, size) -> tuple[list, int]
    async get_subscription_details(subscription_id) -> Optional[dict]
    async refresh_subscription(subscription_id) -> list[PodcastEpisode]
    async reparse_subscription(subscription_id, force_all) -> dict
    async remove_subscription(subscription_id) -> bool
    async remove_subscriptions_bulk(subscription_ids) -> dict
```

**episode_service.py** - 剧集管理
```python
class PodcastEpisodeService:
    async get_episode(episode_id) -> Optional[PodcastEpisode]
    async list_episodes(subscription_id, filters, page, size) -> tuple[list, int]
    async update_episode_progress(episode_id, position, completed)
```

**playback_service.py** - 播放管理
```python
class PodcastPlaybackService:
    async get_playback_state(episode_id) -> Optional[PodcastPlaybackState]
    async update_playback_state(episode_id, position, is_playing, rate)
    async get_recently_played(limit) -> list
```

**search_service.py** - 搜索功能
```python
class PodcastSearchService:
    async search_episodes(query, filters, page, size) -> tuple[list, int]
    async search_transcripts(query, page, size) -> tuple[list, int]
```

**summary_service.py** - 摘要生成
```python
class PodcastSummaryService:
    async generate_summary(episode_id) -> Optional[str]
    async regenerate_summary(episode_id) -> Optional[str]
    async get_summary(episode_id) -> Optional[dict]
```

**sync_service.py** - Feed 同步
```python
class PodcastSyncService:
    async sync_subscription(subscription_id) -> dict
    async sync_all_subscriptions() -> dict
    async trigger_transcription(episode_id) -> bool
```

#### 转录系统 (transcription_*.py)

**transcription.py** - 转录核心逻辑
- 音频下载
- 格式转换
- 文件分割
- API 转录
- 结果合并

**transcription_manager.py** - 转录工作流管理
- 任务创建
- 状态更新
- 进度跟踪
- 错误处理

**transcription_scheduler.py** - 任务调度
- 队列管理
- 并发控制
- 优先级处理

**transcription_state.py** - 状态机
- 状态转换
- 步骤管理
- 状态验证

#### 集成层 (integration/)

**platform_detector.py** - 平台检测
- 识别播客平台
- 提取平台特定元数据

**secure_rss_parser.py** - 安全 RSS 解析
- SSL 验证
- 超时控制
- 错误处理

**security.py** - 安全工具
- URL 验证
- 内容过滤

#### API 路由 (api/routes.py)

| 端点 | 方法 | 功能 |
|------|------|------|
| `/subscriptions` | GET | 列出播客订阅 |
| `/subscriptions` | POST | 添加订阅 |
| `/subscriptions/batch` | POST | 批量添加订阅 |
| `/subscriptions/{id}` | GET | 获取订阅详情 |
| `/subscriptions/{id}` | DELETE | 删除订阅 |
| `/subscriptions/{id}/refresh` | POST | 刷新订阅 |
| `/subscriptions/{id}/reparse` | POST | 重新解析订阅 |
| `/subscriptions/bulk-delete` | POST | 批量删除订阅 |
| `/episodes` | GET | 列出剧集 |
| `/episodes/{id}` | GET | 获取剧集详情 |
| `/episodes/{id}/playback` | GET/POST | 播放状态 |
| `/episodes/{id}/transcribe` | POST | 触发转录 |
| `/episodes/{id}/summary` | GET | 获取摘要 |
| `/episodes/{id}/conversations` | GET/POST | 对话交互 |
| `/search` | GET | 搜索剧集 |

---

### 3.4 AI Domain (AI 服务领域)

#### 数据模型 (models.py)

**AIModelConfig 表**:
```python
id: Integer (PK)

# 基本信息
name: String(100)                       # 模型名称
display_name: String(200)               # 显示名称
description: Text
model_type: String(20)                  # transcription/text_generation

# API 配置
api_url: String(500)                    # API 端点 URL
api_key: String(1000)                   # API 密钥 (加密存储)
api_key_encrypted: Boolean

# 模型配置
model_id: String(200)                   # 模型标识符
provider: String(100)                   # openai/siliconflow/custom

# 性能配置
max_tokens: Integer
temperature: String(10)
timeout_seconds: Integer (default=300)
max_retries: Integer (default=3)

# 并发配置
max_concurrent_requests: Integer (default=1)
rate_limit_per_minute: Integer (default=60)

# 成本配置
cost_per_input_token: String(20)
cost_per_output_token: String(20)

# 额外配置
extra_config: JSON

# 状态管理
is_active: Boolean (default=True)
is_default: Boolean (default=False)
is_system: Boolean (default=False)
priority: Integer (default=1)

# 使用统计
usage_count: Integer (default=0)
success_count: Integer (default=0)
error_count: Integer (default=0)
total_tokens_used: Integer (default=0)

# 时间戳
created_at, updated_at, last_used_at: DateTime
```

#### Pydantic 模型

```python
class AIModelConfigBase(BaseModel):
    name: str
    display_name: str
    description: Optional[str]
    model_type: ModelType
    api_url: str
    api_key: Optional[str]
    model_id: str
    provider: str
    max_tokens: Optional[int]
    temperature: Optional[str]
    # ... 更多字段

class AIModelConfigCreate(AIModelConfigBase):
    pass

class AIModelConfigUpdate(BaseModel):
    # 可选更新字段

class AIModelConfigResponse(AIModelConfigBase):
    id: int
    api_key_encrypted: bool
    usage_count: int
    success_count: int
    error_count: int
    total_tokens_used: int
    success_rate: float
    created_at: datetime
    updated_at: datetime
    last_used_at: Optional[datetime]
    is_system: bool
    priority: int
```

#### 服务 (services.py)

**TextGenerationService**:
```python
class TextGenerationService:
    async generate_text(prompt, model_config, max_tokens, temperature) -> str
    async generate_summary(content, model_config) -> str
    async chat(messages, model_config) -> str
```

#### API 路由 (api/routes.py)

| 端点 | 方法 | 功能 |
|------|------|------|
| `/models` | GET | 列出 AI 模型配置 |
| `/models` | POST | 创建模型配置 |
| `/models/{id}` | GET | 获取模型详情 |
| `/models/{id}` | PUT | 更新模型配置 |
| `/models/{id}` | DELETE | 删除模型配置 |
| `/models/{id}/test` | POST | 测试模型 |
| `/models/{id}/set-default` | POST | 设为默认 |
| `/models/stats` | GET | 获取使用统计 |
| `/generate` | POST | 文本生成 |
| `/summarize` | POST | 摘要生成 |

---

### 3.5 Assistant Domain (AI 助手领域)

#### 数据模型 (models.py)

**Conversation 表**:
```python
id: Integer (PK)
user_id: Integer (FK to users)
title: String(255)
description: Text
status: String(20)                      # active/archived/deleted
model_name: String(100)
system_prompt: Text
temperature: Integer (0-100)
max_tokens: Integer
settings: JSON
created_at, updated_at: DateTime
```

**Message 表**:
```python
id: Integer (PK)
conversation_id: Integer (FK to conversations)
role: String(20)                        # system/user/assistant/tool
content: Text
tokens: Integer
model_name: String(100)
metadata_json: JSON
created_at, updated_at: DateTime
```

**PromptTemplate 表**:
```python
id: Integer (PK)
user_id: Integer (FK to users, nullable)
name: String(255)
description: Text
category: String(100)
template: Text
variables: JSON                         # 变量名列表
is_public: Boolean
is_system: Boolean
usage_count: Integer (default=0)
created_at, updated_at: DateTime
```

**AssistantTask 表**:
```python
id: Integer (PK)
user_id: Integer (FK to users)
conversation_id: Integer (FK to conversations, nullable)
title: String(255)
description: Text
task_type: String(50)                   # reminder/research/summary
status: String(20)                      # pending/in_progress/completed/cancelled
priority: String(20)                    # low/medium/high
due_date: DateTime
completed_at: DateTime
result: Text
metadata_json: JSON
created_at, updated_at: DateTime
```

**ToolCall 表**:
```python
id: Integer (PK)
message_id: Integer (FK to messages)
tool_name: String(100)
arguments: JSON
result: JSON
status: String(20)                      # pending/completed/failed
error_message: Text
execution_time: Integer                 # 毫秒
created_at, completed_at: DateTime
```

#### 服务 (services.py)

```python
class AssistantService:
    async create_conversation(title, system_prompt, model_name) -> Conversation
    async get_conversation(conversation_id) -> Optional[Conversation]
    async add_message(conversation_id, role, content) -> Message
    async chat(conversation_id, message) -> str
    async generate_summary(conversation_id) -> str
```

#### API 路由 (api/routes.py)

| 端点 | 方法 | 功能 |
|------|------|------|
| `/conversations` | GET | 列出对话 |
| `/conversations` | POST | 创建对话 |
| `/conversations/{id}` | GET | 获取对话详情 |
| `/conversations/{id}` | PUT | 更新对话 |
| `/conversations/{id}` | DELETE | 删除对话 |
| `/conversations/{id}/messages` | GET | 获取消息列表 |
| `/conversations/{id}/messages` | POST | 发送消息 |
| `/conversations/{id}/summary` | POST | 生成摘要 |
| `/templates` | GET | 列出提示模板 |
| `/templates` | POST | 创建模板 |
| `/templates/{id}` | GET/PUT/DELETE | 模板操作 |
| `/tasks` | GET | 列出任务 |
| `/tasks` | POST | 创建任务 |
| `/tasks/{id}` | GET/PUT/DELETE | 任务操作 |

---

### 3.6 Multimedia Domain (多媒体领域)

#### 数据模型 (models.py)

**MediaFile 表**:
```python
id: Integer (PK)
user_id: Integer (FK to users)
original_filename: String(500)
file_path: String(500)
file_size: Integer
mime_type: String(100)
media_type: String(20)                  # image/audio/video/document
duration: Float                         # 音频/视频秒数
width: Integer                          # 图片/视频宽度
height: Integer                         # 图片/视频高度
checksum: String(64)                    # SHA-256
media_metadata: JSON
processed: Boolean (default=False)
created_at, updated_at: DateTime
```

**ProcessingJob 表**:
```python
id: Integer (PK)
user_id: Integer (FK to users)
media_file_id: Integer (FK to media_files)
job_type: String(50)                    # transcribe/analyze/convert/extract
status: String(20)                      # pending/processing/completed/failed/cancelled
progress: Integer (0-100)
result: JSON
error_message: Text
started_at, completed_at: DateTime
config: JSON
created_at, updated_at: DateTime
```

#### 服务 (services.py)

```python
class MultimediaService:
    async upload_file(file, user_id) -> MediaFile
    async get_media_file(media_file_id) -> Optional[MediaFile]
    async create_processing_job(media_file_id, job_type, config) -> ProcessingJob
    async get_job_status(job_id) -> Optional[ProcessingJob]
```

#### API 路由 (api/routes.py)

| 端点 | 方法 | 功能 |
|------|------|------|
| `/files` | GET | 列出媒体文件 |
| `/files` | POST | 上传文件 |
| `/files/{id}` | GET | 获取文件详情 |
| `/files/{id}` | DELETE | 删除文件 |
| `/jobs` | GET | 列出处理任务 |
| `/jobs` | POST | 创建处理任务 |
| `/jobs/{id}` | GET | 获取任务状态 |
| `/jobs/{id}/cancel` | POST | 取消任务 |

---

## 四、Admin Module (管理模块)

### 4.1 管理模块文件

| 文件 | 功能 |
|------|------|
| `router.py` | 管理路由配置 |
| `models.py` | 管理相关数据模型 |
| `schemas.py` | 管理 Pydantic 模型 |
| `audit.py` | 审计日志 |
| `csrf.py` | CSRF 保护 |
| `twofa.py` | 双因素认证 |
| `first_run.py` | 首次运行设置 |
| `monitoring.py` | 监控工具 |
| `security_settings.py` | 安全设置 |
| `storage_service.py` | 存储管理 |
| `dependencies.py` | 管理依赖 |
| `exception_handlers.py` | 异常处理 |
| `middleware.py` | 管理中间件 |

### 4.2 管理后台路由

| 路由 | 功能 |
|------|------|
| `/super/login` | 登录页面 |
| `/super/2fa/setup` | 2FA 设置 |
| `/super/dashboard` | 仪表板 |
| `/super/settings` | 系统设置 |
| `/super/audit` | 审计日志 |
| `/super/monitoring` | 系统监控 |

---

## 五、数据库迁移

### 5.1 迁移历史 (21个版本)

| 版本 | 描述 |
|------|------|
| `001_create_podcast_tables.py` | 创建播客相关表 |
| `002_add_episode_image_field.py` | 添加剧集图片字段 |
| `003_add_transcription_task_summary_columns.py` | 添加转录任务摘要字段 |
| `004_add_current_step_to_transcription_tasks.py` | 添加当前步骤字段 |
| `005_increase_api_key_column_size.py` | 增加 API 密钥列大小 |
| `007_add_podcast_conversations_table.py` | 添加播客对话表 |
| `008_add_subscription_schedule_fields.py` | 添加订阅调度字段 |
| `009_add_download_method_to_transcription_tasks.py` | 添加下载方法字段 |
| `010_add_episode_item_link.py` | 添加剧集链接字段 |
| `011_remove_download_method.py` | 移除下载方法 |
| `012_add_admin_audit_log_table.py` | 添加管理审计日志表 |
| `013_add_2fa_fields_to_users_table.py` | 添加 2FA 字段到用户表 |
| `014_add_priority_to_ai_model_configs.py` | 添加优先级到 AI 模型配置 |
| `015_add_system_settings_table.py` | 添加系统设置表 |
| `016_remove_guid_use_item_link_as_unique.py` | 移除 guid，使用 item_link 作为唯一标识 |
| `017_add_subscription_title_index.py` | 添加订阅标题索引 |
| `018_add_cascade_delete_to_podcast_foreign_keys.py` | 添加级联删除到播客外键 |
| `019_add_latest_item_published_at_to_subscriptions.py` | 添加最新项目发布时间 |
| `020_add_performance_indexes.py` | 添加性能索引 |
| `021_drop_unused_tables.py` | 删除未使用的表 |
| `add_transcription_task_table.py` | 添加转录任务表 |

---

## 六、测试结构

### 6.1 测试目录

```
tests/
├── core/                               # 核心层测试
│   └── test_final_deploy.py
├── integration/                        # 集成测试
│   └── test_forgot_password_complete_flow.py
├── performance/                        # 性能测试
│   ├── locustfile.py                   # Locust 负载测试
│   └── test_api_performance.py
├── podcast/                            # 播客测试
│   ├── test_e2e_simulation.py
│   ├── test_podcast_e2e_comprehensive.py
│   ├── ../performance/test_api_performance.py
│   └── test_podcast_workflow.py
├── test_podcast_api.py                 # API 测试
├── test_stage1.py                      # 阶段1测试
└── test_stage2.py                      # 阶段2测试
```

### 6.2 领域测试

各领域内部的测试目录:

```
app/domains/{domain}/tests/
├── test_api.py                         # API 端点测试
├── test_services.py                    # 服务测试
├── test_{feature}.py                   # 特定功能测试
```

---

## 七、API 结构总览

### 7.1 基础路径

所有 API 端点使用 `/api/v1/` 前缀

### 7.2 各领域路由

| 领域 | 路径前缀 | 标签 |
|------|----------|------|
| 用户认证 | `/api/v1/auth` | authentication |
| 订阅管理 | `/api/v1/subscriptions` | subscriptions |
| 播客 | `/api/v1/podcasts` | podcasts |
| AI 助手 | `/api/v1/assistant` | assistant |
| 多媒体 | `/api/v1/multimedia` | multimedia |
| AI 模型 | `/api/v1/ai` | ai-models |
| 管理后台 | `/super` | admin |

### 7.3 通用端点

| 端点 | 方法 | 功能 |
|------|------|------|
| `/` | GET | 欢迎页面 |
| `/health` | GET | 健康检查 |
| `/metrics` | GET | 性能指标 |
| `/docs` | GET | API 文档 (Swagger) |

---

## 八、关键配置参数

### 8.1 数据库连接池

```python
DATABASE_POOL_SIZE = 20                 # 基础连接数
DATABASE_MAX_OVERFLOW = 40              # 最大溢出连接数
DATABASE_POOL_TIMEOUT = 30              # 连接超时 (秒)
DATABASE_RECYCLE = 3600                 # 连接回收时间 (秒)
DATABASE_CONNECT_TIMEOUT = 5            # 连接超时 (秒)
```

### 8.2 JWT 配置

```python
ACCESS_TOKEN_EXPIRE_MINUTES = 30        # 访问令牌有效期
REFRESH_TOKEN_EXPIRE_DAYS = 7           # 刷新令牌有效期
ALGORITHM = "HS256"                     # 签名算法
```

### 8.3 播客配置

```python
MAX_PODCAST_SUBSCRIPTIONS = 999999      # 每用户最大订阅数
MAX_PODCAST_EPISODE_DOWNLOAD_SIZE = 500MB  # 单集最大大小
RSS_POLL_INTERVAL_MINUTES = 60          # RSS 轮询间隔
PODCAST_EPISODE_BATCH_SIZE = 50         # 批量处理大小
PODCAST_RECENT_EPISODES_LIMIT = 3       # 最近剧集数量
```

### 8.4 转录配置

```python
TRANSCRIPTION_API_URL = "https://api.siliconflow.cn/v1/audio/transcriptions"
TRANSCRIPTION_CHUNK_SIZE_MB = 10        # 分片大小 (MB)
TRANSCRIPTION_MAX_THREADS = 4           # 最大并发线程
TRANSCRIPTION_QUEUE_SIZE = 100          # 队列大小
```

### 8.5 Celery 配置

```python
CELERY_BROKER_URL = "redis://localhost:6379/0"
CELERY_RESULT_BACKEND = "redis://localhost:6379/0"
```

---

## 九、架构设计原则

### 9.1 Domain-Driven Design (DDD)

1. **Core Layer**: 基础设施，与业务无关
2. **Shared Layer**: 跨领域共享组件
3. **Domain Layer**: 业务逻辑，按领域划分
   - 每个领域包含: models, repositories, services, schemas, api
4. **Admin Module**: 独立的管理后台模块

### 9.2 依赖注入

- 使用 `dependency-injector` 库
- 在 `core/container.py` 中配置
- 支持 FastAPI 的依赖注入系统

### 9.3 异步架构

- 全面使用 `async/await`
- SQLAlchemy 2.0 with async support
- 异步数据库和 Redis 连接
- Celery 后台任务

### 9.4 测试策略

- 单元测试: 各领域内的 tests/ 目录
- 集成测试: tests/integration/
- 性能测试: tests/performance/ (使用 Locust)
- E2E 测试: tests/podcast/ 中的端到端测试

---

## 十、关键代码模式

### 10.1 仓储模式

```python
class BaseRepository(Generic[ModelType]):
    async def get_by_id(self, id: int) -> Optional[ModelType]:
        stmt = select(self.model).where(self.model.id == id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
```

### 10.2 服务模式

```python
class BaseService(Generic[ModelType]):
    def __init__(self, db: AsyncSession, model: type[ModelType], user_id: Optional[int] = None):
        self.db = db
        self.model = model
        self.user_id = user_id
```

### 10.3 FastAPI 依赖注入

```python
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()

# 在路由中使用
@router.get("/episodes")
async def list_episodes(
    db: AsyncSession = Depends(get_db_session),
    user_id: UserId = Depends(require_user_id)
):
    service = PodcastEpisodeService(db, user_id)
    return await service.list_episodes()
```

---

## 附录

### A. 环境变量

```bash
# 数据库
DATABASE_URL=postgresql+asyncpg://user:pass@localhost/dbname

# Redis
REDIS_URL=redis://localhost:6379

# JWT
SECRET_KEY=your-secret-key

# 转录 API
TRANSCRIPTION_API_KEY=your-api-key

# OpenAI
OPENAI_API_KEY=your-openai-key
```

### B. 常用命令

```bash
# 安装依赖
cd backend
uv sync --extra dev

# 数据库迁移
uv run alembic upgrade head

# 启动服务
uv run uvicorn app.main:app --reload

# 运行测试
uv run pytest

# 代码格式化
uv run black .
uv run isort .
uv run mypy .
```

### C. Docker 部署

```bash
cd docker
docker-compose -f docker-compose.podcast.yml up -d
```

---

**文档版本**: 1.0.0
**最后更新**: 2025-01-25
