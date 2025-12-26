# Personal AI Assistant

一个可扩展的私人AI助手，集成了播客订阅、转录、AI摘要和知识库管理功能。旨在通过本地化部署和AI能力，打造个人化的信息处理中心。

An extensible personal AI assistant that integrates podcast subscription, transcription, AI summarization, and knowledge base management. Designed to create a personalized information processing center through local deployment and AI capabilities.

## 📋 [更新日志 / Changelog](CHANGELOG.md)

查看最新的版本更新和功能改进。

Check the latest version updates and feature improvements.

---

## ✨ 核心特性 / Core Features

### 🎙️ 播客管理 / Podcast Management
- **订阅管理 / Subscription**: 支持 RSS Feed 订阅，自动抓取最新单集 / RSS Feed subscription with automatic episode fetching
- **智能播放 / Smart Playback**: 内置 Flutter 播放器，支持后台播放、进度记忆 / Built-in Flutter player with background playback and progress tracking
- **AI 转录 / AI Transcription**: 集成 OpenAI Whisper 和 Azure Speech Services，将音频转化为文本 / Integrated with OpenAI Whisper and Azure Speech Services for audio-to-text conversion
- **智能摘要 / Smart Summary**: 利用 LLM (GPT-4, Claude 等) 自动生成单集摘要和关键点提取 / Auto-generate episode summaries and key points using LLMs (GPT-4, Claude, etc.)
- **全文搜索 / Full-text Search**: 支持对转录内容的全文检索，快速定位感兴趣片段 / Full-text search across transcripts for quick content discovery
- **AI 对话 / AI Conversation**: 与播客单集内容进行智能问答 / Intelligent Q&A based on episode content

### 🤖 AI 集成 / AI Integration
- **多模型支持 / Multi-model Support**: 支持配置不同的 LLM 模型 (OpenAI, Anthropic 等) 用于摘要和对话 / Support for various LLM models (OpenAI, Anthropic, etc.) for summaries and conversations
- **灵活配置 / Flexible Configuration**: 可动态管理 API Key 和模型参数 / Dynamic API key and model parameter management
- **加密存储 / Encrypted Storage**: API Key 使用 RSA + Fernet 加密存储 / API keys encrypted with RSA + Fernet

### 🧠 AI 助手 / AI Assistant
- **对话管理 / Conversation Management**: 创建和管理多个对话会话，支持对话历史 / Create and manage multiple conversations with history
- **上下文保持 / Context Retention**: 保持对话上下文，实现连续对话 / Maintain conversation context for continuous dialogue
- **提示词模板 / Prompt Templates**: 创建可复用的提示词模板 / Create reusable prompt templates

### 📚 知识库 / Knowledge Base
- **知识库管理 / Knowledge Base Management**: 创建多个知识库，支持分类组织 / Create and organize multiple knowledge bases
- **文档管理 / Document Management**: 上传、存储和检索文档 / Upload, store, and retrieve documents
- **跨库搜索 / Cross-base Search**: 在所有知识库中搜索内容 / Search across all knowledge bases

### 📰 订阅管理 / Subscription Management
- **Feed 订阅 / Feed Subscription**: 支持 RSS/API Feed 订阅 / Support for RSS/API feed subscriptions
- **内容同步 / Content Sync**: 自动同步订阅内容 / Automatic content synchronization
- **分类管理 / Category Management**: 使用分类组织订阅 / Organize subscriptions with categories
- **阅读状态 / Reading Status**: 跟踪已读/未读状态，支持收藏 / Track read/unread status with bookmark support

### 🎬 多媒体处理 / Multimedia Processing
- **文件上传 / File Upload**: 支持图片、音频、视频、文档上传 / Support for image, audio, video, and document uploads
- **音频转录 / Audio Transcription**: 后台异步音频转录任务 / Asynchronous background audio transcription
- **图片分析 / Image Analysis**: 物体检测、人脸识别、OCR、情绪识别 / Object detection, face recognition, OCR, emotion recognition
- **任务管理 / Job Management**: 实时跟踪处理任务状态 / Real-time processing job status tracking

### 🔐 认证与用户 / Authentication & User
- **多种登录方式 / Multiple Login Methods**: 支持邮箱或用户名登录 / Login with email or username
- **JWT 认证 / JWT Authentication**: Access + Refresh Token 双 Token 机制 / Dual-token mechanism with access and refresh tokens
- **多设备支持 / Multi-device Support**: 管理多个登录会话 / Manage multiple login sessions
- **密码重置 / Password Reset**: 邮件重置密码流程 / Email-based password reset flow

## 🛠️ 技术架构

### 后端 (Backend)
- **核心框架**: FastAPI (Python 3.10+)
- **依赖管理**: `uv` (高性能Python包管理器)
- **数据库**: PostgreSQL (业务数据)
- **缓存/队列**: Redis (缓存与Celery Broker)
- **ORM**: SQLAlchemy 2.0 (Async)
- **异步任务**: Celery (处理音频转录、下载、Feed刷新等耗时任务)

### 前端 (Frontend)
- **框架**: Flutter 3.x (跨平台移动端/桌面端)
- **状态管理**: Riverpod 2.0
- **路由**: GoRouter
- **网络**: Dio + Retrofit
- **本地存储**: Hive + Flutter Secure Storage

## 🚀 快速开始

### 前置要求
- **Docker**: 推荐用于运行 PostgreSQL, Redis 和 Celery Worker。
- **Python**: 3.10+
- **uv**: 推荐安装 `uv` 获得极致的包管理体验。
- **Flutter**: 3.0+

### 1. 启动基础设施
项目提供了 Docker Compose配置来一键启动数据库和后台任务服务。

```bash
cd docker

# Windows 用户 (推荐):
scripts\start.bat

# Linux/Mac 用户:
docker compose -f docker-compose.podcast.yml up -d --build
```
> **注意**: `docker-compose.podcast.yml` 包含了 Postgres, Redis, Celery Worker 和 Celery Beat 服务。

### 2. 后端开发环境运行

如果您需要开发或调试后端代码：

```bash
cd backend

# 2.1 配置环境变量
cp .env.example .env
# 编辑 .env 文件，设置必要的配置 (如 API Keys, 数据库连接)

# 2.2 安装依赖
uv sync

# 2.3 运行数据库迁移 (确保数据库表结构最新)
uv run python database_migration.py

# 2.4 启动 API 服务
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
API 文档地址: http://localhost:8000/docs

### 3. 前端运行

```bash
cd frontend

# 3.1 安装依赖
flutter pub get

# 3.2 启动应用
flutter run
```

## 📂 项目结构

```
personal-ai-assistant/
├── backend/                # FastAPI 后端应用
│   ├── app/
│   │   ├── core/           # 核心配置 (Config, DB, Security)
│   │   ├── domains/        # 业务领域 (Podcast, AI, User...)
│   │   ├── integration/    # 外部集成 (LLM, Transcribers)
│   │   └── main.py         # 入口文件
│   ├── pyproject.toml      # uv 依赖管理配置
│   └── alembic/            # 数据库版本控制
│
├── frontend/               # Flutter 移动端应用
│   ├── lib/
│   │   ├── features/       # 业务功能模块
│   │   └── core/           # 核心组件
│
├── docker/                 # Docker 部署配置
│   ├── docker-compose.podcast.yml # 完整服务编排
│   └── scripts/            # 启动脚本
│
└── docs/                   # 详细文档
```

## 🤝 贡献
欢迎提交 Issue 和 Pull Request 帮助改进这个项目。

## 📄 许可证
MIT License