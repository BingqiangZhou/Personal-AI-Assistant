# Personal AI Assistant

[![Version](https://img.shields.io/badge/version-0.13.0-blue)](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.13.0)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org/)
[![Flutter](https://img.shields.io/badge/flutter-3.0+-cyan)](https://flutter.dev/)
[![Docker](https://img.shields.io/badge/docker-supported-blue)](https://www.docker.com/)

一个可扩展的私人AI助手，集成了播客订阅、音频播放和 AI 功能。旨在通过本地化部署和 AI 能力，打造个人化的信息处理中心。

An extensible personal AI assistant that integrates podcast subscription, audio playback, and AI features. Designed to create a personalized information processing center through local deployment and AI capabilities.

**📦 当前版本 / Current Version: [v0.13.0](https://github.com/BingqiangZhou/Personal-AI-Assistant/releases/tag/v0.13.0)** (2026-02-27)

## 📋 [更新日志 / Changelog](CHANGELOG.md)

查看最新的版本更新和功能改进。

Check the latest version updates and feature improvements.

---

## 📚 文档导航 / Documentation Index

项目包含详细的技术文档和指南。以下文档按类别组织，帮助您快速找到所需信息。

The project includes comprehensive technical documentation and guides. The following documentation is organized by category to help you quickly find the information you need.

### 🏗️ 架构与设计 / Architecture & Design
- **[架构演进 / Architecture Evolution](docs/architecture-evolution.md)** - 项目架构的演进历程和设计决策
- **[ADR-001: No Unused DI Container](docs/adr/ADR-001-no-unused-di-container.md)** - 架构决策记录：避免过度依赖注入
- **[ADR-002: Route Thin, Service Thick](docs/adr/ADR-002-route-thin-service-thick.md)** - 架构决策记录：路由层轻量化设计

### 🔧 后端文档 / Backend Documentation
- **[后端 README](backend/README.md)** - 后端项目概览和快速开始
- **[环境变量配置 / Environment Variables](backend/README-ENV.md)** - 后端环境变量配置指南
- **[测试指南 / Testing Guide](backend/tests/README.md)** - 后端测试结构和规范
- **[管理面板 / Admin Panel](backend/app/admin/README.md)** - 超级管理员面板文档
- **[认证系统 / Authentication](backend/docs/AUTHENTICATION.md)** - 用户认证系统详细说明
- **[开发者快速开始 / Developer Quickstart](backend/docs/DEVELOPER_QUICKSTART.md)** - 后端开发者快速入门
- **[完整参考 / Complete Reference](docs/BACKEND_COMPLETE_REFERENCE.md)** - 后端完整技术参考

### 📱 前端文档 / Frontend Documentation
- **[前端 README](frontend/README.md)** - 前端项目概览
- **[测试架构指南 / Test Architecture Guide](frontend/docs/test_architecture_guide.md)** - Flutter 测试架构说明

### 🐳 部署文档 / Deployment Documentation
- **[部署指南 / Deployment Guide](docs/DEPLOYMENT.md)** - 完整的部署流程指南
- **[Docker 快速设置 / Docker Quick Setup](docker/QUICK_SETUP.md)** - Docker 快速设置指南
- **[Docker README](docker/README.md)** - Docker 配置说明
- **[Nginx 配置 / Nginx Configuration](docker/nginx/README.md)** - Nginx 反向代理配置
- **[SSL 设置 / SSL Setup](docker/nginx/SSL_SETUP.md)** - SSL 证书配置指南
- **[Android 签名 / Android Signing](docs/ANDROID_SIGNING.md)** - Android 应用签名配置
- **[GitHub Actions 指南 / GitHub Actions Guide](docs/GITHUB_ACTIONS_GUIDE.md)** - CI/CD 自动化部署

### 🧪 测试文档 / Testing Documentation
- **[测试结构 / Test Structure](docs/testing/TEST_STRUCTURE.md)** - 测试目录结构和规范
- **[播客功能测试 / Podcast Testing](docs/testing/PODCAST_TESTING_GUIDE.md)** - 播客功能测试指南
- **[登录 API 修复 / Login API Fix](docs/testing/LOGIN_API_FIX.md)** - 登录 API 问题修复记录

### ✨ 功能文档 / Feature Documentation
- **[转录功能 / Transcription Feature](docs/transcription-feature.md)** - 音频转录功能详细说明
- **[密码重置实现 / Password Reset Implementation](docs/implementation/PASSWORD_RESET_IMPLEMENTATION.md)** - 密码重置功能实现

### 🔄 工作流文档 / Workflow Documentation
- **[优化工作流指南 / Optimized Workflow Guide](docs/workflow/optimized-workflow-guide.md)** - 开发工作流优化
- **[工作流使用示例 / Workflow Usage Example](docs/workflow/workflow-usage-example.md)** - 工作流使用示例

### 📋 项目管理 / Project Management
- **[项目计划 / Project Plan](docs/personal-ai-assistant-plan.md)** - 个人 AI 助手项目计划
- **[发布快速参考 / Release Quick Reference](docs/RELEASE_QUICK_REF.md)** - 发布流程快速参考
- **[功能规格 / Feature Specs](specs/README.md)** - 功能规格说明目录

---

## ✨ 已实现功能 / Implemented Features

### 🔐 用户认证与会话 / Authentication & User Management

#### 认证功能 / Authentication
- **用户注册**: 邮箱注册，自动创建登录会话
- **用户登录**: 支持邮箱或用户名登录
- **JWT 认证**: Access Token + Refresh Token 双 Token 机制，自动刷新
- **多设备会话**: 管理多个登录设备，查看设备信息和 IP
- **退出登录**: 单设备退出或全部设备退出
- **密码重置**: 基于邮件的密码重置流程

#### 用户资料 / User Profile
- **个人信息**: 管理用户名、邮箱、头像、全名
- **时区设置**: 配置用户时区，显示本地化时间

---

### 🎙️ 播客管理 / Podcast Management

#### 订阅管理 / Subscription Management
- **RSS Feed 订阅**: 支持 RSS Feed 订阅，自动解析播客元数据
- **自动抓取**: 可配置的自动抓取频率（每小时/每日/每周）
- **批量操作**: 批量创建、批量删除订阅
- **手动刷新**: 手动触发内容更新和重新解析
- **分类管理 (Categories)**: 将订阅组织到自定义分类中
- **OPML 导入导出**: 通过 OPML 格式导入/导出订阅列表
- **更新频率**: 每个订阅独立的 RSS 更新计划

#### 单集管理 / Episode Management
- **懒加载分页**: 高效处理大量单集数据
- **多维度筛选**: 按订阅、是否有摘要、是否已播放筛选
- **搜索功能 (Search)**: 全文搜索播客标题、描述和 AI 摘要
- **显示笔记 (Show Notes)**: HTML 渲染显示节目详情

#### 音频播放 / Audio Playback
- **播放器**: 基于 `audioplayers 6.5.1` 的完整播放器实现
- **播放控制**: 播放/暂停、快进/快退、进度条拖动
- **后台播放**: 支持后台音频播放
- **系统媒体控制**: Android/iOS 锁屏媒体控制和通知
- **播放进度**: 记录和恢复播放进度
- **播放状态追踪**: 播放次数、完成状态

#### 播放增强功能 / Podcast Enhancements
- **播放队列 (Playback Queue)**: 添加单集到队列、重新排序、自动推进
- **播放历史 (Playback History)**: 追踪最近播放的单集，支持断点续播
- **个性化播放速度 (Playback Rate)**: 每用户和每订阅独立的播放速度偏好
- **统计信息 (Statistics)**: 收听时长、播放次数等个人统计

#### 播客发现 / Podcast Discover (v0.10.0-v0.10.2)
- **Apple Podcast 集成**: Apple Podcast RSS 榜单和推荐
- **iTunes 查询**: iTunes 单集查询和应用内预览
- **自动展开**: 滚动时自动展开更多榜单
- **分类筛选**: 按流派浏览热门播客
- **单集搜索**: 搜索iTunes上的播客单集

#### 缓存管理 / Cache Management (v0.9.0-v0.10.2)
- **清除缓存**: 一键清除应用缓存
- **分类选择**: 按类别选择性清除缓存
- **缓存统计**: 显示各类型缓存占用空间
- **性能优化**: 缓存层优化数据加载策略
- **统计缓存**: 个人统计和播放历史的缓存层

#### UI 增强 / UI Enhancements (v0.7.0-v0.10.2)
- **浮动通知**: 顶部浮动通知组件，全局状态提示
- **移动端播放器**: 底部播放器重新设计，优化的移动端体验
- **Feed 风格卡片**: 统一的卡片布局设计
- **自动收起播放器**: 导航离开播客标签时自动收起播放器
- **最近播放恢复**: 登录后自动恢复最近播放的单集
- **密集布局模式**: 高密度列表模式，适合高级用户

#### AI 转录与对话 / AI Transcription & Conversations
- **音频转录**: 支持 OpenAI Whisper 等转录服务
- **AI 摘要**: 使用 LLM 生成单集摘要
- **转录调度 (Transcription Scheduling)**: 为新单集调度自动转录
- **批量转录 (Batch Transcription)**: 批量转录订阅的所有单集
- **AI 对话 (AI Conversations)**: 与 AI 讨论单集内容（支持多会话）
- **进度追踪**: 实时查看转录任务状态
- **对话历史**: 多轮对话支持，上下文保持

---

### 🤖 AI 模型配置 / AI Model Configuration

- **模型管理**: 创建、更新、删除 AI 模型配置
- **多供应商支持**: OpenAI、Anthropic、DeepSeek 等多种 AI 服务商
- **加密存储**: API Key 使用 RSA + Fernet 双重加密存储
- **连接测试**: 测试模型连接性和可用性
- **使用统计**: 追踪模型调用成功率和 Token 使用量
- **默认模型设置**: 为不同功能类型设置默认模型
- **模型验证**: API Key 验证和连接测试

---

### 🛡️ 管理面板 / Admin Panel (`/super`)

- **仪表盘 (Dashboard)**: 系统统计概览
- **订阅管理**: 管理所有订阅，支持批量操作
- **API 密钥管理**: 管理外部访问的 API 密钥
- **用户审计日志**: 追踪用户操作
- **系统设置**: 音频处理、RSS 频率、安全（2FA）
- **初始化设置**: 首次运行设置认证

---

### 🎨 用户界面 / User Interface

- **Material 3 设计**: 采用最新 Material Design 3 规范
- **自适应布局**: 使用自定义 `AdaptiveScaffoldWrapper` 实现桌面/平板/移动端自适应
- **双语支持**: 中英文国际化
- **响应式设计**: 支持移动端（<600dp）、平板、桌面（>840dp）多种屏幕尺寸

---

### 🔧 技术功能 / Technical Features

- **Redis 缓存**: ETag 支持的高效缓存
- **性能监控**: 请求计时指标、慢请求检测

---

## 🛠️ 技术架构 / Technical Architecture

### 后端架构 (Backend - DDD)
```
backend/app/
├── core/                   # 核心基础设施层
│   ├── config/            # 配置管理
│   ├── security/          # 安全认证（JWT、加密）
│   ├── database/          # 数据库连接
│   ├── exceptions/        # 异常处理
│   └── container/         # 依赖注入容器
│
├── shared/                # 共享层
│   ├── schemas/           # 通用数据模型
│   ├── utils/             # 工具函数
│   └── constants/         # 常量定义
│
└── domains/               # 领域层（按业务功能划分）
    ├── user/              # 用户认证和会话管理
    ├── podcast/           # 播客订阅、单集、转录
    ├── assistant/         # AI 助手对话
    ├── admin/             # 管理面板
    └── ai/                # AI 服务集成和模型管理
```

#### 后端技术栈
- **框架**: FastAPI (Python 3.10+) - 高性能异步 Web 框架
- **依赖管理**: `uv` - 极速 Python 包管理器
- **数据库**: PostgreSQL 15 - 关系型数据库
- **ORM**: SQLAlchemy 2.0 (Async) - 异步 ORM
- **缓存/消息队列**: Redis 7 - 缓存和 Celery Broker
- **异步任务**: Celery 5.x - 处理耗时任务（转录、Feed 刷新）
- **任务调度**: Celery Beat - 定时任务调度
- **数据迁移**: Alembic - 数据库版本控制
- **加密**: cryptography (RSA + Fernet) - API Key 加密
- **RSS 解析**: feedparser - RSS/Atom Feed 解析

### 前端架构 (Frontend)
```
frontend/lib/
├── core/                  # 核心层
│   ├── constants/         # 常量
│   ├── error/             # 错误处理
│   ├── network/           # 网络客户端 (Dio)
│   ├── storage/           # 本地存储 (Hive)
│   └── utils/             # 工具函数
│
├── shared/                # 共享层
│   ├── widgets/           # 可复用组件
│   ├── theme/             # Material 3 主题
│   └── extensions/        # 扩展方法
│
└── features/              # 功能模块
    ├── auth/              # 登录、注册、密码重置
    ├── home/              # 首页
    ├── podcast/           # 播客订阅、单集、播放器
    ├── ai/                # AI 模型配置
    ├── profile/           # 用户资料
    └── admin/             # 管理面板
```

#### 前端技术栈
- **框架**: Flutter 3.x - 跨平台 UI 框架
- **UI 设计**: Material 3 Design System
- **响应式布局**: 自定义 AdaptiveScaffoldWrapper
- **状态管理**: Riverpod 2.x
- **路由**: GoRouter
- **网络**: Dio + Retrofit
- **本地存储**: Hive + flutter_secure_storage
- **音频播放**: audioplayers 6.5.1
- **系统媒体控制**: audio_service + audio_session

---

## 📊 API 端点 / API Endpoints

### 认证 / Authentication (`/api/v1/auth/`)
- `POST /register` - 用户注册
- `POST /login` - 用户登录（邮箱或用户名）
- `POST /refresh` - 刷新访问令牌
- `POST /logout` - 从特定设备登出
- `POST /logout-all` - 从所有设备登出
- `GET /me` - 获取当前用户信息
- `POST /forgot-password` - 请求密码重置
- `POST /reset-password` - 使用令牌重置密码

### 播客订阅 / Subscriptions (`/api/v1/subscriptions/`)
- `GET /` - 列出订阅（分页、可筛选）
- `POST /` - 创建新订阅
- `POST /batch` - 批量创建订阅
- `GET /{id}` - 按 ID 获取订阅
- `PUT /{id}` - 更新订阅
- `DELETE /{id}` - 删除订阅
- `POST /{id}/fetch` - 手动触发 RSS 抓取
- `POST /fetch-all` - 抓取所有活跃 RSS 订阅
- `GET /{id}/items/` - 获取订阅的单集
- `POST /items/{item_id}/read` - 标记为已读
- `POST /items/{item_id}/unread` - 标记为未读
- `POST /items/{item_id}/bookmark` - 切换书签状态
- `GET /items/unread-count` - 获取未读单集总数
- `GET /categories/` - 列出所有用户的分类
- `POST /categories/` - 创建新分类
- `PUT /categories/{category_id}` - 更新分类
- `DELETE /categories/{category_id}` - 删除分类
- `POST /{id}/categories/{category_id}` - 添加订阅到分类
- `DELETE /{id}/categories/{category_id}` - 从分类移除订阅
- `POST /opml/import` - 导入 OPML 订阅列表
- `GET /opml/export` - 导出 OPML 订阅列表

### 播客单集 / Episodes (`/api/v1/podcasts/episodes/`)
- `GET /feed` - 获取所有已订阅单集（按发布时间排序）
- `GET /` - 列出单集（支持筛选：订阅、是否有摘要、是否已播放）
- `GET /history` - 列出播放历史
- `GET /history-lite` - 轻量级播放历史（用于卡片）
- `GET /{episode_id}` - 获取单集详情和摘要
- `POST /{episode_id}/summary` - 生成/重新生成 AI 摘要
- `PUT /{episode_id}/playback` - 更新播放进度
- `GET /{episode_id}/playback` - 获取播放状态
- `GET /playback/rate/effective` - 获取有效播放速度偏好
- `PUT /playback/rate/apply` - 应用播放速度偏好
- `GET /summaries/pending` - 列出待生成摘要的单集
- `GET /summaries/models` - 列出可用的摘要模型
- `GET /search` - 搜索播客内容（标题、描述、摘要）
- `GET /recommendations` - 获取播客推荐

### 播放队列 / Queue (`/api/v1/podcasts/queue/`)
- `GET /` - 获取播放队列
- `POST /items` - 添加单集到队列
- `DELETE /items/{episode_id}` - 从队列移除
- `PUT /items/reorder` - 重新排序队列
- `POST /current` - 设置当前队列单集
- `POST /current/complete` - 完成当前并推进

### 统计信息 / Stats (`/api/v1/podcasts/stats/`)
- `GET /` - 获取用户收听统计（支持 ETag 缓存）
- `GET /profile` - 获取轻量级个人统计（用于卡片）

### 转录 / Transcriptions (`/api/v1/podcasts/episodes/`)
- `POST /{episode_id}/transcribe` - 开始转录任务
- `GET /{episode_id}/transcription` - 获取转录详情
- `DELETE /{episode_id}/transcription` - 删除转录
- `GET /transcriptions/{task_id}/status` - 获取任务状态
- `POST /{episode_id}/transcribe/schedule` - 调度转录
- `GET /{episode_id}/transcript` - 获取已有转录文本
- `POST /subscriptions/{subscription_id}/transcribe/batch` - 批量转录订阅
- `GET /{episode_id}/transcription/schedule-status` - 获取调度状态
- `POST /{episode_id}/transcription/cancel` - 取消转录
- `POST /subscriptions/{subscription_id}/check-new-episodes` - 检查并转录新单集
- `GET /transcriptions/pending` - 获取待处理转录任务

### 对话 / Conversations (`/api/v1/podcasts/episodes/`)
- `GET /{episode_id}/conversation-sessions` - 列出对话会话
- `POST /{episode_id}/conversation-sessions` - 创建对话会话
- `DELETE /{episode_id}/conversation-sessions/{session_id}` - 删除会话
- `GET /{episode_id}/conversations` - 获取对话历史
- `POST /{episode_id}/conversations` - 发送消息并获取 AI 回复
- `DELETE /{episode_id}/conversations` - 清除对话历史

### AI 模型 / AI Models (`/api/v1/ai/`)
- `POST /models` - 创建 AI 模型配置
- `GET /models` - 列出模型（可按类型、活跃状态、供应商筛选）
- `GET /models/{model_id}` - 获取模型详情（可选解密密钥）
- `PUT /models/{model_id}` - 更新模型配置
- `DELETE /models/{model_id}` - 删除模型
- `POST /models/{model_id}/set-default` - 设为类型的默认模型
- `GET /models/default/{model_type}` - 获取类型的默认模型
- `GET /models/active/{model_type}` - 获取类型的所有活跃模型
- `POST /models/{model_id}/test` - 测试模型连接
- `GET /models/{model_id}/stats` - 获取模型使用统计
- `GET /models/stats/{model_type}` - 获取类型的所有模型统计
- `POST /models/init-defaults` - 初始化系统默认模型
- `POST /models/validate-api-key` - 验证 API 密钥连接
- `GET /security/rsa-public-key` - 获取 RSA 公钥用于客户端加密

### 管理面板 / Admin Panel (`/super/`)
- 仪表盘、设置、订阅、API 密钥、用户审计、初始化认证等相关路由

---

## 🚀 快速开始 / Quick Start

### 前置要求 / Prerequisites
- **Docker & Docker Compose**: 推荐用于运行 PostgreSQL、Redis 和 Celery 服务
- **Python**: 3.10+
- **uv**: 推荐安装 `uv` 获得极致的包管理体验
- **Flutter**: 3.0+

### 平台特定说明 / Platform-Specific Notes

#### Windows
- 推荐使用 WSL2 或 Git Bash 运行命令
- 使用 `scripts\start.bat` 快速启动 Docker 服务
- 确保 Docker Desktop 已启动并分配足够资源（建议 4GB+ 内存）

#### Linux
- 确保用户在 docker 组中：`sudo usermod -aG docker $USER`
- 使用 `docker compose`（新语法）而非 `docker-compose`
- 检查防火墙设置，确保端口 8000、5432、6379 可访问

#### macOS
- Docker Desktop for Mac 需要分配足够资源
- 可能需要调整文件共享设置以获得最佳性能

### 1. 启动基础设施服务 / Start Infrastructure

```bash
cd docker

# Windows 用户 (推荐):
scripts\start.bat

# Linux/Mac 用户:
docker compose -f docker-compose.podcast.yml up -d --build
```

**💡 提示 / Tip**: 首次启动需要构建镜像，请耐心等待。查看 [Docker README](docker/README.md) 了解更多配置选项。

### 2. 后端开发环境运行 / Backend Development

```bash
cd backend

# 2.1 配置环境变量
cp .env.example .env
# 编辑 .env 文件，设置必要的配置
# 详见 [环境变量配置指南](backend/README-ENV.md)

# 2.2 安装依赖 (使用 uv)
uv sync --extra dev

# 2.3 运行数据库迁移
uv run alembic upgrade head

# 2.4 启动 API 服务
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**API 文档**: http://localhost:8000/docs

**🐳 Docker 验证（推荐）**: 所有后端测试必须通过 Docker 验证，详见 [Docker 快速设置](docker/QUICK_SETUP.md)

### 3. 前端运行 / Frontend

```bash
cd frontend

# 3.1 安装依赖
flutter pub get

# 3.2 运行应用
flutter run

# 指定设备运行：
# flutter run -d chrome          # Web
# flutter run -d windows         # Windows Desktop
# flutter run -d macos           # macOS Desktop
# flutter run                   # 连接的移动设备
```

**💡 提示 / Tip**: 首次运行需要下载 Flutter 依赖，可能需要几分钟。

### 常见问题排查 / Troubleshooting

| 问题 / Issue | 解决方案 / Solution |
|-------------|-------------------|
| Docker 启动失败 | 检查 Docker Desktop 是否运行，查看 [Docker README](docker/README.md) |
| 端口冲突 | 修改 `docker/.env` 中的端口配置 |
| 数据库连接失败 | 确认 PostgreSQL 容器已启动：`docker ps` |
| Flutter 依赖解析失败 | 运行 `flutter clean` 后重试 |
| 后端测试失败 | 必须在 Docker 容器中运行，不要使用 `uv run` 本地测试 |

更多问题排查，请参考 [Docker 快速设置指南](docker/QUICK_SETUP.md) 和 [测试文档](docs/testing/TEST_STRUCTURE.md)。

### 下一步 / Next Steps
- 📖 阅读 [后端开发指南](backend/README.md)
- 📱 查看 [前端测试架构](frontend/docs/test_architecture_guide.md)
- 🚀 了解 [部署流程](docs/DEPLOYMENT.md)
- 🧪 运行 [测试套件](docs/testing/TEST_STRUCTURE.md)

---

## 📂 项目结构 / Project Structure

```
personal-ai-assistant/
├── backend/                    # FastAPI 后端应用
│   ├── app/
│   │   ├── core/               # 核心基础设施
│   │   ├── shared/             # 共享层
│   │   ├── domains/            # 业务领域（DDD）
│   │   ├── integration/        # 外部集成
│   │   └── main.py             # 应用入口
│   ├── alembic/                # 数据库迁移
│   ├── tests/                  # 测试文件
│   └── pyproject.toml          # uv 依赖配置
│
├── frontend/                   # Flutter 前端应用
│   ├── lib/
│   │   ├── core/               # 核心层
│   │   ├── shared/             # 共享层
│   │   └── features/           # 功能模块
│   ├── test/                   # 测试文件
│   └── pubspec.yaml            # Flutter 依赖配置
│
├── docker/                     # Docker 部署
│   └── docker-compose.podcast.yml
│
├── docs/                       # 详细文档
├── specs/                      # 功能规格说明
├── CLAUDE.md                   # Claude Code 项目指南
├── CHANGELOG.md                # 更新日志
└── README.md                   # 项目说明
```

---

## 🧪 测试要求 / Testing Requirements

### 后端测试 / Backend Testing
- **必须通过 Docker 验证**: 所有后端测试必须通过 Docker 容器运行
- **代码检查**: `uv run ruff check .`
- **代码格式化**: `uv run ruff format .`
- **单元测试**: `uv run pytest`

### 前端测试 / Frontend Testing
- **Widget 测试强制**: 页面功能必须编写 Widget 测试
- **运行 Widget 测试**: `flutter test test/widget/`
- **多屏幕测试**: 必须在移动端（<600dp）、桌面（>840dp）等多种屏幕尺寸下测试

### 质量关卡 / Quality Gates

任务完成的必要条件：
- ✅ 代码编译无错误
- ✅ 后端 Docker 容器成功启动
- ✅ 后端 API 正确响应（`curl http://localhost:8000/api/v1/health`）
- ✅ 所有后端测试通过
- ✅ 前端编译并运行
- ✅ 所有前端测试通过
- ✅ 修改的功能端到端正常工作

---

## 📈 开发路线图 / Development Roadmap

### ✅ 已完成 / Completed

#### 核心功能 / Core Features
- [x] 用户认证和会话管理（含多设备、密码重置）
- [x] 播客订阅和单集管理
- [x] 音频播放器（完整实现，含系统媒体控制）
- [x] AI 模型配置管理（多供应商、加密存储）
- [x] Material 3 UI 实现（自定义 AdaptiveScaffoldWrapper）
- [x] Docker 部署配置

#### 播客增强 / Podcast Enhancements
- [x] AI 对话功能（关于单集的多会话对话）
- [x] 播放队列管理（添加、重新排序、自动推进）
- [x] 播放历史追踪（断点续播）
- [x] 最近播放恢复（登录后自动恢复）
- [x] 分类管理（自定义分类组织）
- [x] 搜索功能（全文搜索标题、描述、摘要）
- [x] 统计信息（收听时长、播放次数）
- [x] 个性化播放速度（每用户、每订阅）
- [x] 睡眠定时器
- [x] 转录调度（自动转录新单集）

#### 播客发现 / Discover (v0.10.0)
- [x] Apple Podcast RSS 榜单集成
- [x] iTunes 单集查询和应用内预览
- [x] 自动展开滚动加载
- [x] 分类筛选

#### UI/UX 改进 / UI Improvements
- [x] 浮动通知组件
- [x] 移动端底部播放器重新设计
- [x] Feed 风格卡片布局
- [x] 自动收起播放器
- [x] 播放列表项显示进度

#### 性能优化 / Performance (v0.10.1-v0.10.2)
- [x] 应用启动优化和本地缓存
- [x] 缓存管理（清除缓存、分类选择）
- [x] 统计和历史的缓存层
- [x] 队列操作优化
- [x] Redis ETag 缓存支持

#### 管理功能 / Admin Features
- [x] 管理面板（`/super` 路由）
- [x] OPML 导入导出
- [x] 显示笔记渲染（HTML 支持）
- [x] 用户审计日志

### 📅 计划中 / Planned

#### 短期计划 / Short-term
- [ ] 更多播客发现功能和推荐
- [ ] 播放列表跨设备同步

#### 长期计划 / Long-term
- [ ] 离线模式支持（下载单集用于离线播放）
- [ ] 社交功能（分享单集、订阅）
- [ ] 播客评论和评分
- [ ] 智能推荐（基于 AI）
- [ ] 多语言字幕支持

---

## 🤝 贡献指南 / Contributing

欢迎提交 Issue 和 Pull Request 来帮助改进这个项目。

### 开发规范 / Development Guidelines

#### 代码风格 / Code Style
1. **遵循现有代码风格和架构模式（DDD）**
   - 后端：按照 domain-driven design 组织代码
   - 前端：使用 feature-based 架构

2. **包管理 / Package Management**
   - **后端必须使用** `uv` 进行包管理，**禁止使用 pip**
   - 前端使用 `flutter pub` 管理依赖

3. **测试要求 / Testing Requirements**
   - **后端测试必须通过 Docker 验证**，不能仅使用 `uv run` 本地测试
   - 前端页面功能必须编写 Widget 测试
   - 编写测试覆盖新功能（后端 pytest、前端 Widget 测试）

4. **文档更新 / Documentation**
   - 更新相关文档（API 变更、新功能说明）
   - 更新 CHANGELOG（使用 [release](/.claude/skills/release.md) skill）

5. **提交前质量检查 / Pre-commit Quality Checks**
   - 后端: `uv run ruff check .` 和 `uv run pytest`
   - 前端: `flutter analyze` 和 `flutter test test/widget/`

#### 开发工作流 / Development Workflow

##### 分支命名 / Branch Naming
- `feature/功能名称` - 新功能开发
- `fix/问题描述` - Bug 修复
- `refactor/重构内容` - 代码重构
- `docs/文档更新` - 文档更新

##### 提交规范 / Commit Conventions
使用 Conventional Commits 格式：
- `feat: 添加新功能`
- `fix: 修复 bug`
- `refactor: 代码重构`
- `docs: 文档更新`
- `test: 测试相关`
- `chore: 构建/工具相关`

**💡 提示**: 使用项目内置的 `/commit` 命令自动生成规范的提交信息。

##### Pull Request 流程 / PR Workflow
1. Fork 项目并创建功能分支
2. 进行开发和测试（通过 Docker 验证后端）
3. 提交代码并推送到远程仓库
4. 创建 Pull Request，填写 PR 模板
5. 等待代码审查和 CI/CD 检查
6. 根据反馈进行修改
7. 合并后删除功能分支

### 技术栈关键注意事项 / Gotchas

| ❌ 错误做法 | ✅ 正确做法 |
|---------|-----------|
| `pip install` | `uv add` 或 `uv sync` |
| 本地使用 `uv run` 进行测试 | 通过 Docker 容器进行测试 |
| 直接使用 `uvicorn` 测试 | 使用 Docker 进行测试 |
| Material 2 组件 | 仅使用 Material 3 |
| 跳过 Widget 测试 | 页面功能必须编写 Widget 测试 |
| 任意提交信息 | 使用 Conventional Commits 格式 |

### 相关文档 / Related Documentation
- [测试结构指南](docs/testing/TEST_STRUCTURE.md)
- [播客功能测试指南](docs/testing/PODCAST_TESTING_GUIDE.md)
- [发布流程快速参考](docs/RELEASE_QUICK_REF.md)
- [GitHub Actions 指南](docs/GITHUB_ACTIONS_GUIDE.md)

---

## 📄 许可证 / License

MIT License

---

**Made with ❤️ for Personal Knowledge Management**
