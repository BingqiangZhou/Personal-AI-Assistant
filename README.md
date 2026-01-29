# Personal AI Assistant

一个可扩展的私人AI助手，集成了播客订阅、音频播放和 AI 功能。旨在通过本地化部署和 AI 能力，打造个人化的信息处理中心。

An extensible personal AI assistant that integrates podcast subscription, audio playback, and AI features. Designed to create a personalized information processing center through local deployment and AI capabilities.

## 📋 [更新日志 / Changelog](CHANGELOG.md)

查看最新的版本更新和功能改进。

Check the latest version updates and feature improvements.

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
- **自动抓取**: 自动抓取最新单集
- **批量操作**: 批量删除订阅
- **手动刷新**: 手动触发内容更新和重新解析

#### 单集管理 / Episode Management
- **懒加载分页**: 高效处理大量单集数据
- **多维度筛选**: 按订阅筛选
- **搜索功能**: 支持标题和描述搜索

#### 音频播放 / Audio Playback
- **播放器**: 基于 `audioplayers` 的完整播放器实现
- **播放控制**: 播放/暂停、快进/快退、进度条拖动
- **后台播放**: 支持后台音频播放
- **系统媒体控制**: Android/iOS 锁屏媒体控制
- **播放进度**: 记录和恢复播放进度
- **播放状态追踪**: 播放次数、完成状态

#### AI 功能（需配置）/ AI Features (Requires Configuration)
- **音频转录**: 支持 OpenAI Whisper 等转录服务
- **AI 摘要**: 使用 LLM 生成单集摘要
- **进度追踪**: 实时查看转录任务状态
- **对话功能**: 针对单集内容的 AI 对话（后端已实现）

---

### 🤖 AI 模型配置 / AI Model Configuration

- **模型管理**: 创建、更新、删除 AI 模型配置
- **多供应商支持**: OpenAI、Anthropic 等多种 AI 服务商
- **加密存储**: API Key 使用 RSA + Fernet 双重加密存储
- **连接测试**: 测试模型连接性和可用性
- **使用统计**: 追踪模型调用成功率和 Token 使用量

---

### 🎨 用户界面 / User Interface

- **Material 3 设计**: 采用最新 Material Design 3 规范
- **自适应布局**: 使用 `flutter_adaptive_scaffold` 实现桌面/平板/移动端自适应
- **双语支持**: 中英文国际化

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
    └── profile/           # 用户资料
```

#### 前端技术栈
- **框架**: Flutter 3.x - 跨平台 UI 框架
- **UI 设计**: Material 3 Design System
- **响应式布局**: flutter_adaptive_scaffold
- **状态管理**: Riverpod 2.x
- **路由**: GoRouter
- **网络**: Dio + Retrofit
- **本地存储**: Hive + flutter_secure_storage
- **音频播放**: audioplayers 6.5.1

---

## 📊 主要 API 端点 / Main API Endpoints

### 认证 / Authentication (`/api/v1/auth/`)
- `POST /register` - 用户注册
- `POST /login` - 用户登录
- `POST /refresh` - 刷新 Token
- `POST /logout` - 登出
- `GET /me` - 获取当前用户信息

### 播客 / Podcast (`/api/v1/podcasts/`)
- `POST /subscriptions` - 添加订阅
- `GET /subscriptions` - 列出订阅
- `DELETE /subscriptions/{id}` - 删除订阅
- `POST /subscriptions/bulk-delete` - 批量删除
- `POST /subscriptions/{id}/refresh` - 手动刷新
- `GET /episodes` - 列出单集（支持筛选）
- `GET /episodes/{id}` - 获取单集详情
- `PUT /episodes/{id}/playback` - 更新播放进度
- `POST /episodes/{id}/transcribe` - 开始转录
- `POST /episodes/{id}/summary` - 生成 AI 摘要

### AI 服务 / AI (`/api/v1/ai/`)
- `POST /models` - 创建模型配置
- `GET /models` - 列出模型
- `PUT /models/{id}` - 更新模型
- `DELETE /models/{id}` - 删除模型
- `POST /models/{id}/test` - 测试连接

---

## 🚀 快速开始 / Quick Start

### 前置要求 / Prerequisites
- **Docker & Docker Compose**: 推荐用于运行 PostgreSQL、Redis 和 Celery 服务
- **Python**: 3.10+
- **uv**: 推荐安装 `uv` 获得极致的包管理体验
- **Flutter**: 3.0+

### 1. 启动基础设施服务 / Start Infrastructure

```bash
cd docker

# Windows 用户 (推荐):
scripts\start.bat

# Linux/Mac 用户:
docker compose -f docker-compose.podcast.yml up -d --build
```

### 2. 后端开发环境运行 / Backend Development

```bash
cd backend

# 2.1 配置环境变量
cp .env.example .env
# 编辑 .env 文件，设置必要的配置

# 2.2 安装依赖 (使用 uv)
uv sync --extra dev

# 2.3 运行数据库迁移
uv run alembic upgrade head

# 2.4 启动 API 服务
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**API 文档**: http://localhost:8000/docs

### 3. 前端运行 / Frontend

```bash
cd frontend

# 3.1 安装依赖
flutter pub get

# 3.2 运行应用
flutter run
```

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
├── CLAUDE.md                   # Claude Code 项目指南
├── CHANGELOG.md                # 更新日志
└── README.md                   # 项目说明
```

---

## 📈 开发路线图 / Development Roadmap

### ✅ 已完成 / Completed
- [x] 用户认证和会话管理
- [x] 播客订阅和单集管理
- [x] 音频播放器（完整实现）
- [x] AI 模型配置管理
- [x] Material 3 UI 实现
- [x] Docker 部署配置

### ⚠️ 部分完成 / Partial
- [ ] AI 助手对话（UI 已完成，后端需配置）
- [ ] 播客播放器页面优化

### 📅 计划中 / Planned
- [ ] AI 转录和摘要的完整配置
- [ ] 更多播客发现功能

---

## 🤝 贡献指南 / Contributing

欢迎提交 Issue 和 Pull Request 来帮助改进这个项目。

### 开发规范
1. 遵循现有代码风格和架构模式
2. 编写测试覆盖新功能
3. 更新相关文档
4. 提交前运行 `uv run black .` 和 `flutter analyze`

---

## 📄 许可证 / License

MIT License

---

**Made with ❤️ for Personal Knowledge Management**
