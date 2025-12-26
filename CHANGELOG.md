# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.0.1] - 2025-01-XX

### 🎉 首次公开版本 / Initial Public Release

这是 Personal AI Assistant 的首个公开版本，提供了完整的播客订阅、AI 转录、知识库管理和 AI 助手对话功能。

This is the first public release of Personal AI Assistant, providing complete podcast subscription, AI transcription, knowledge base management, and AI assistant conversation features.

---

## 📦 Added / 新增

### 🎙️ Podcast Management / 播客管理

- **RSS 订阅管理**
  - 订阅/取消订阅播客 RSS Feed
  - 批量导入播客订阅
  - 自动刷新获取最新单集
  - 支持分类管理播客订阅

- **音频播放**
  - 内置音频播放器，支持播放/暂停/进度控制
  - 播放状态持久化（记录播放进度、播放次数）
  - 支持倍速播放
  - 后台播放支持

- **AI 转录 (AI Transcription)**
  - 集成 OpenAI Whisper 和 Azure Speech Services
  - 支持音频分块转录大文件
  - 转录状态实时跟踪
  - 批量转录播客单集
  - 定时自动转录新单集

- **AI 摘要 (AI Summary)**
  - 使用 LLM (GPT-4, Claude 等) 自动生成单集摘要
  - 提取关键点和亮点
  - 支持多种 AI 模型配置

- **内容搜索**
  - 对转录内容进行全文搜索
  - 快速定位感兴趣的内容片段

- **AI 对话 (AI Conversation)**
  - 与单集内容进行 AI 对话
  - 基于转录内容的智能问答

### 🤖 AI Integration / AI 集成

- **多模型支持**
  - OpenAI GPT 系列 (GPT-3.5, GPT-4)
  - Anthropic Claude 系列
  - 自定义 API 端点支持

- **模型管理**
  - 动态配置 AI 模型参数
  - API Key 加密存储（RSA + Fernet）
  - 模型测试和验证
  - 默认模型设置
  - 使用统计跟踪

### 🧠 AI Assistant / AI 助手

- **对话管理**
  - 创建和管理多个对话会话
  - 对话历史记录
  - 归档和删除对话

- **消息处理**
  - 发送消息并获取 AI 回复
  - 上下文保持的对话
  - 消息 CRUD 操作

- **提示词模板**
  - 创建可复用的提示词模板
  - 模板管理

### 📚 Knowledge Base / 知识库

- **知识库管理**
  - 创建多个知识库
  - 知识库 CRUD 操作

- **文档管理**
  - 上传文档到知识库
  - 文档内容存储和检索
  - 跨知识库搜索

### 📰 Subscription Management / 订阅管理

- **Feed 订阅**
  - RSS/API Feed 订阅
  - 批量创建订阅

- **内容管理**
  - 获取订阅内容
  - 已读/未读状态跟踪
  - 收藏/书签功能

- **分类管理**
  - 创建和管理分类
  - 将订阅添加到分类

### 🎬 Multimedia Processing / 多媒体处理

- **文件上传**
  - 支持图片、音频、视频、文档上传
  - 文件元数据提取

- **音频处理**
  - 音频转录任务
  - 后台异步处理

- **图片分析**
  - 物体检测
  - 人脸识别
  - 文字提取 (OCR)
  - 情绪识别

- **视频处理**
  - 关键帧提取
  - 音频提取

### 🔐 Authentication & User Management / 认证与用户管理

- **用户认证**
  - 邮箱/用户名注册
  - 邮箱/用户名登录
  - JWT Token 认证（Access + Refresh Token）
  - Token 自动刷新

- **会话管理**
  - 多设备会话支持
  - 登出单个设备或所有设备

- **密码管理**
  - 忘记密码流程
  - 邮件重置密码

### ⚙️ Settings & Configuration / 设置与配置

- **应用设置**
  - 语言切换（中文/英文）
  - 主题配置

- **全局配置**
  - AI 模型全局默认设置
  - 转录调度配置

### 🏗️ Architecture & Infrastructure / 架构与基础设施

- **后端 (Backend)**
  - FastAPI 框架
  - 异步支持 (Async/Await)
  - SQLAlchemy 2.0 ORM
  - PostgreSQL 数据库
  - Redis 缓存
  - Celery 异步任务队列
  - Alembic 数据库迁移
  - 双语错误消息（中文/英文）

- **前端 (Frontend)**
  - Flutter 3.x 框架
  - Riverpod 状态管理
  - GoRouter 路由
  - Material 3 设计系统
  - 自适应布局（桌面/Web/移动端）
  - 双语支持（中文/英文）

- **DevOps**
  - Docker 容器化部署
  - GitHub Actions CI/CD
  - 多平台自动构建（Windows/Linux/macOS/Android）

---

## 🎯 API Endpoints / API 端点

### 认证 (`/api/v1/auth`)
- `POST /register` - 用户注册
- `POST /login` - 用户登录
- `POST /refresh` - 刷新 Token
- `POST /logout` - 登出
- `POST /logout-all` - 登出所有设备
- `GET /me` - 获取当前用户信息
- `POST /forgot-password` - 请求重置密码
- `POST /reset-password` - 重置密码

### 播客 (`/api/v1/podcasts`)
- `POST /subscriptions` - 添加播客订阅
- `POST /subscriptions/bulk` - 批量添加订阅
- `GET /subscriptions` - 获取订阅列表
- `GET /episodes` - 获取单集列表
- `GET /episodes/{id}` - 获取单集详情
- `POST /episodes/{id}/transcribe` - 开始转录
- `GET /episodes/{id}/transcript` - 获取转录文本
- `POST /episodes/{id}/summary` - 生成 AI 摘要
- `POST /episodes/{id}/conversations` - 与单集对话
- `PUT /episodes/{id}/playback` - 更新播放进度
- `GET /search` - 搜索播客内容
- `GET /stats` - 获取统计信息

### AI 模型 (`/api/v1/ai`)
- `POST /models` - 创建模型配置
- `GET /models` - 获取模型列表
- `POST /models/{id}/test` - 测试模型连接
- `POST /models/{id}/set-default` - 设置默认模型
- `GET /models/default/{type}` - 获取默认模型

### AI 助手 (`/api/v1/assistant`)
- `GET /conversations` - 获取对话列表
- `POST /conversations` - 创建对话
- `POST /chat` - 发送消息并获取 AI 回复
- `GET /prompts` - 获取提示词模板
- `POST /prompts` - 创建提示词模板

### 知识库 (`/api/v1/knowledge`)
- `GET /bases/` - 获取知识库列表
- `POST /bases/` - 创建知识库
- `POST /bases/{id}/documents/` - 创建文档
- `POST /bases/{id}/documents/upload` - 上传文档
- `POST /search` - 搜索知识库

### 订阅 (`/api/v1/subscriptions`)
- `GET /subscriptions/` - 获取订阅列表
- `POST /subscriptions/` - 创建订阅
- `POST /subscriptions/batch` - 批量创建订阅
- `GET /subscriptions/{id}/items/` - 获取订阅内容
- `POST /subscriptions/items/{id}/read` - 标记为已读
- `GET /categories/` - 获取分类列表

### 多媒体 (`/api/v1/multimedia`)
- `POST /files/upload` - 上传媒体文件
- `POST /files/{id}/transcribe` - 转录音频
- `POST /files/{id}/analyze` - 分析图片
- `GET /jobs/{id}` - 获取处理任务状态

---

## 📊 Statistics / 统计数据

| 指标 | 数量 |
|------|------|
| 后端业务领域 | 7 |
| 前端功能模块 | 13 |
| API 端点组 | 7 |
| 总 API 端点 | 100+ |
| 数据库模型 | 20+ |
| 前端页面 | 30+ |
| 前端组件 | 15+ |

---

## 🙏 Acknowledgments / 致谢

感谢所有为本项目做出贡献的开发者和用户。

Thanks to all developers and users who contributed to this project.

---

## 📝 Notes / 说明

- 这是一个功能完整的 MVP 版本
- 部分功能仍在持续改进中
- 欢迎提交 Issue 和 Pull Request

This is a fully functional MVP version.
Some features are still being improved.
Issues and Pull Requests are welcome.

---

[0.0.1]: https://github.com/YOUR_USERNAME/YOUR_REPO/releases/tag/v0.0.1
