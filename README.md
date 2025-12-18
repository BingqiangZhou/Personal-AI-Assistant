# Personal AI Assistant

一个可扩展的个人AI助手工具，支持信息流订阅、知识库管理和多媒体处理功能。

## 技术架构

### 后端 (FastAPI)
- **框架**: FastAPI (Python异步框架)
- **数据库**: PostgreSQL + Redis
- **ORM**: SQLAlchemy (异步)
- **认证**: JWT Token
- **任务队列**: Celery
- **API文档**: 自动生成的OpenAPI文档

### 前端 (Flutter)
- **框架**: Flutter (跨平台)
- **状态管理**: Riverpod
- **路由**: GoRouter
- **HTTP客户端**: Dio + Retrofit
- **本地存储**: Hive + SharedPreferences
- **安全存储**: Flutter Secure Storage

## 项目结构

```
personal-ai-assistant/
├── docker/                     # Docker部署目录 ⭐
│   ├── docker-compose.podcast.yml    # 主配置文件
│   ├── README.md                      # 说明文档
│   └── scripts/
│       └── start.bat                 # Windows一键启动
│
├── backend/                    # FastAPI后端
│   ├── app/
│   │   ├── core/              # 核心基础设施 (config, security, database)
│   │   ├── shared/            # 共享组件 (schemas, utils, constants)
│   │   ├── domains/           # 业务域 (user, subscription, podcast, knowledge...)
│   │   └── integration/       # 集成层 (connectors, workers, events)
│   ├── alembic/               # 数据库迁移
│   ├── tests/                 # 测试文件 (归类: core, podcast, ...)
│   ├── pyproject.toml         # uv依赖配置
│   └── README.md              # 后端开发文档
│
├── frontend/                   # Flutter前端
│   ├── lib/
│   │   ├── core/              # 核心功能
│   │   ├── shared/            # 共享组件
│   │   └── features/          # 功能模块
│   ├── assets/                # 资源文件
│   ├── test/                  # 测试文件
│   └── pubspec.yaml           # Flutter依赖
│
├── scripts/                    # 脚本文件
│   └── init.sql               # 数据库初始化
│
├── docs/                       # 文档目录
│   ├── architecture-evolution.md # 架构演进
│   └── DEPLOYMENT.md          # 部署说明
│
├── .claude/                    # Claude Code配置 ✨
│   ├── agents/                 # 智能代理定义
│   ├── agents.json             # 代理配置
│   └── commands/               # 自定义命令
│
├── docker-compose.yml          # 根目录Docker配置
├── .env.example               # 环境变量模板
├── README.md                   # 项目说明 (本文件)
├── CLAUDE.md                   # 项目开发指南
└── CLEANUP_SUMMARY.md          # 清理总结文档
```

## 设计模式应用

### 后端设计模式
1. **仓储模式 (Repository Pattern)**: 抽象数据访问层
2. **工厂模式 (Factory Pattern)**: 管理各种类型的连接器
3. **策略模式 (Strategy Pattern)**: 灵活处理不同类型的内容
4. **观察者模式 (Observer Pattern)**: 实现事件驱动架构
5. **依赖注入 (Dependency Injection)**: 使用 dependency-injector 实现

### 前端设计模式
1. **MVVM架构**: 分离UI和业务逻辑
2. **仓储模式**: 抽象数据源
3. **提供者模式 (Provider Pattern)**: 使用Riverpod管理状态
4. **单例模式**: 管理全局资源

## 快速开始

### 环境要求
- Python 3.10+
- Flutter 3.1.0+
- PostgreSQL 15+
- Redis 7+
- Docker (可选，推荐)

### 后端部署 (推荐2种方式)

####  🐳 方式1: Docker Compose (5分钟，最简单)
```bash
# 进入docker目录
cd docker

# 方式A: Windows用户，双击运行
scripts\start.bat

# 方式B: 命令行
docker compose -f docker-compose.podcast.yml up -d --build
```

详细文档: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

####  ⚙️ 方式2: 手动运行 (适合开发者)
```bash
# 1. 启动数据库和Redis (使用Docker建议)
cd docker
docker compose -f docker-compose.podcast.yml up -d postgres redis

# 2. 配置环境
cd ../backend
cp .env.example .env
# 编辑 .env，连接字符串设为 localhost

# 3. 安装依赖
uv sync --extra dev

# 4. 运行迁移和后端
uv run python database_migration.py
uvicorn app.main:app --reload
```

详细文档: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

### 前端启动

1. 安装Flutter依赖
```bash
cd frontend
flutter pub get
```

2. 运行应用
```bash
flutter run
```

## API文档

启动后端服务后，访问以下地址查看API文档：
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 开发计划

### 第一阶段：基础架构 ✅
- [x] 项目结构搭建
- [x] FastAPI应用初始化
- [x] 数据库配置和迁移
- [x] 基础认证系统
- [x] Flutter项目初始化

### 第二阶段：订阅功能
- [ ] 订阅源CRUD操作
- [ ] RSS/API连接器实现
- [ ] 定时任务和数据抓取
- [ ] 移动端订阅列表展示

### 第三阶段：知识库功能
- [ ] 文档上传和管理
- [ ] 向量化和搜索
- [ ] 分类和标签系统
- [ ] 知识图谱构建

### 第四阶段：AI集成
- [ ] 对话系统实现
- [ ] 上下文管理
- [ ] 任务调度和提醒
- [ ] 智能推荐

### 第五阶段：多媒体功能
- [ ] 语音合成和识别
- [ ] 图像处理和分析
- [ ] 视频内容提取
- [ ] 多模态交互

## 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 联系方式

如有问题或建议，请通过以下方式联系：
- 提交 Issue: [Issues](https://github.com/your-username/personal-ai-assistant/issues)
- 邮箱: your.email@example.com