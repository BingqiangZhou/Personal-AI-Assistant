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
├── backend/                    # FastAPI后端
│   ├── app/
│   │   ├── core/              # 核心基础设施
│   │   │   ├── config/        # 配置管理
│   │   │   ├── security/      # 认证安全
│   │   │   ├── database/      # 数据库连接
│   │   │   ├── exceptions/    # 异常处理
│   │   │   └── dependencies/  # 依赖注入
│   │   ├── shared/            # 共享组件
│   │   │   ├── schemas/       # Pydantic模型
│   │   │   ├── utils/         # 工具函数
│   │   │   └── constants/     # 常量定义
│   │   ├── domains/           # 业务域 (DDD)
│   │   │   ├── user/          # 用户管理
│   │   │   ├── subscription/  # 订阅管理
│   │   │   ├── knowledge/     # 知识库
│   │   │   ├── assistant/     # AI助手
│   │   │   └── multimedia/    # 多媒体
│   │   └── integration/       # 集成层
│   │       ├── connectors/    # 外部服务连接器
│   │       ├── workers/       # 后台任务
│   │       └── events/        # 事件系统
│   ├── alembic/               # 数据库迁移
│   ├── tests/                 # 测试文件
│   └── requirements.txt       # Python依赖
├── frontend/                   # Flutter前端
│   ├── lib/
│   │   ├── core/              # 核心功能
│   │   │   ├── constants/     # 常量
│   │   │   ├── errors/        # 错误处理
│   │   │   ├── network/       # 网络请求
│   │   │   ├── storage/       # 本地存储
│   │   │   └── utils/         # 工具函数
│   │   ├── shared/            # 共享组件
│   │   │   ├── widgets/       # 通用UI组件
│   │   │   ├── themes/        # 主题
│   │   │   └── extensions/    # 扩展方法
│   │   └── features/          # 功能模块
│   │       ├── subscription/  # 订阅管理
│   │       ├── knowledge/     # 知识库
│   │       ├── assistant/     # AI助手
│   │       └── multimedia/    # 多媒体
│   ├── assets/                # 资源文件
│   ├── test/                  # 测试文件
│   └── pubspec.yaml           # Flutter依赖
├── scripts/                    # 脚本文件
├── docker-compose.yml          # Docker编排
└── README.md                   # 项目说明
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
- Docker (可选)

### 后端启动

1. 克隆项目
```bash
git clone <repository-url>
cd personal-ai-assistant
```

2. 安装依赖
```bash
cd backend
uv sync --extra dev
```

3. 配置环境变量
```bash
cp .env.example .env
# 编辑 .env 文件，配置数据库和其他服务
```

4. 运行数据库迁移
```bash
uv run alembic upgrade head
```

5. 启动服务
```bash
uvicorn app.main:app --reload
```

### 使用Docker

```bash
# 启动所有服务
docker-compose up -d

# 查看日志
docker-compose logs -f
```

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