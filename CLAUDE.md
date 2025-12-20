# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 🤖 优化后的Subagent协作工作流程

**📅 基于需求工程师驱动的完整开发流程**

### 🔄 **核心工作流程（4阶段循环）**

```
用户输入指令 → 产品经理分析 → 定义产品需求 → 规划功能 → 任务分配 → 工程师执行 → 更新状态 → 产品验证
      ↑                                                                                  ↓
      ←←←←←←←←←←←← 验证发现问题或价值不足，返回重新规划 ←←←←←←←←←←←←←←←←←←←←←←←←←
```

### 📋 **阶段1：产品分析与需求定义**
**负责人**：产品经理
1. **分析用户指令和业务需求** - 理解用户痛点、业务价值和市场机会
2. **定义产品需求**：
   - 新功能 → 在`specs/active/`下创建产品需求文档
   - 功能改进/优化 → 更新现有需求文档
   - 问题修复 → 在需求文档中定义修复目标和优先级
3. **输出**：完整的产品需求文档（用户故事、商业价值、验收标准、成功指标）

### 👥 **阶段2：功能规划与任务分配**
1. **产品经理**进行功能规划：
   - 基于产品愿景和战略规划功能
   - 确定功能优先级（使用价值 vs 成本矩阵）
   - 定义MVP范围和迭代计划
2. **任务分配**：
   - Backend任务 → Backend Developer
   - Frontend任务 → Frontend Developer
   - Mobile任务 → Mobile Developer
   - 架构相关 → Architect
   - 测试相关 → Test Engineer
   - 部署相关 → DevOps Engineer

### ⚙️ **阶段3：开发执行与状态跟踪**
**工程师团队**：
1. 按照产品需求文档执行开发任务
2. 在任务跟踪文档中实时更新状态
3. 记录关键决策、技术方案和测试结果
4. 主动沟通进度和阻塞点

### ✅ **阶段4：产品验证与商业价值评估**
**产品经理**：
1. 验证功能完成度和用户体验
2. 评估商业价值实现情况
3. 收集用户反馈和数据分析
4. 确认是否满足成功指标
5. 如未达标 → 制定改进计划并返回阶段2

### 🔥 **快速开始 - 直接输入需求**

**⚠️ 重要：所有功能开发必须严格遵循产品驱动开发流程！**

无需特定命令，直接描述你的需求：

**示例**：
- "添加用户时区设置功能"
- "修复搜索结果不准确的bug"
- "优化文档上传的性能"
- "实现语音备忘录功能"

**📋 强制性流程要求**：
1. **第1步（必须）**: **产品经理**必须先分析需求并创建产品需求文档（PRD）
2. **第2步（必须）**: 产品经理进行功能规划和任务分配
3. **第3步（必须）**: 工程师团队按照PRD执行开发
4. **第4步（必须）**: 产品经理进行最终验收并更新文档状态

**🚫 禁止行为**：
- ❌ 跳过产品经理直接开始开发
- ❌ 开发完成后不进行产品验收
- ❌ 不更新PRD状态就标记完成
- ❌ 违反4阶段开发流程

**⚡ 流程自动化检查**：
- 系统会自动验证是否已创建PRD文档
- 每个阶段完成后会更新任务状态
- 最终验收前会检查所有验收标准

### 📁 **文档结构**
```
specs/
├── active/          # 进行中的需求
├── completed/       # 已完成的需求
├── templates/       # 文档模板
├── verification/    # 验证报告
├── completion/      # 完成报告
└── README.md       # 需求索引
```

### 🔍 **工作流程检查清单**

**阶段1：需求分析检查**
- [ ] 产品经理已分析用户需求
- [ ] 已创建PRD文档（`specs/active/`）
- [ ] PRD包含用户故事、验收标准、成功指标
- [ ] 商业价值已明确定义

**阶段2：功能规划检查**
- [ ] 功能优先级已确定
- [ ] MVP范围已定义
- [ ] 任务已分配给正确的工程师
- [ ] 时间规划已制定

**阶段3：开发执行检查**
- [ ] 后端API已实现（如需要）
- [ ] 前端UI已实现
- [ ] 测试已编写并执行
- [ ] 代码审查已完成

**阶段4：产品验收检查**
- [ ] 产品经理已验证功能完成度
- [ ] 所有验收标准已通过
- [ ] 商业价值已评估
- [ ] PRD状态已更新为"已完成"
- [ ] 验证报告已创建
- [ ] 完成报告已创建

**❌ 流程违规处理**
如果发现违反流程的情况：
1. 立即停止当前任务
2. 补充缺失的流程步骤
3. 重新开始正确的流程
4. 更新相关文档

### Agent Roles (7个专业角色)

基于 `.claude/agents.json` 配置：

1. **产品经理** (📋) - **产品愿景与执行负责人**
   - 定义产品愿景和战略方向
   - 分析用户需求和商业价值
   - 创建和维护产品需求文档（PRD）
   - 管理产品路线图和功能优先级
   - 协调所有工程团队
   - 验证产品价值和用户满意度

2. **架构师** (🏛️) - 系统设计与DDD架构
   - 技术架构设计
   - 技术选型决策
   - 架构文档编写

3. **后端工程师** (⚙️) - FastAPI/Python开发
   - API接口开发
   - 数据库设计
   - 业务逻辑实现

4. **前端工程师** (🖥️) - Flutter桌面/Web开发
   - UI组件开发
   - 用户交互实现
   - 响应式设计

5. **移动端工程师** (📱) - Flutter iOS/Android开发
   - 移动端适配
   - 原生功能集成
   - 性能优化

6. **测试工程师** (🧪) - 质量保证与自动化测试
   - 测试策略制定
   - 自动化测试开发
   - 质量门禁把控

7. **DevOps工程师** (⚙️) - 部署与基础设施
   - CI/CD流水线
   - 部署自动化
   - 监控告警

### Workflows Available

- **Feature Development** (`/workflow feature-development`) - End-to-end feature delivery
- **Bug Fix** (`/workflow bug-fix`) - Swift bug resolution
- **Architecture Review** (`/workflow architecture-review`) - Design validation

### 🔄 Agent Communication Protocol

#### System Integration Commands
```bash
# Manual agent activation (one-by-one)
/role architect
/role backend-dev
/role frontend-dev

#/workflow feature-development
# Automatically orchestrates all roles defined in agents.json with timing, dependencies, and handoff points
```

#### Context Sharing Rules
When you activate auto-collaboration, agents automatically share:
1. Requirements documents
2. API contracts
3. Architecture decisions
4. Test results
5. Performance metrics
6. Deployment status

All agents use `./claude/agents/coordination/task-board.md` to track progress and `./claude/agents/coordination/communication.md` for protocol standards.

#### Decision Consensus Protocol
- Architect has final architecture say
- Product owner approves requirements
- QA rejects failing builds
- DevOps blocks bad deployments
- All agents can challenge for consistency

### 🎯 Usage Examples & Scenarios

#### 1. Full Feature Implementation
```bash
User: /feature "api-rate-limiting" "Add rate limiting for subscription API endpoints"
```
**Auto-Orchestration Flow:**
```
Requirements Analyst → Dives into why we need rate limiting
    ↓
Architect → Design Redis-based rate limiter, rate limit schedule
    ↓
Backend Developer → Implement FastAPI middleware, database limits
    ↓
Frontend Developer → Implement rate limit error UI in mobile app
    ↓
Mobile Developer → Handle rate limit errors gracefully in mobile app
    ↓
Test Engineer → Load testing, rate limit boundary testing
    ↓
DevOps Engineer → Redis config, monitoring alerts for rate limits
```

#### 2. Bug Fix Production Issue
```bash
User: /fix "search crashing for users with large knowledge base"
```
**Auto-Triage & Resolution:**
```
Test Engineer → "Reproduces in test, checks DB index usage"
    ↓
Backend Dev → Optimize indexing, implement streaming search
    ↓
Test Engineer → "Performance target hit, no crashes"
    ↓
DevOps Engineer → Deploy and monitor
```

#### 3. Architecture Decision
```bash
User: /architecture "chat message encryption at rest"
```
**Auto-Research & Decision:**
```
Architect → Research AES-256 vs. GCP KMS, performance impact
Backend Dev → "Zero-knowledge requires device-specific key management"
Test Engineer → "Performance impact minimal at message scale"
Consensus → Recommended GCP KMS with client-side key wrapping
```

#### 4. Flexible Team Coordination
```bash
User: /collaborate "Need a new feature for batch document processing"
```
**Auto-Determined Need:**
```
Requirements Analyst → Creates acceptance criteria
Architect → Firebase Cloud Functions for scaling?
Backend Dev → OR Backend Celery workers? Let's do Celery.
DevOps → "Kubernetes CronJob for scheduled batch processing"
```
---
#### Simple Task Assignment
```bash
User: /task "#342 - Add user preference persistence"
```
**AI Selection:**
```json
{
  "selected_agent": "backend-dev",
  "action": "Backend task - add user_preferences table + API endpoints",
  "next_task": "frontend-dev for UI binding"
}
```

## Project Overview

Personal AI Assistant - A scalable personal AI assistant tool supporting information feed subscriptions, knowledge base management, and multimedia processing capabilities.

## Development Commands

### ⚠️ IMPORTANT: Package Management with uv

**This project uses `uv` for Python package management** (not pip). All Python commands must be prefixed with `uv run` or executed within uv's managed environment.

### Backend (FastAPI)
```bash
# Install dependencies (with uv)
cd backend
uv sync --extra dev

# Check sync status
uv sync --check

# Run database migrations
uv run alembic upgrade head

# Start development server
uv run uvicorn app.main:app --reload

# Run tests
uv run pytest

# Run specific test file
uv run pytest app/domains/podcast/tests/test_services.py

# Code quality checks
uv run black .
uv run isort .
uv run flake8 .
uv run mypy .

# Add new dependency
uv add package-name

# Check what's installed
uv pip list

# Run Python interpreter
uv run python
uv run python -c "import sqlalchemy; print('OK')"

# IMPORTANT: Never run 'pip install' directly
# Always use 'uv add' or 'uv sync'
```

### Frontend (Flutter)
```bash
# Install dependencies
cd frontend
flutter pub get

# Run the app
flutter run

# Run tests
flutter test

# Run widget tests specifically (mandatory for page functionality)
flutter test test/widget/

# Run unit tests only
flutter test test/unit/

# Run tests with coverage
flutter test --coverage

# Generate code (for JSON serialization, Retrofit, etc.)
flutter packages pub run build_runner build --delete-conflicting-outputs
```

### Docker Development (Backend Services)
```bash
# Navigate to docker folder first
cd docker

# Start all backend services using podcast configuration (database, redis, backend, celery)
docker-compose -f docker-compose.podcast.yml up -d

# View logs
docker-compose -f docker-compose.podcast.yml logs -f

# Stop services
docker-compose -f docker-compose.podcast.yml down
```

**IMPORTANT**: This Docker configuration runs the **backend services** including:
- PostgreSQL database
- Redis cache
- FastAPI backend server
- Celery background workers

The frontend Flutter application should be run separately using the commands in the Frontend (Flutter) section.

## Architecture Overview

### Backend Architecture (Domain-Driven Design)
- **Core Layer** (`app/core/`): Infrastructure components including config, security, database, exceptions, and dependency injection
- **Shared Layer** (`app/shared/`): Cross-cutting concerns like schemas, utilities, and constants
- **Domain Layer** (`app/domains/`): Business domains organized by feature:
  - `user/`: Authentication and user management
  - `subscription/`: Feed subscriptions and content fetching
  - `knowledge/`: Document management and knowledge base
  - `assistant/`: AI interaction and chat functionality
  - `multimedia/`: Media processing and handling
- **Integration Layer** (`app/integration/`): External service connectors, background workers, and event system

### Frontend Architecture (Clean Architecture)
- **Core Layer** (`lib/core/`): Fundamental components including constants, error handling, network client, storage, and utilities
- **Shared Layer** (`lib/shared/`): Reusable UI components, themes, and extension methods
- **Feature Layer** (`lib/features/`): Feature modules organized by domain mirroring the backend structure

### Key Technologies & Patterns
- **Backend**: FastAPI with async/await, SQLAlchemy with async support, PostgreSQL, Redis, Celery for background tasks
- **Frontend**: Flutter with Riverpod for state management, GoRouter for navigation, Dio for HTTP, Hive for local storage
- **Authentication**: JWT tokens with secure storage
- **Database**: PostgreSQL with Alembic migrations
- **Background Tasks**: Celery with Redis broker
- **Dependency Injection**: dependency-injector (backend) and Riverpod (frontend)

### API Structure
All API endpoints are prefixed with `/api/v1/`:
- `/auth`: Authentication endpoints (register, login, refresh token)
- `/subscriptions`: Feed subscription management
- `/knowledge`: Knowledge base operations
- `/assistant`: AI assistant interactions
- `/multimedia`: Media processing endpoints

### Database Schema
Uses PostgreSQL with the following key entities:
- Users: Authentication and profile management
- Subscriptions: RSS/API feed configurations
- Knowledge Items: Documents and knowledge base entries
- Assistant Conversations: Chat history and context
- Media Files: Uploaded multimedia content

## Development Notes

### Environment Configuration
- Copy `.env.example` to `.env` in the backend directory
- Configure database URL, Redis connection, and JWT settings
- The application supports development, staging, and production environments

### Testing Strategy
- Backend: pytest with async support, comprehensive test coverage
- Frontend: flutter_test with widget and integration tests
- Both layers follow testing best practices with unit and integration tests

### 🧪 Flutter Widget Testing Rules (MANDATORY)

**IMPORTANT**: When testing Flutter page functionality, Widget Tests are **mandatory**. All Test Engineer agents must follow these rules:

1. **Widget Tests are Required for Page Testing**
   - Always use widget tests (`testWidgets`) for testing page functionality
   - Unit tests are only for pure logic functions (no UI)
   - Integration tests are only for complete user workflows

2. **Widget Test Structure**
   ```
   test/features/[feature]/widget/
   ├── pages/
   │   ├── [page_name]_page_test.dart
   │   └── ...
   └── components/
       ├── [component_name]_widget_test.dart
       └── ...
   ```

3. **Required Test Scenarios for Every Page**
   - Renders all required UI components
   - Displays loading state initially
   - Shows data when loaded successfully
   - Handles error states appropriately
   - Navigation works correctly
   - Empty state displays correctly
   - Pull to refresh (if applicable)
   - Search/filter functionality (if applicable)

4. **Widget Testing Best Practices**
   - Use ProviderContainer for state management testing
   - Mock providers using `.overrideWith()`
   - Use meaningful keys for widgets
   - Test user interactions (taps, scrolls, input)
   - Verify accessibility with semantic labels
   - Group related tests with `group()`
   - Use descriptive test names: `'[widget] [condition] [expected outcome]'`

5. **Test Commands**
   ```bash
   # Run all widget tests (mandatory for page functionality)
   flutter test test/widget/

   # Run widget tests for specific feature
   flutter test test/widget/pages/[page_name]_page_test.dart

   # Run tests with coverage
   flutter test --coverage
   ```

### Code Quality Tools
- Backend: black (formatting), isort (imports), flake8 (linting), mypy (type checking)
- Frontend: flutter_lints and very_good_analysis for code standards

### Background Processing
Celery workers handle:
- Feed content fetching and parsing
- Document vectorization and indexing
- Media processing and transcoding
- Scheduled tasks and notifications

### Security Considerations
- JWT-based authentication with refresh tokens
- Secure storage of sensitive data using flutter_secure_storage
- CORS configuration for cross-origin requests
- Input validation and sanitization throughout the application

## Working with the Codebase

When making changes:
1. Follow the domain-driven structure - keep business logic within appropriate domains
2. Use async/await consistently in the backend
3. Maintain type safety with mypy (backend) and strong typing (Dart)
4. Write tests for new functionality
5. Update API documentation automatically generated by FastAPI
6. Keep the frontend and backend domain structures in sync

### 🔒 **MANDATORY: Code Modification and Verification Rules**

**CRITICAL**: Every code modification MUST follow this verification workflow:

#### 1. **Syntax Validation (Always Required)**
```bash
# Backend (Python)
cd backend
uv run python -m py_compile <file_path>
uv run black <file_path>  # Format check
uv run mypy <file_path>   # Type check

# Frontend (Flutter)
cd frontend
flutter analyze <file_path>
```

#### 2. **Runtime Verification - Backend (Always Required)**
**IMPORTANT**: Backend must be verified using Docker for consistent environment:

```bash
# Navigate to docker folder
cd docker

# Start all backend services
docker-compose -f docker-compose.podcast.yml up -d

# Check logs for startup errors
docker-compose -f docker-compose.podcast.yml logs -f backend

# Run tests inside the backend container
docker-compose -f docker-compose.podcast.yml exec backend uv run pytest -v

# Verify API endpoints are responding
curl http://localhost:8000/api/v1/health  # Should return OK
```

**Backend Verification Checklist:**
- ✅ Docker containers start without errors
- ✅ Backend server starts successfully
- ✅ Database migrations are applied
- ✅ All tests pass inside container
- ✅ API endpoints respond correctly
- ✅ Modified endpoints work as expected

#### 3. **Runtime Verification - Frontend (Always Required)**
```bash
cd frontend
flutter pub get  # If dependencies changed
flutter analyze  # Check for errors
flutter test  # Run all tests
flutter run  # Must compile and start successfully
```

#### 4. **Functional Testing (For New Features)**
- **Backend**: Test all modified endpoints using curl or Postman against Docker container
  ```bash
  # Example: Test podcast subscription endpoint
  curl -X POST http://localhost:8000/api/v1/podcast/subscriptions \
    -H "Authorization: Bearer <token>" \
    -H "Content-Type: application/json" \
    -d '{"feed_url": "https://example.com/feed.xml"}'
  ```
- **Frontend**: Manually test the UI flow in the running app
- **Both**: Verify error handling and edge cases

#### 5. **Completion Criteria**
A task is **NOT COMPLETE** until:
- ✅ Code compiles without syntax errors
- ✅ Backend Docker containers start successfully
- ✅ Backend API responds correctly
- ✅ All backend tests pass
- ✅ Frontend compiles and starts
- ✅ All frontend tests pass
- ✅ Modified functionality works as expected (end-to-end tested)
- ✅ Error handling is verified

#### 6. **Common Verification Commands**
```bash
# Backend verification (Docker-based)
cd docker
docker-compose -f docker-compose.podcast.yml down  # Clean start
docker-compose -f docker-compose.podcast.yml up -d
docker-compose -f docker-compose.podcast.yml logs -f backend  # Watch for errors
docker-compose -f docker-compose.podcast.yml exec backend uv run pytest app/domains/podcast/tests/ -v

# Frontend verification
cd frontend
flutter analyze
flutter test
flutter run

# API testing (after backend is running)
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/podcast/subscriptions
```

**⚠️ WARNING**: Never mark a task as complete without running these verifications. "It should work" is not enough - it must actually work. Both backend (via Docker) and frontend must be tested and verified.

The project uses clean architecture principles with clear separation of concerns, making it easy to extend with new features or modify existing functionality.