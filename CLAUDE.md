# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 🌐 Language Requirements / 语言要求

**IMPORTANT: This project follows a strict bilingual (Chinese/English) policy**

**重要：本项目严格遵循中英文双语政策**

### Bilingual Communication Standards / 双语沟通标准

1. **User Interaction / 用户交互**
   - All agents MUST respond in the same language as the user's input
   - 所有 agent 必须使用与用户输入相同的语言回复
   - If user uses Chinese → respond in Chinese
   - 如果用户使用中文 → 用中文回复
   - If user uses English → respond in English
   - 如果用户使用英文 → 用英文回复

2. **Documentation Requirements / 文档要求**
   - **Code Comments**: Use language matching the code context or project team's primary language
   - **代码注释**：使用与代码上下文匹配的语言或项目团队主要语言
   - **Technical Documents**: Provide bilingual headers/summaries when possible
   - **技术文档**：尽可能提供双语标题/摘要
   - **API Documentation**: English is preferred for API specs, with Chinese translations as needed
   - **API 文档**：API 规范首选英文，必要时提供中文翻译

3. **Agent Communication Protocol / Agent 通信协议**
   - Inter-agent messages: Use language matching the original task/request
   - Agent 间消息：使用与原始任务/请求匹配的语言
   - Status updates: Match the language of requirement document
   - 状态更新：与需求文档语言匹配
   - Error messages: Bilingual format preferred (English primary, Chinese secondary)
   - 错误消息：首选双语格式（英文为主，中文为辅）

4. **Product Documentation / 产品文档**
   - **Requirement Documents (PRD)**: Chinese only
   - **需求文档(PRD)**：仅使用中文
   - **User Stories**: Write in Chinese
   - **用户故事**：使用中文编写
   - **Acceptance Criteria**: Chinese
   - **验收标准**：使用中文

### Implementation Guidelines / 实现指南

#### Backend / 后端
```python
# API Error Response (Bilingual Format)
class ErrorResponse(BaseModel):
    """Bilingual error response model / 双语错误响应模型"""
    error_code: str
    message_en: str  # English message / 英文消息
    message_zh: str  # Chinese message / 中文消息
    detail: Optional[str] = None
```

#### Frontend / 前端
```dart
// UI Labels (Bilingual Support)
class AppLocalizations {
  static const Map<String, Map<String, String>> _translations = {
    'en': {
      'search': 'Search',
      'settings': 'Settings',
    },
    'zh': {
      'search': '搜索',
      'settings': '设置',
    },
  };
}
```

### Agent-Specific Requirements / Agent 特定要求

| Agent Role | Language Capability / 语言能力 | Notes / 备注 |
|------------|-------------------------------|--------------|
| Product Manager 📋 | **Bilingual Required** | Must analyze and document in user's preferred language / 必须使用用户首选语言分析和文档化 |
| Architect 🏛️ | Bilingual | Technical docs primarily in English with Chinese summaries / 技术文档主要英文，中文摘要 |
| Backend Dev ⚙️ | Bilingual | Code comments in team's language / 代码注释使用团队语言 |
| Frontend Dev 🖥️ | Bilingual | UI must support i18n / UI 必须支持国际化 |
| Mobile Dev 📱 | Bilingual | Same as Frontend / 与前端相同 |
| Test Engineer 🧪 | Bilingual | Test reports bilingual when possible / 测试报告尽可能双语 |
| DevOps ⚙️ | Bilingual | Logs and alerts bilingual preferred / 日志和告警首选双语 |

### Validation Criteria / 验证标准

When validating bilingual support:
验证双语支持时：

- [ ] User-facing UI supports language switching or detection
- [ ] 面向用户的 UI 支持语言切换或检测
- [ ] Error messages are provided in both languages
- [ ] 错误消息提供双语版本
- [ ] Documentation has appropriate language coverage
- [ ] 文档有适当的语言覆盖
- [ ] Agent responses match user's input language
- [ ] Agent 回复与用户输入语言匹配

---

## 🤖 Product-Driven Development Workflow

**📅 基于产品经理驱动的完整开发流程**

### 🔄 **核心工作流程（4阶段循环）**

```
用户输入指令 → 产品经理分析 → 定义需求 → 规划功能 → 任务分配 → 工程师执行 → 更新状态 → 产品验证
      ↑                                                                                  ↓
      ←←←←←←←←←←←← 验证发现问题，返回重新规划 ←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←←
```

### 📋 **阶段1：需求分析与定义**
**负责人**：产品经理
1. **分析用户指令和技术需求** - 理解用户需求、技术可行性
2. **定义产品需求**：
   - 新功能 → 在`specs/active/`下创建需求文档
   - 功能改进/优化 → 更新现有需求文档
   - 问题修复 → 在需求文档中定义修复目标和优先级
3. **输出**：完整的需求文档（用户故事、验收标准、技术要求）

### 👥 **阶段2：功能规划与任务分配**
**负责人**：产品经理
1. **功能规划**：
   - 确定功能优先级和实现范围
   - 定义 MVP 范围和迭代计划
2. **任务分配**：
   - Backend任务 → Backend Developer
   - Frontend任务 → Frontend Developer
   - Mobile任务 → Mobile Developer
   - 架构相关 → Architect
   - 测试相关 → Test Engineer
   - 部署相关 → DevOps Engineer

### ⚙️ **阶段3：开发执行与状态跟踪**
**工程师团队**：
1. 按照需求文档执行开发任务
2. **建议使用 MCP 工具提高开发效率**：
   - 使用 context7 查询相关库的官方文档
   - 使用 exa 搜索实现示例和最佳实践
   - 审查现有代码库模式
3. 在任务跟踪文档中实时更新状态
4. 记录关键决策、技术方案和测试结果
5. 主动沟通进度和阻塞点

### ✅ **阶段4：产品验证**
**产品经理**：
1. 验证功能完成度和用户体验
2. 确认是否满足验收标准
3. 如未达标 → 制定改进计划并返回阶段2

## 📚 MCP Tools for Documentation & Problem Solving

**💡 提示：使用 MCP 工具可以提高开发效率，快速查找文档和解决方案**

### Context7 - Library Documentation

Use `context7` to get up-to-date library documentation and code examples:

```bash
# When you need to understand how to use a library/framework
# Example: Need to understand FastAPI dependency injection
→ Use mcp__context7__resolve-library-id with "fastapi"
→ Then use mcp__context7__get-library-docs with the resolved ID

# Example: Need Flutter Riverpod state management docs
→ Use mcp__context7__resolve-library-id with "riverpod"
→ Then use mcp__context7__get-library-docs with topic "providers"
```

**When to use Context7:**
- Learning a new library API
- Finding correct usage patterns
- Getting code examples for specific features
- Understanding library architecture
- Checking latest features and best practices

### Exa - Code Context & Solutions

Use `exa` to search for coding solutions and implementation examples:

```bash
# When you need to find solutions or code examples
# Example: How to implement JWT authentication in FastAPI
→ Use mcp__exa__get_code_context_exa with query "FastAPI JWT authentication implementation"

# Example: Flutter adaptive layout examples
→ Use mcp__exa__get_code_context_exa with query "Flutter adaptive scaffold responsive layout"
```

**When to use Exa:**
- Finding implementation examples
- Researching best practices
- Solving specific technical problems
- Learning design patterns
- Finding error solutions

### 🎯 MCP-First Development Approach

**建议：在开始编码前，使用 MCP 工具查询文档可以避免重复造轮子**

#### Development Workflow with MCP:

1. **Receive Task** → Identify required libraries/technologies

2. **Research Phase (Optional but Recommended)**:
   ```
   a. Use context7 to get official library documentation
   b. Use exa to find implementation examples and solutions
   c. Review existing codebase patterns
   ```

3. **Plan Implementation**:
   - Based on documentation and examples
   - Follow project architecture patterns
   - Consider existing code standards

4. **Implement**:
   - Write code following researched patterns
   - Reference documentation as needed
   - Apply best practices found in examples

5. **Verify**:
   - Run tests
   - Verify against documentation
   - Check code quality

#### Example Scenarios:

**Scenario 1: Add new FastAPI endpoint**
```
1. context7 → Get FastAPI router and dependency injection docs
2. exa → Find similar endpoint implementation examples
3. Review backend/app/domains/ structure
4. Implement following DDD pattern
5. Write tests and verify
```

**Scenario 2: Create Flutter widget**
```
1. context7 → Get Material 3 component documentation
2. exa → Find adaptive scaffold widget examples
3. Review existing widgets in lib/shared/
4. Implement following Material 3 design
5. Write widget tests and verify
```

**Scenario 3: Fix a bug**
```
1. exa → Search for similar error messages and solutions
2. context7 → Check relevant library documentation
3. Analyze stack trace and affected code
4. Apply solution
5. Write regression test
```

### 🔥 **快速开始 - 直接输入需求**

**⚠️ 重要：所有功能开发必须严格遵循产品驱动开发流程！**

无需特定命令，直接描述你的需求：

**示例**：
- "添加用户时区设置功能"
- "修复搜索结果不准确的bug"
- "优化文档上传的性能"
- "实现语音备忘录功能"

**📋 强制性流程要求**：
1. **第1步（必须）**: **产品经理**必须先分析需求并创建需求文档
2. **第2步（必须）**: 产品经理进行功能规划和任务分配
3. **第3步（必须）**: 工程师团队按照需求执行开发
4. **第4步（必须）**: 产品经理进行最终验收并更新文档状态

**🚫 禁止行为**：
- ❌ 跳过产品经理直接开始开发
- ❌ 开发完成后不进行产品验收
- ❌ 不更新需求文档状态就标记完成
- ❌ 违反4阶段开发流程

**⚡ 流程自动化检查**：
- 系统会自动验证是否已创建需求文档
- 每个阶段完成后会更新任务状态
- 最终验收前会检查所有验收标准

### 📁 **文档结构**
```
specs/
├── active/          # 进行中的需求
├── completed/       # 已完成的需求
├── completion/      # 完成验证文档
├── verification/    # 验证报告
├── templates/       # 文档模板
└── README.md       # 需求索引
```

### 🔍 **工作流程检查清单**

**阶段1：需求分析检查**
- [ ] 产品经理已分析用户需求
- [ ] 已创建需求文档（`specs/active/`）
- [ ] 需求文档包含用户故事、验收标准、技术要求

**阶段2：功能规划检查**
- [ ] 功能优先级已确定
- [ ] MVP范围已定义
- [ ] 任务已分配给正确的工程师

**阶段3：开发执行检查**
- [ ] 后端API已实现（如需要）
- [ ] 前端UI已实现
- [ ] 测试已编写并执行
- [ ] 代码审查已完成
- [ ] （可选）使用 context7 查询了相关文档
- [ ] （可选）使用 exa 搜索了实现示例

**阶段4：产品验收检查**
- [ ] 产品经理已验证功能完成度
- [ ] 所有验收标准已通过
- [ ] 需求文档状态已更新为"已完成"

**❌ 流程违规处理**
如果发现违反流程的情况：
1. 立即停止当前任务
2. 补充缺失的流程步骤
3. 重新开始正确的流程
4. 更新相关文档

### Agent Roles (7个专业角色)

基于 `.claude/agents.json` 配置：

1. **产品经理** (📋) - **产品需求与执行负责人**
   - 定义产品需求和功能规划
   - 分析用户需求和技术可行性
   - 创建和维护需求文档
   - 管理功能优先级
   - 协调所有工程团队
   - 验证功能完成度
   - 建议使用 context7/exa 进行需求调研

2. **架构师** (🏛️) - 系统设计与DDD架构
   - 技术架构设计
   - 技术选型决策
   - 架构文档编写
   - 建议使用 context7 查询库文档
   - 建议使用 exa 搜索架构模式

3. **后端工程师** (⚙️) - FastAPI/Python开发
   - API接口开发
   - 数据库设计
   - 业务逻辑实现
   - 建议使用 context7 查询 FastAPI/SQLAlchemy 文档
   - 建议使用 exa 搜索实现示例

4. **前端工程师** (🖥️) - Flutter桌面/Web开发
   - UI组件开发（使用Material 3设计规范）
   - 用户交互实现
   - 响应式设计（使用flutter_adaptive_scaffold适配不同屏幕尺寸）
   - 建议使用 context7 查询 Flutter/Material 3 文档
   - 建议使用 exa 搜索 Flutter UI 模式

5. **移动端工程师** (📱) - Flutter iOS/Android开发
   - 移动端适配
   - 原生功能集成
   - 性能优化
   - 建议使用 context7 查询 Flutter 平台文档
   - 建议使用 exa 搜索移动开发模式

6. **测试工程师** (🧪) - 质量保证与自动化测试
   - 测试策略制定
   - 自动化测试开发
   - 质量门禁把控
   - 建议使用 exa 搜索测试模式和最佳实践
   - 建议使用 context7 查询测试框架文档

7. **DevOps工程师** (⚙️) - 部署与基础设施
   - CI/CD流水线
   - 部署自动化
   - 监控告警
   - 建议使用 context7 查询 Docker/K8s 文档
   - 建议使用 exa 搜索 DevOps 模式

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
7. MCP research findings (if used)

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
User: "Add rate limiting for API endpoints"
```
**Auto-Orchestration Flow:**
```
Product Manager → Analyze requirements, create spec document
    ↓
Architect → context7: Redis docs, exa: rate limiting patterns
    ↓
Backend Developer → context7: FastAPI middleware docs, implement
    ↓
Frontend Developer → Handle rate limit errors in UI
    ↓
Mobile Developer → Handle rate limit errors in mobile app
    ↓
Test Engineer → exa: load testing best practices, implement tests
    ↓
DevOps Engineer → context7: Redis configuration, deploy
```

#### 2. Bug Fix Production Issue
```bash
User: "Fix search crashing with large datasets"
```
**Auto-Triage & Resolution:**
```
Product Manager → Define bug fix requirements
    ↓
Test Engineer → Reproduce bug
    ↓
Backend Dev → exa: PostgreSQL optimization, fix implementation
    ↓
Test Engineer → Verify fix
    ↓
DevOps Engineer → Deploy and monitor
```

#### 3. Architecture Decision
```bash
User: "Choose encryption strategy for sensitive data"
```
**Auto-Research & Decision:**
```
Product Manager → Define technical requirements
    ↓
Architect → context7: cryptography libraries, exa: encryption patterns
    ↓
Backend Dev → Evaluate implementation complexity
    ↓
Test Engineer → Security testing requirements
    ↓
Consensus → Decision based on research and requirements
```

## Project Overview

Personal AI Assistant - A scalable personal AI assistant tool supporting information feed subscriptions, knowledge base management, and multimedia processing capabilities.

### 🎯 Current Feature Status

**Implemented Features:**
- ✅ User authentication and profile management
- ✅ Podcast feed subscriptions and management
- ✅ Podcast episode browsing and playback
- ✅ Audio player with floating controls
- ✅ RSS feed subscriptions
- ✅ Material 3 adaptive UI design (desktop, web, mobile)
- ✅ Bilingual support (Chinese/English)
- ✅ Docker-based backend deployment
- ✅ Celery background task processing

**In Progress / Planned:**
- 🔄 Podcast audio transcription and AI summary
- 🔄 Knowledge base document management
- 🔄 AI assistant chat functionality
- 🔄 Multimedia processing features
- 🔄 Enhanced search and filtering capabilities

### 🚀 Recent Major Updates

- **Podcast System**: Implemented complete podcast subscription, episode management, and audio playback features
- **UI/UX Modernization**: Migrated to Material 3 design system with adaptive layouts
- **Performance Optimization**: Implemented lazy loading for podcast feeds
- **Developer Experience**: Enhanced product-driven development workflow with structured requirements management

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
  - `podcast/`: Podcast feed subscriptions, episodes, and audio processing
  - `ai/`: AI services integration and processing
- **Integration Layer** (`app/integration/`): External service connectors, background workers, and event system

### Frontend Architecture (Clean Architecture)
- **Core Layer** (`lib/core/`): Fundamental components including constants, error handling, network client, storage, and utilities
- **Shared Layer** (`lib/shared/`): Reusable UI components, themes, and extension methods
- **Feature Layer** (`lib/features/`): Feature modules organized by domain mirroring the backend structure:
  - `auth/`: Authentication and login flows
  - `home/`: Home page and dashboard
  - `user/`: User profile management
  - `subscription/`: Feed subscription management
  - `knowledge/`: Knowledge base features
  - `assistant/`: AI assistant chat interface
  - `multimedia/`: Media viewing and management
  - `podcast/`: Podcast player, subscriptions, and episodes
  - `ai/`: AI features and integrations
  - `profile/`: User profile settings
  - `settings/`: Application settings
  - `splash/`: Initial loading screen
- **UI Design System**: Material 3 design language with flutter_adaptive_scaffold for responsive layouts across desktop, web, and mobile

### Key Technologies & Patterns
- **Backend**: FastAPI with async/await, SQLAlchemy with async support, PostgreSQL, Redis, Celery for background tasks
- **Frontend**: Flutter with Riverpod for state management, GoRouter for navigation, Dio for HTTP, Hive for local storage
- **UI/UX**: Material 3 design system with flutter_adaptive_scaffold for responsive layouts
- **Authentication**: JWT tokens with secure storage
- **Database**: PostgreSQL with Alembic migrations
- **Background Tasks**: Celery with Redis broker
- **Dependency Injection**: dependency-injector (backend) and Riverpod (frontend)
- **Podcast Processing**:
  - RSS feed parsing with feedparser
  - Audio streaming and playback with just_audio
  - Lazy loading pagination for efficient data handling
  - Background episode downloads and updates
- **AI Integration**:
  - Audio transcription services (planned)
  - AI-powered content summarization (planned)
  - Natural language processing for chat features (planned)

### 🎨 UI/UX Design Guidelines (MANDATORY for Frontend Development)

**All frontend development MUST follow these design standards:**

1. **Material 3 Design System**
   - Use Material 3 components and design tokens exclusively
   - Follow Material 3 color schemes, typography, and elevation
   - Implement Material 3 theming with ThemeData using `useMaterial3: true`
   - Reference: https://m3.material.io/
   - 建议使用 context7 获取 Material 3 文档

2. **Responsive Layout with flutter_adaptive_scaffold**
   - Use `flutter_adaptive_scaffold` package for all page layouts
   - Implement adaptive navigation (NavigationRail for desktop, BottomNavigationBar for mobile)
   - Support breakpoints: mobile (<600dp), tablet (600-840dp), desktop (>840dp)
   - Ensure consistent UX across desktop, web, and mobile platforms
   - 建议使用 context7 获取 flutter_adaptive_scaffold 文档

3. **Implementation Requirements**
   - All new pages must use `AdaptiveScaffold` or `AdaptiveLayout`
   - Navigation must adapt based on screen size
   - UI components must be responsive and scale appropriately
   - Test on multiple screen sizes during development

### API Structure
All API endpoints are prefixed with `/api/v1/`:
- `/auth`: Authentication endpoints (register, login, refresh token)
- `/subscriptions`: Feed subscription management
- `/knowledge`: Knowledge base operations
- `/assistant`: AI assistant interactions
- `/multimedia`: Media processing endpoints
- `/podcast`: Podcast feed subscriptions, episodes, and audio management
- `/ai`: AI service integration endpoints

### Database Schema
Uses PostgreSQL with the following key entities:
- Users: Authentication and profile management
- Subscriptions: RSS/API feed configurations
- Knowledge Items: Documents and knowledge base entries
- Assistant Conversations: Chat history and context
- Media Files: Uploaded multimedia content
- Podcast Subscriptions: Podcast feed subscriptions and metadata
- Podcast Episodes: Episode details, audio files, and playback status
- Podcast Transcriptions: Audio transcriptions and AI-generated summaries

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
   - 建议使用 exa 查找 Flutter 测试模式和示例

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
- Feed content fetching and parsing (RSS feeds and podcast feeds)
- Document vectorization and indexing
- Media processing and transcoding
- Podcast audio transcription and AI summary generation
- Scheduled tasks and notifications
- Podcast feed updates and episode downloads

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
7. 建议使用 context7 和 exa MCP 工具查询文档和搜索解决方案以提高开发效率

### 🔒 **MANDATORY: Code Modification and Verification Rules**

**CRITICAL**: Every code modification MUST follow this verification workflow:

#### 0. **Research Phase (建议但非必须)**
```bash
# 建议：在编码前使用 MCP 工具进行研究可以提高效率

# For library-specific implementation:
→ 可以使用 context7 获取官方文档
→ 可以使用 exa 查找实现示例

# Example: Adding FastAPI authentication
1. (Optional) context7 → Get FastAPI security documentation
2. (Optional) exa → Find JWT authentication examples
3. Review existing auth patterns in app/core/security/
4. Then proceed with implementation
```

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

**⚠️ WARNING**: Never mark a task as complete without:
1. Running all verifications
2. Testing the actual functionality

"It should work" is not enough - it must actually work. Both backend (via Docker) and frontend must be tested and verified.

## 📝 Summary: Product-Driven Development with MCP Tools

**Remember: Requirement → Plan → Implement → Verify**

1. **Product Manager leads requirement analysis and planning**
2. **Follow clean architecture and coding standards**
3. **Write comprehensive tests**
4. **建议使用 context7 查询官方库文档以提高效率**
5. **建议使用 exa 搜索实现示例和解决方案**
6. **Document your decisions and implementations**

This approach ensures:
- ✅ Clear requirements and planning
- ✅ Correct usage of libraries and frameworks
- ✅ Following best practices
- ✅ Avoiding common pitfalls
- ✅ Writing maintainable code
- ✅ Faster development with fewer errors

The project uses clean architecture principles with clear separation of concerns, making it easy to extend with new features or modify existing functionality.

## 💡 Development Best Practices

### When Adding New Features

1. **Start with Requirements**: Always create a requirement document in `specs/active/` before coding
2. **Research First**: Use context7/exa to understand libraries and find implementation examples
3. **Follow Patterns**: Review existing code in the same domain to maintain consistency
4. **Test Thoroughly**: Write widget tests for UI, unit tests for logic, integration tests for workflows
5. **Verify End-to-End**: Test both backend (via Docker) and frontend before marking complete

### Common Patterns in This Project

**Backend Patterns:**
- Domain-Driven Design with clear separation of concerns
- Async/await for all I/O operations
- Repository pattern for data access
- Dependency injection for loose coupling
- Background tasks with Celery for long-running operations

**Frontend Patterns:**
- Feature-first architecture mirroring backend domains
- Riverpod for state management (StateNotifier + AsyncValue)
- Material 3 components with AdaptiveScaffold for responsive design
- Repository pattern for data access
- Localization support for bilingual UI

### Current Development Focus

**Priority 1: Podcast Features**
- Audio transcription and AI summary generation
- Enhanced playback controls and offline support
- Improved search and discovery features

**Priority 2: Knowledge Base**
- Document upload and management
- Vector search and semantic retrieval
- Knowledge graph visualization

**Priority 3: AI Assistant**
- Chat interface with context awareness
- Integration with knowledge base
- Multi-modal input support

### Troubleshooting Tips

**Backend Issues:**
- Always verify using Docker (`docker-compose -f docker-compose.podcast.yml up -d`)
- Check logs: `docker-compose -f docker-compose.podcast.yml logs -f backend`
- Run tests in container: `docker exec backend uv run pytest`
- Database issues: Check migrations with `uv run alembic current`

**Frontend Issues:**
- Run `flutter analyze` to check for errors
- Use `flutter clean` and `flutter pub get` if dependencies are stale
- Check provider overrides in widget tests
- Verify Material 3 theming: `useMaterial3: true` in ThemeData

**Common Gotchas:**
- Backend: Never use `pip install`, always use `uv add` or `uv sync`
- Frontend: Material 3 components have different APIs than Material 2
- Both: Always test bilingual support (Chinese and English)
- Docker: Backend must be tested via Docker, not direct uvicorn
