# 后端架构重构需求文档

## 基本信息
- **需求ID**: REQ-20260125-001
- **创建日期**: 2026-01-25
- **最后更新**: 2026-01-25
- **负责人**: 架构师 + 产品经理
- **状态**: Draft
- **优先级**: High

## 需求描述

### 用户故事
作为开发团队成员，我想要一个清晰、可维护的后端架构，以便能够高效地开发新功能、修复bug和进行代码维护。

### 业务价值
- 提高代码可维护性，降低技术债务
- 加快新功能开发速度（预计提升30%开发效率）
- 减少bug修复时间（预计降低40%的回归问题）
- 提升代码质量和系统稳定性
- 降低新团队成员的学习成本

### 背景信息

**当前状况分析**：

1. **Podcast域服务类过大（1,408行）**
   - `PodcastService` 类承担了过多职责
   - 包含订阅管理、列表查询、搜索、刷新、AI总结、播放进度等多个功能
   - 违反单一职责原则（SRP）
   - 难以测试、难以维护、容易引入bug

2. **Core层职责混乱**
   - `app/core/feed_parser.py` (579行) - 业务逻辑放在核心层
   - `app/core/feed_schemas.py` - 业务领域模型放在核心层
   - Core层应该只包含基础设施组件（配置、安全、数据库、异常）

3. **缺少服务层依赖注入容器**
   - 服务依赖在运行时手动创建
   - 难以管理复杂依赖关系
   - 测试时难以mock依赖

4. **代码重复度高**
   - 分页逻辑散落在多个route文件中
   - 响应构建逻辑重复
   - CRUD操作模式重复但没有统一抽象

**用户痛点**：
- 开发新功能时难以找到合适的代码位置
- 修改一个功能可能影响其他功能
- 单元测试难以编写和维护
- 代码审查耗时较长

**机会点**：
- 重构后将极大提升开发体验
- 为后续微服务化奠定基础
- 提升系统整体质量

## 功能需求

### 核心功能
- [FR-001] 拆分PodcastService为多个专职服务
- [FR-002] 将业务逻辑从Core层移至Domain层
- [FR-003] 实现服务层依赖注入容器
- [FR-004] 提取通用分页和响应构建组件

### 功能详述

#### 功能1：Podcast服务拆分
- **描述**：将`PodcastService`按职责拆分为多个专职服务类
- **输入**：当前单一的PodcastService类
- **处理**：
  1. 分析PodcastService的40+个方法
  2. 按功能域分组：
     - 订阅管理（SubscriptionService）
     - 单集管理（EpisodeService）
     - 播放进度（PlaybackService）
     - AI总结（SummaryService）
     - 搜索推荐（SearchService）
     - 同步刷新（SyncService）
  3. 创建服务基类处理通用逻辑
  4. 保持API层接口不变
- **输出**：多个职责清晰的服务类

#### 功能2：Core层清理
- **描述**：将业务逻辑从Core层移至Domain层
- **输入**：Core层的feed_parser.py和相关schemas
- **处理**：
  1. 将`app/core/feed_parser.py`移至`app/domains/subscription/services/`
  2. 将`app/core/feed_schemas.py`移至`app/domains/subscription/schemas/`
  3. 更新所有import引用
  4. Core层只保留：config, security, database, exceptions, dependencies
- **输出**：清晰的分层架构

#### 功能3：依赖注入容器
- **描述**：实现服务层依赖注入容器
- **输入**：当前手动创建服务实例的代码
- **处理**：
  1. 使用`dependency-injector`库创建容器
  2. 为每个Domain创建独立的Container
  3. 定义服务的生命周期（singleton vs transient）
  4. 在API层通过FastAPI的Depends注入服务
- **输出**：完整的服务依赖注入体系

#### 功能4：通用组件提取
- **描述**：提取通用的分页、响应构建、CRUD组件
- **输入**：散落在各处的重复代码
- **处理**：
  1. 创建`app/shared/pagination.py` - 统一分页逻辑
  2. 创建`app/shared/response_builder.py` - 统一响应构建
  3. 创建`app/shared/crud_base.py` - CRUD基类
  4. 更新所有使用这些功能的地方
- **输出**：可复用的通用组件库

## 非功能需求

### 性能要求
- 重构后性能不低于重构前
- API响应时间增加 < 5%
- 内存占用增加 < 10%

### 安全要求
- 保持现有的认证和授权机制
- 不引入新的安全漏洞
- 所有重构代码需通过安全审查

### 可用性要求
- 重构过程中服务不停机（分阶段部署）
- 保持向后兼容（API接口不变）
- 降级方案：如出现问题可快速回滚

### 可维护性要求
- 单个服务类不超过500行
- 单个方法不超过50行
- 圈复杂度 <= 10
- 测试覆盖率 >= 80%

## 任务分解

### 阶段1：准备阶段 (1-2天)

- [ ] [TASK-ARCH-001] 代码分析和重构方案设计
  - **负责人**: 架构师
  - **预估工时**: 1天
  - **验收标准**:
    - [ ] 完成PodcastService方法分类分析
    - [ ] 完成Core层业务逻辑识别
    - [ ] 完成依赖注入容器设计方案
    - [ ] 完成通用组件清单
  - **依赖**: 无
  - **状态**: Todo

- [ ] [TASK-ARCH-002] 创建重构分支和基础设施
  - **负责人**: 架构师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] 创建feature分支 `feature/backend-arch-refactor`
    - [ ] 更新依赖（如有需要）
    - [ ] 准备测试环境
  - **依赖**: TASK-ARCH-001
  - **状态**: Todo

### 阶段2：Podcast服务拆分 (3-4天)

- [ ] [TASK-B-001] 创建Podcast服务基类和接口定义
  - **负责人**: 后端工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] 创建`BasePodcastService`抽象基类
    - [ ] 定义服务接口协议
    - [ ] 编写基类单元测试
  - **依赖**: TASK-ARCH-002
  - **状态**: Todo

- [ ] [TASK-B-002] 实现SubscriptionService（订阅管理）
  - **负责人**: 后端工程师
  - **预估工时**: 1天
  - **验收标准**:
    - [ ] 提取所有订阅相关方法
    - [ ] 实现SubscriptionService类
    - [ ] 单元测试覆盖率 >= 80%
    - [ ] 集成测试通过
  - **依赖**: TASK-B-001
  - **状态**: Todo

- [ ] [TASK-B-003] 实现EpisodeService（单集管理）
  - **负责人**: 后端工程师
  - **预估工时**: 1天
  - **验收标准**:
    - [ ] 提取所有单集相关方法
    - [ ] 实现EpisodeService类
    - [ ] 单元测试覆盖率 >= 80%
    - [ ] 集成测试通过
  - **依赖**: TASK-B-001
  - **状态**: Todo

- [ ] [TASK-B-004] 实现PlaybackService（播放进度）
  - **负责人**: 后端工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] 提取播放进度相关方法
    - [ ] 实现PlaybackService类
    - [ ] 单元测试覆盖率 >= 80%
  - **依赖**: TASK-B-001
  - **状态**: Todo

- [ ] [TASK-B-005] 实现SummaryService（AI总结）
  - **负责人**: 后端工程师
  - **预估工时**: 1天
  - **验收标准**:
    - [ ] 提取AI总结相关方法
    - [ ] 实现SummaryService类
    - [ ] 单元测试覆盖率 >= 80%
    - [ ] 集成测试通过
  - **依赖**: TASK-B-001
  - **状态**: Todo

- [ ] [TASK-B-006] 实现SearchService和SyncService
  - **负责人**: 后端工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] 提取搜索和同步相关方法
    - [ ] 实现SearchService和SyncService类
    - [ ] 单元测试覆盖率 >= 80%
  - **依赖**: TASK-B-001
  - **状态**: Todo

- [ ] [TASK-B-007] 更新API层以使用新的服务类
  - **负责人**: 后端工程师
  - **预估工时**: 1天
  - **验收标准**:
    - [ ] 更新routes.py使用新服务
    - [ ] 所有API端点测试通过
    - [ ] 性能测试通过
  - **依赖**: TASK-B-002, TASK-B-003, TASK-B-004, TASK-B-005, TASK-B-006
  - **状态**: Todo

### 阶段3：Core层清理 (1-2天)

- [ ] [TASK-B-008] 移动feed_parser到Domain层
  - **负责人**: 后端工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] 移动文件到`app/domains/subscription/services/`
    - [ ] 更新所有import引用
    - [ ] 所有测试通过
  - **依赖**: TASK-B-007
  - **状态**: Todo

- [ ] [TASK-B-009] 移动feed_schemas到Domain层
  - **负责人**: 后端工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] 移动文件到`app/domains/subscription/schemas/`
    - [ ] 更新所有import引用
    - [ ] 所有测试通过
  - **依赖**: TASK-B-008
  - **状态**: Todo

- [ ] [TASK-B-010] 清理Core层并更新文档
  - **负责人**: 后端工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] Core层只保留基础设施组件
    - [ ] 更新架构文档
    - [ ] 代码注释更新
  - **依赖**: TASK-B-009
  - **状态**: Todo

### 阶段4：依赖注入容器 (2-3天)

- [ ] [TASK-B-011] 设计和实现DI Container基础结构
  - **负责人**: 架构师 + 后端工程师
  - **预估工时**: 1天
  - **验收标准**:
    - [ ] 创建`app/core/container.py`
    - [ ] 定义Container基类
    - [ ] 实现基本的依赖注入逻辑
  - **依赖**: TASK-B-010
  - **状态**: Todo

- [ ] [TASK-B-012] 实现Podcast域的DI Container
  - **负责人**: 后端工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] 创建`PodcastContainer`
    - [ ] 配置所有Podcast相关服务
    - [ ] 单元测试通过
  - **依赖**: TASK-B-011
  - **状态**: Todo

- [ ] [TASK-B-013] 实现其他域的DI Container
  - **负责人**: 后端工程师
  - **预估工时**: 1天
  - **验收标准**:
    - [ ] 创建User, Subscription, Assistant等域的Container
    - [ ] 创建主ApplicationContainer
    - [ ] 单元测试通过
  - **依赖**: TASK-B-012
  - **状态**: Todo

- [ ] [TASK-B-014] 更新API层使用依赖注入
  - **负责人**: 后端工程师
  - **预估工时**: 1天
  - **验收标准**:
    - [ ] 更新所有routes使用Depends注入服务
    - [ ] 移除手动服务实例化代码
    - [ ] 集成测试通过
  - **依赖**: TASK-B-013
  - **状态**: Todo

### 阶段5：通用组件提取 (2天)

- [ ] [TASK-B-015] 实现统一分页组件
  - **负责人**: 后端工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] 创建`app/shared/pagination.py`
    - [ ] 实现通用分页函数
    - [ ] 单元测试覆盖各种分页场景
  - **依赖**: TASK-B-014
  - **状态**: Todo

- [ ] [TASK-B-016] 实现统一响应构建组件
  - **负责人**: 后端工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] 创建`app/shared/response_builder.py`
    - [ ] 实现成功/错误响应构建函数
    - [ ] 单元测试通过
  - **依赖**: TASK-B-014
  - **状态**: Todo

- [ ] [TASK-B-017] 实现CRUD基类
  - **负责人**: 后端工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] 创建`app/shared/crud_base.py`
    - [ ] 实现通用CRUD操作基类
    - [ ] 单元测试通过
  - **依赖**: TASK-B-014
  - **状态**: Todo

- [ ] [TASK-B-018] 重构现有代码使用通用组件
  - **负责人**: 后端工程师
  - **预估工时**: 1天
  - **验收标准**:
    - [ ] 更新所有routes使用新组件
    - [ ] 删除重复代码
    - [ ] 所有测试通过
  - **依赖**: TASK-B-015, TASK-B-016, TASK-B-017
  - **状态**: Todo

### 阶段6：测试和验证 (2-3天)

- [ ] [TASK-T-001] 单元测试补充
  - **负责人**: 测试工程师 + 后端工程师
  - **预估工时**: 1天
  - **验收标准**:
    - [ ] 所有新服务类单元测试覆盖率 >= 80%
    - [ ] 所有通用组件单元测试覆盖率 >= 90%
  - **依赖**: TASK-B-018
  - **状态**: Todo

- [ ] [TASK-T-002] 集成测试
  - **负责人**: 测试工程师
  - **预估工时**: 1天
  - **验收标准**:
    - [ ] 所有API端点集成测试通过
    - [ ] 服务间协作测试通过
  - **依赖**: TASK-T-001
  - **状态**: Todo

- [ ] [TASK-T-003] 性能测试
  - **负责人**: 测试工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] API响应时间增加 < 5%
    - [ ] 内存占用增加 < 10%
  - **依赖**: TASK-T-002
  - **状态**: Todo

- [ ] [TASK-T-004] 代码质量检查
  - **负责人**: 测试工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] 通过black格式化检查
    - [ ] 通过isort导入检查
    - [ ] 通过flake8代码检查
    - [ ] 通过mypy类型检查
  - **依赖**: TASK-T-003
  - **状态**: Todo

### 阶段7：部署和监控 (1天)

- [ ] [TASK-D-001] 准备部署脚本
  - **负责人**: DevOps工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] 创建数据库迁移脚本（如需要）
    - [ ] 准备回滚脚本
    - [ ] 更新Docker配置
  - **依赖**: TASK-T-004
  - **状态**: Todo

- [ ] [TASK-D-002] 灰度发布和监控
  - **负责人**: DevOps工程师
  - **预估工时**: 0.5天
  - **验收标准**:
    - [ ] 执行灰度发布
    - [ ] 监控系统指标
    - [ ] 监控错误日志
  - **依赖**: TASK-D-001
  - **状态**: Todo

## 验收标准

### 整体验收
- [ ] 所有功能需求已实现
- [ ] 性能指标达标
- [ ] 代码质量检查全部通过
- [ ] 测试覆盖率达标
- [ ] API接口向后兼容
- [ ] 文档更新完整

### 用户验收标准
- [ ] 所有现有API端点正常工作
- [ ] 前端应用无需修改即可正常使用
- [ ] 系统响应时间无明显变化
- [ ] 无新增bug

### 技术验收标准
- [ ] 单个服务类不超过500行
- [ ] 单个方法不超过50行
- [ ] 圈复杂度 <= 10
- [ ] 单元测试覆盖率 >= 80%
- [ ] 集成测试覆盖率 >= 60%
- [ ] 通过所有代码质量检查工具
- [ ] 架构文档完整更新

### 代码审查检查项
- [ ] 遵循单一职责原则
- [ ] 遵循开闭原则
- [ ] 依赖倒置原则
- [ ] 接口隔离原则
- [ ] 代码重复率 < 5%
- [ ] 注释清晰完整

## 设计约束

### 技术约束
- 必须使用FastAPI框架
- 必须使用SQLAlchemy ORM
- 必须使用dependency-injector库
- 必须保持向后兼容
- 不能修改数据库schema

### 业务约束
- 总工时不超过12个工作日
- 必须分阶段交付
- 每个阶段必须有可回滚点

### 环境约束
- 需要开发环境、测试环境
- 需要Docker支持
- 需要CI/CD流水线支持

## 风险评估

### 技术风险

| 风险项 | 概率 | 影响 | 缓解措施 |
|--------|------|------|----------|
| 重构过程中引入新bug | 中 | 高 | 分阶段重构，每阶段充分测试 |
| 性能下降 | 低 | 中 | 性能基准测试，持续监控 |
| 依赖注入配置复杂 | 中 | 中 | 提供详细文档和示例 |
| 破坏现有功能 | 中 | 高 | 完整的回归测试 |
| 第三方库兼容性 | 低 | 低 | 提前验证dependency-injector版本 |

### 业务风险

| 风险项 | 概率 | 影响 | 缓解措施 |
|--------|------|------|----------|
| 重构时间超出预期 | 中 | 中 | 分阶段交付，优先核心功能 |
| 影响其他开发工作 | 中 | 中 | 协调开发计划，避免冲突 |
| 团队成员学习成本 | 低 | 低 | 提供培训和技术分享 |

## 依赖关系

### 外部依赖
- dependency-injector库 - 依赖注入框架
- pytest - 测试框架
- pytest-asyncio - 异步测试支持

### 内部依赖
- 现有Podcast域代码
- 现有API路由
- 现有数据库模型

## 时间线

### 里程碑
- **需求确认**: 2026-01-25
- **设计完成**: 2026-01-26
- **阶段2-3完成（服务拆分+Core清理）**: 2026-01-30
- **阶段4完成（依赖注入）**: 2026-02-02
- **阶段5完成（通用组件）**: 2026-02-04
- **测试完成**: 2026-02-06
- **上线发布**: 2026-02-08

### 关键路径
```
TASK-ARCH-001 → TASK-ARCH-002 → TASK-B-001 → [TASK-B-002~006] → TASK-B-007
                                                        ↓
TASK-B-008 → TASK-B-009 → TASK-B-010 → TASK-B-011 → TASK-B-012~013 → TASK-B-014
                                                        ↓
                                              TASK-B-015~017 → TASK-B-018
                                                        ↓
                                              TASK-T-001~004 → TASK-D-001~002
```

## 技术方案详细设计

### 1. Podcast服务拆分方案

#### 服务类结构
```
app/domains/podcast/services/
├── __init__.py
├── base.py                    # 基础服务类
├── subscription_service.py    # 订阅管理
├── episode_service.py         # 单集管理
├── playback_service.py        # 播放进度
├── summary_service.py         # AI总结
├── search_service.py          # 搜索推荐
├── sync_service.py            # 同步刷新
└── podcast_service_facade.py  # 门面类（可选）
```

#### 基础服务类设计
```python
# app/domains/podcast/services/base.py
from abc import ABC, abstractmethod
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

class BasePodcastService(ABC):
    """Podcast服务基类"""

    def __init__(self, db: AsyncSession, user_id: int):
        self.db = db
        self.user_id = user_id
        self.repo = None  # 子类设置

    async def _validate_user_access(self, resource_id: int) -> bool:
        """验证用户访问权限"""
        pass

    async def _handle_error(self, error: Exception) -> None:
        """统一错误处理"""
        pass
```

#### 服务方法分配
- **SubscriptionService** (~300行)
  - add_subscription
  - add_subscriptions_batch
  - list_subscriptions
  - refresh_subscription
  - reparse_subscription
  - remove_subscription
  - get_subscription_details
  - get_subscription_by_id

- **EpisodeService** (~400行)
  - list_episodes
  - get_episode_by_id
  - get_episode_with_summary
  - search_podcasts
  - _get_episode_count
  - _get_unplayed_count

- **PlaybackService** (~200行)
  - get_playback_state
  - update_playback_progress
  - _calculate_listening_streak

- **SummaryService** (~400行)
  - generate_summary_for_episode
  - regenerate_summary
  - get_pending_summaries
  - _generate_summary_task
  - _generate_summary_with_session
  - _generate_summary
  - _call_llm_for_summary
  - _wait_for_existing_summary

- **SearchService** (~150行)
  - search_podcasts
  - get_recommendations
  - get_user_stats

- **SyncService** (~200行)
  - refresh_subscription
  - reparse_subscription
  - _validate_and_get_subscription
  - _get_episode_ids_for_subscription

### 2. Core层清理方案

#### 清理前后对比
```
清理前:
app/core/
├── feed_parser.py        # 移至 domains/subscription/services/
├── feed_schemas.py       # 移至 domains/subscription/schemas/
├── config.py             # 保留
├── security.py           # 保留
├── database.py           # 保留
├── exceptions.py         # 保留
└── dependencies.py       # 保留

清理后:
app/core/
├── config.py             # 配置管理
├── security.py           # 安全工具
├── database.py           # 数据库连接
├── exceptions.py         # 异常定义
├── dependencies.py       # FastAPI依赖
└── container.py          # DI容器（新增）
```

### 3. 依赖注入容器方案

#### 容器层次结构
```python
# app/core/container.py
from dependency_injector import containers, providers

class ApplicationContainer(containers.DeclarativeContainer):
    """应用级容器"""

    config = providers.Configuration()

    # Core组件
    database = providers.Singleton(Database, config.db_url)
    redis = providers.Singleton(Redis, config.redis_url)

    # Domain容器
    podcast = providers.Container(PodcastContainer, database=database, redis=redis)
    user = providers.Container(UserContainer, database=database)
    subscription = providers.Container(SubscriptionContainer, database=database)
    assistant = providers.Container(AssistantContainer, database=database)

# app/domains/podcast/container.py
class PodcastContainer(containers.DeclarativeContainer):
    """Podcast域容器"""

    database: providers.Provider

    # Repositories
    podcast_repository = providers.Factory(
        PodcastRepository,
        db=database
    )

    # Services
    subscription_service = providers.Factory(
        SubscriptionService,
        repo=podcast_repository
    )

    episode_service = providers.Factory(
        EpisodeService,
        repo=podcast_repository
    )

    # ... 其他服务
```

#### FastAPI集成
```python
# app/main.py
from app.core.container import ApplicationContainer

app = FastAPI()
container = ApplicationContainer()

@app.get("/api/v1/podcast/subscriptions")
async def list_subscriptions(
    service: SubscriptionService = Depends(container.podcast.subscription_service)
):
    return await service.list_subscriptions()
```

### 4. 通用组件方案

#### 分页组件
```python
# app/shared/pagination.py
from typing import Generic, TypeVar, List
from pydantic import BaseModel

T = TypeVar('T')

class PaginatedResponse(BaseModel, Generic[T]):
    """通用分页响应"""
    items: List[T]
    total: int
    page: int
    size: int
    pages: int

class PaginationHelper:
    """分页辅助类"""

    @staticmethod
    async def paginate(
        query: Select,
        page: int,
        size: int
    ) -> PaginatedResponse:
        """执行分页查询"""
        # 实现逻辑...
```

#### 响应构建组件
```python
# app/shared/response_builder.py
from typing import Any, Optional
from fastapi import status

class ResponseBuilder:
    """响应构建器"""

    @staticmethod
    def success(
        data: Any,
        message: Optional[str] = None
    ) -> dict:
        """构建成功响应"""
        return {
            "success": True,
            "data": data,
            "message": message
        }

    @staticmethod
    def error(
        error: str,
        code: Optional[str] = None,
        status_code: int = status.HTTP_400_BAD_REQUEST
    ) -> dict:
        """构建错误响应"""
        return {
            "success": False,
            "error": error,
            "code": code
        }
```

#### CRUD基类
```python
# app/shared/crud_base.py
from typing import Generic, TypeVar, Optional, Type
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

ModelType = TypeVar("ModelType")

class CRUDBase(Generic[ModelType]):
    """CRUD操作基类"""

    def __init__(self, model: Type[ModelType], db: AsyncSession):
        self.model = model
        self.db = db

    async def get(self, id: int) -> Optional[ModelType]:
        """根据ID获取"""
        result = await self.db.execute(
            select(self.model).where(self.model.id == id)
        )
        return result.scalar_one_or_none()

    async def create(self, obj_in: dict) -> ModelType:
        """创建"""
        db_obj = self.model(**obj_in)
        self.db.add(db_obj)
        await self.db.commit()
        await self.db.refresh(db_obj)
        return db_obj

    async def update(self, id: int, obj_in: dict) -> Optional[ModelType]:
        """更新"""
        # 实现逻辑...

    async def delete(self, id: int) -> bool:
        """删除"""
        # 实现逻辑...
```

### 5. 重构后的目录结构

```
backend/app/
├── core/                          # 核心层（基础设施）
│   ├── config.py                  # 配置
│   ├── security.py                # 安全
│   ├── database.py                # 数据库
│   ├── exceptions.py              # 异常
│   ├── dependencies.py            # FastAPI依赖
│   └── container.py               # DI容器（新增）
│
├── shared/                        # 共享层
│   ├── schemas.py                 # 通用schema
│   ├── pagination.py              # 分页组件（新增）
│   ├── response_builder.py        # 响应构建（新增）
│   ├── crud_base.py               # CRUD基类（新增）
│   └── utils.py                   # 工具函数
│
└── domains/                       # 领域层
    ├── podcast/                   # Podcast域
    │   ├── services/
    │   │   ├── __init__.py
    │   │   ├── base.py            # 基础服务类（新增）
    │   │   ├── subscription_service.py  # 订阅服务（新增）
    │   │   ├── episode_service.py       # 单集服务（新增）
    │   │   ├── playback_service.py      # 播放服务（新增）
    │   │   ├── summary_service.py       # 总结服务（新增）
    │   │   ├── search_service.py        # 搜索服务（新增）
    │   │   ├── sync_service.py          # 同步服务（新增）
    │   │   └── podcast_service_facade.py # 门面（可选）
    │   ├── repositories.py
    │   ├── models.py
    │   ├── schemas.py
    │   ├── api/
    │   │   └── routes.py
    │   └── container.py            # Podcast域容器（新增）
    │
    ├── subscription/              # Subscription域
    │   ├── services/
    │   │   ├── feed_parser.py     # 从core移入
    │   │   └── ...
    │   ├── schemas/
    │   │   ├── feed_schemas.py    # 从core移入
    │   │   └── ...
    │   └── container.py            # Subscription域容器（新增）
    │
    ├── user/
    ├── assistant/
    └── ...
```

## 变更记录

| 版本 | 日期 | 变更内容 | 变更人 | 审批人 |
|------|------|----------|--------|--------|
| 1.0 | 2026-01-25 | 初始创建 | 架构师 | 产品经理 |

## 相关文档

- [CLAUDE.md](../../CLAUDE.md) - 项目开发指南
- [README.md](../../README.md) - 项目说明
- 后续补充：详细设计文档、API文档、测试计划

## 审批

### 需求评审
- [x] 产品经理审批 - 自动确认
- [ ] 架构师审批 - 待审批
- [ ] 技术负责人审批 - 待审批

---

**注意**: 本重构需求遵循渐进式重构原则，分阶段实施，每阶段都有明确的验收标准和回滚方案。重构过程中保持向后兼容，确保不影响前端和其他依赖方。
