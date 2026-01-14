# RSS订阅重复检测增强需求

## 基本信息 / Basic Information
- **需求ID**: REQ-20260114-001
- **创建日期**: 2026-01-14
- **最后更新**: 2026-01-14
- **负责人**: Product Manager
- **状态**: Active
- **优先级**: High

## 需求描述 / Requirement Description

### 用户故事 / User Story
作为内容订阅者，我想要系统能够智能检测重复的RSS订阅（包括URL和标题），并在检测到重复时根据现有订阅状态采取适当的处理策略，以便避免重复订阅并自动修复失效的订阅链接。

### 业务价值 / Business Value
- **提升用户体验**: 避免用户意外创建重复订阅
- **自动修复失效订阅**: 当订阅源URL变更时，能够通过标题匹配自动更新链接
- **减少维护成本**: 自动检测和处理重复，减少手动管理工作

### 背景信息 / Background
- **当前状况**: 系统仅通过URL判断重复，当RSS源URL变更时无法识别为同一订阅
- **用户痛点**:
  - 同一RSS源可能有多个URL（如http/https、www/non-www等）
  - RSS源可能更换域名或URL
  - 用户可能不知道已存在类似订阅而重复添加
- **机会点**: 通过标题匹配实现更智能的重复检测

## 功能需求 / Functional Requirements

### 核心功能 / Core Features
- [FR-001] 增强重复检测：同时检查URL和标题
- [FR-002] 智能处理策略：根据现有订阅状态决定是否更新
- [FR-003] 批量导入支持：批量创建订阅时应用相同的重复检测逻辑

### 功能详述 / Feature Details

#### 功能1：增强的重复检测
- **描述**: 在创建新订阅时，除了检查URL重复外，还要检查标题是否相同
- **输入**: 订阅创建请求（包含URL和标题）
- **处理逻辑**:
  1. 首先检查URL是否已存在
  2. 如果URL不存在，检查标题是否已存在（不区分大小写）
  3. 如果URL或标题任一匹配，则认为订阅重复
- **输出**: 重复检测结果和适当的响应

#### 功能2：智能重复处理策略
- **描述**: 根据现有订阅的状态，采取不同的处理策略
- **输入**: 检测到重复的新订阅请求
- **处理逻辑**:
  - **现有订阅状态为 ACTIVE**: 跳过创建，返回提示信息
  - **现有订阅状态为 ERROR/INACTIVE/PENDING**:
    - 更新现有订阅的URL为新URL
    - 更新标题（如果不同）
    - 重置状态为 ACTIVE
    - 清空错误信息
- **输出**: 更新后的订阅信息或跳过提示

#### 功能3：批量导入支持
- **描述**: 批量创建订阅时，应用相同的重复检测和处理逻辑
- **处理逻辑**: 对每个订阅请求应用增强的重复检测
- **响应分类**:
  - `success`: 成功创建新订阅
  - `updated`: 更新了现有订阅（ERROR/INACTIVE/PENDING状态）
  - `skipped`: 跳过（ACTIVE状态的重复订阅）

## 非功能需求 / Non-Functional Requirements

### 性能要求
- **响应时间**: 重复检测查询应在 100ms 内完成
- **批量处理**: 批量导入 100 个订阅应在 5 秒内完成

### 数据库要求
- 需要在 `subscriptions` 表的 `title` 字段上添加索引以优化查询性能

### 兼容性要求
- 向后兼容：现有的API调用不受影响
- 数据迁移：无需数据迁移，仅添加索引

## 任务分解 / Task Breakdown

### Backend任务

- [ ] **TASK-B-001** 添加数据库索引
  - **负责人**: Backend Developer
  - **验收标准**:
    - [ ] 在 `subscriptions.title` 字段添加索引
    - [ ] 验证查询性能提升
  - **状态**: Todo

- [ ] **TASK-B-002** 实现增强的重复检测逻辑
  - **负责人**: Backend Developer
  - **验收标准**:
    - [ ] Repository 层添加 `get_subscription_by_title` 方法
    - [ ] Repository 层添加 `get_duplicate_subscription` 方法（同时检查URL和标题）
    - [ ] 单元测试覆盖率 > 90%
  - **状态**: Todo
  - **依赖**: TASK-B-001

- [ ] **TASK-B-003** 实现智能处理策略
  - **负责人**: Backend Developer
  - **验收标准**:
    - [ ] Service 层更新 `create_subscription` 方法
    - [ ] Service 层更新 `create_subscriptions_batch` 方法
    - [ ] 实现基于状态的更新逻辑
    - [ ] 集成测试通过
  - **状态**: Todo
  - **依赖**: TASK-B-002

- [ ] **TASK-B-004** 更新API响应
  - **负责人**: Backend Developer
  - **验收标准**:
    - [ ] 批量创建响应包含 `updated` 状态
    - [ ] 单个创建返回适当的错误/成功信息
    - [ ] API文档更新
  - **状态**: Todo
  - **依赖**: TASK-B-003

### 测试任务

- [ ] **TASK-T-001** 单元测试
  - **负责人**: Test Engineer
  - **验收标准**:
    - [ ] Repository 层测试（重复检测逻辑）
    - [ ] Service 层测试（处理策略）
    - [ ] 覆盖率 > 90%
  - **状态**: Todo
  - **依赖**: TASK-B-002, TASK-B-003

- [ ] **TASK-T-002** 集成测试
  - **负责人**: Test Engineer
  - **验收标准**:
    - [ ] API端到端测试
    - [ ] 各种状态组合的测试场景
  - **状态**: Todo
  - **依赖**: TASK-B-004

## 验收标准 / Acceptance Criteria

### 整体验收
- [ ] 所有功能需求已实现
- [ ] 单元测试覆盖率 > 90%
- [ ] 集成测试通过
- [ ] API文档更新完成

### 用户验收标准
- [ ] 场景1：添加已存在的活跃订阅（URL匹配）→ 返回跳过提示
- [ ] 场景2：添加已存在的活跃订阅（标题匹配，URL不同）→ 返回跳过提示
- [ ] 场景3：添加已存在的失效订阅（标题匹配）→ 更新URL并激活
- [ ] 场景4：批量导入混合场景 → 正确分类处理
- [ ] 场景5：添加全新的订阅 → 成功创建

### 技术验收标准
- [ ] 代码通过所有质量检查（black, isort, flake8, mypy）
- [ ] 数据库索引已创建
- [ ] 查询性能达标
- [ ] 无回归问题

## 设计约束 / Design Constraints

### 技术约束
- 必须使用现有的 Repository 和 Service 层架构
- 必须保持 API 向后兼容
- 标题匹配不区分大小写

### 业务约束
- 只对同一用户的订阅进行重复检测
- 更新操作只能由订阅所有者触发

## 风险评估 / Risk Assessment

### 技术风险
| 风险项 | 概率 | 影响 | 缓解措施 |
|--------|------|------|----------|
| 标题匹配误判 | 中 | 中 | 提供明确的用户提示，允许强制创建 |
| 性能下降 | 低 | 低 | 添加数据库索引优化查询 |
| 并发更新冲突 | 低 | 低 | 使用数据库事务和乐观锁 |

### 业务风险
| 风险项 | 概率 | 影响 | 缓解措施 |
|--------|------|------|----------|
| 用户误更新 | 低 | 中 | 只更新非活跃状态的订阅 |
| 标题变更导致误判 | 中 | 低 | 以URL匹配为主，标题为辅 |

## 测试场景 / Test Scenarios

### 场景1：URL完全匹配
- **前置条件**: 存在订阅，URL="https://example.com/feed.xml", 标题="Tech News", 状态=ACTIVE
- **操作**: 创建订阅，URL="https://example.com/feed.xml", 标题="Tech News"
- **预期结果**: 跳过创建，返回"订阅已存在"

### 场景2：标题匹配，URL不同，状态为ACTIVE
- **前置条件**: 存在订阅，URL="https://old.com/feed.xml", 标题="Tech News", 状态=ACTIVE
- **操作**: 创建订阅，URL="https://new.com/feed.xml", 标题="Tech News"
- **预期结果**: 跳过创建，返回"订阅已存在"

### 场景3：标题匹配，URL不同，状态为ERROR
- **前置条件**: 存在订阅，URL="https://old.com/feed.xml", 标题="Tech News", 状态=ERROR
- **操作**: 创建订阅，URL="https://new.com/feed.xml", 标题="Tech News"
- **预期结果**: 更新现有订阅的URL，重置状态为ACTIVE

### 场景4：完全不匹配
- **前置条件**: 存在订阅，URL="https://example.com/feed.xml", 标题="Tech News"
- **操作**: 创建订阅，URL="https://other.com/feed.xml", 标题="Other News"
- **预期结果**: 成功创建新订阅

### 场景5：批量导入
- **前置条件**:
  - 订阅A: URL="https://a.com/feed.xml", 标题="News A", 状态=ACTIVE
  - 订阅B: URL="https://b.com/feed.xml", 标题="News B", 状态=ERROR
- **操作**: 批量创建
  - 订阅1: URL="https://a.com/feed.xml", 标题="News A" (完全匹配)
  - 订阅2: URL="https://b2.com/feed.xml", 标题="News B" (标题匹配，非活跃)
  - 订阅3: URL="https://c.com/feed.xml", 标题="News C" (新订阅)
- **预期结果**:
  - 订阅1: skipped
  - 订阅2: updated
  - 订阅3: success

## 变更记录 / Change History

| 版本 | 日期 | 变更内容 | 变更人 | 审批人 |
|------|------|----------|--------|--------|
| 1.0 | 2026-01-14 | 初始创建 | Product Manager | - |

## 相关文档 / Related Documents
- Subscription API: `backend/app/domains/subscription/`
- 数据库模型: `backend/app/domains/subscription/models.py`

---
