# 播客订阅批量删除功能 / Podcast Subscription Bulk Delete Feature

## Basic Information / 基本信息

- **Requirement ID / 需求ID**: FEP-20241229-001
- **Created Date / 创建日期**: 2024-12-29
- **Last Updated / 最后更新**: 2024-12-29
- **Owner / 负责人**: Product Manager
- **Status / 状态**: ⚠️ **Verification Failed - Needs Fixes / 验收未通过 - 需要修复**
- **Priority / 优先级**: High
- **Verification Report / 验收报告**: [查看详细报告 / View Detailed Report](./FEP-20241229-podcast-bulk-delete-verification-report.md)

## Requirement Description / 需求描述

### User Story / 用户故事 (Bilingual)

**中文 / Chinese:**

作为一名播客收听用户，我想要在 Podcasts 页面右上角添加批量删除按钮并实现批量删除播客订阅的功能，以便我可以一次性删除多个不再需要的播客订阅，而不需要逐个点击删除。

**English:**

As a podcast listener user, I want to add a bulk delete button in the upper right corner of the Podcasts page and implement the ability to bulk delete podcast subscriptions, so that I can remove multiple unwanted podcast subscriptions at once without having to delete them individually.

### Business Value / 业务价值

- **提升用户效率 / Improve User Efficiency**: 用户可以一次性删除多个不再需要的播客订阅，节省时间和操作步骤
- **改善用户体验 / Enhance User Experience**: 减少重复操作，提供更便捷的订阅管理方式
- **增加用户粘性 / Increase User Retention**: 更好的管理工具鼓励用户保持订阅列表的整洁

**Success Metrics / 成功指标**:
- 批量删除操作成功率达到 99% 以上
- 用户操作步骤减少 80%（相比逐个删除）
- 功能使用率达到订阅管理功能的 30% 以上

### Background Information / 背景信息

**Current Situation / 当前状况**:
- 现有的 `PodcastListPage` 只有单个添加按钮 (`IconButton` with `Icons.add`)
- 删除操作只能通过逐个点击订阅卡片进入详情页后删除
- 没有批量选择和批量操作的功能

**User Pain Points / 用户痛点**:
- 当用户想要清理多个不再收听的播客时，需要重复多次操作
- 长期积累的大量订阅管理效率低下
- 缺乏便捷的批量管理工具

**Opportunity / 机会点**:
- 添加批量操作模式，提升订阅管理的灵活性
- 引入 Material 3 的选择模式 UI 组件
- 为未来其他批量操作（如批量刷新、批量移动分类）奠定基础

## Functional Requirements / 功能需求

### Core Features / 核心功能

- **FR-001** 批量删除按钮 - 在 Podcasts 页面右上角添加批量删除入口按钮
- **FR-002** 批量选择模式 - 支持进入/退出批量选择模式
- **FR-003** 批量删除确认 - 在删除前显示确认对话框
- **FR-004** 批量删除执行 - 调用后端 API 执行批量删除操作
- **FR-005** 删除结果反馈 - 显示删除操作的结果（成功/失败数量）

### Feature Details / 功能详述

#### Feature 1: 批量删除入口按钮 / Bulk Delete Entry Button

**Description / 描述**:
在 Podcasts 页面右上角添加一个批量删除按钮，位于现有的"添加订阅"和"批量导入"按钮旁边。

**UI Requirements / UI 要求**:
- 使用 Material 3 的 `IconButton` 组件
- 图标: `Icons.delete_sweep` 或 `Icons.delete_outline`
- Tooltip: "批量删除" / "Bulk Delete"
- 位置: 在现有操作按钮组中，位于 "批量导入" 按钮之后
- 仅在有订阅数据时显示（空状态隐藏）

**States / 状态**:
- **Normal / 正常状态**: 可点击，进入批量选择模式
- **Disabled / 禁用状态**: 订阅列表为空时禁用
- **Hover / 悬停状态**: Material 3 标准悬停效果

#### Feature 2: 批量选择模式 / Bulk Selection Mode

**Description / 描述**:
点击批量删除按钮后，页面进入批量选择模式，允许用户选择要删除的订阅。

**UI Behavior / UI 行为**:
1. **进入选择模式**:
   - 页面标题改为 "选择要删除的播客" / "Select Podcasts to Delete"
   - 每个订阅卡片/列表项左侧显示复选框
   - 底部显示批量操作栏（确认/取消按钮）
   - 批量删除按钮变为退出选择模式按钮

2. **选择交互**:
   - 点击卡片可切换选中状态
   - 支持全选/取消全选功能
   - 实时显示已选数量（例如："已选 3 项" / "3 Selected"）

3. **退出选择模式**:
   - 点击返回按钮或"取消"按钮
   - 完成删除操作后自动退出
   - 清除所有选中状态

**Visual States / 视觉状态**:
- **未选中**: 卡片保持原样
- **选中**: 卡片显示选中边框或背景色变化（Material 3 标准选中样式）
- **部分选中**: 全选复选框显示为"-"状态

#### Feature 3: 删除确认对话框 / Delete Confirmation Dialog

**Description / 描述**:
在执行批量删除前，显示确认对话框，防止误操作。

**Dialog Content / 对话框内容**:
```
标题: 确认删除播客 / Confirm Delete Podcasts
内容: 您确定要删除选中的 N 个播客订阅吗？
       删除后，这些订阅及其所有单集数据将被永久删除。
       / Are you sure you want to delete the selected N podcast subscriptions?
       All episodes and data will be permanently deleted.

按钮: [取消 / Cancel] [删除 / Delete]
```

**Validation / 验证**:
- 至少选择 1 个订阅才能点击"删除"按钮
- 未选择任何订阅时，删除按钮禁用

#### Feature 4: 后端批量删除 API / Backend Bulk Delete API

**API Endpoint / API 端点**:
```
DELETE /api/v1/podcasts/subscriptions/bulk
```

**Request Format / 请求格式**:
```json
{
  "subscription_ids": [1, 2, 3, 4, 5]
}
```

**Response Format / 响应格式**:
```json
{
  "success_count": 4,
  "failed_count": 1,
  "errors": [
    {
      "subscription_id": 3,
      "message": "Subscription not found or no permission"
    }
  ]
}
```

**Business Logic / 业务逻辑**:
1. 验证用户身份和权限
2. 验证所有订阅 ID 是否属于当前用户
3. 逐个删除订阅及其关联数据：
   - 删除订阅的所有单集
   - 删除单集的播放进度记录
   - 删除单集的 AI 总结和转录记录
   - 删除订阅关联的对话历史
   - 最后删除订阅本身
4. 使用数据库事务确保数据一致性
5. 记录成功和失败的删除操作

**Error Handling / 错误处理**:
- 404: 订阅不存在或无权限
- 400: 请求体为空或格式错误
- 500: 服务器内部错误

#### Feature 5: 删除结果反馈 / Deletion Result Feedback

**Success Scenario / 成功场景**:
- 显示 SnackBar: "成功删除 N 个播客订阅" / "Successfully deleted N podcast subscriptions"
- 刷新订阅列表
- 退出批量选择模式

**Partial Failure Scenario / 部分失败场景**:
- 显示 SnackBar: "成功删除 N 个，失败 M 个" / "Deleted N, failed M"
- 可点击查看详细错误信息
- 刷新订阅列表
- 退出批量选择模式

**Complete Failure Scenario / 完全失败场景**:
- 显示错误对话框: "删除失败，请稍后重试" / "Deletion failed, please try again later"
- 保持当前选择状态
- 保持在批量选择模式

## Non-Functional Requirements / 非功能需求

### Performance Requirements / 性能要求

- **Response Time / 响应时间**:
  - 批量删除 10 个订阅应在 2 秒内完成
  - 批量删除 50 个订阅应在 10 秒内完成
- **UI Responsiveness / UI 响应性**:
  - 进入/退出选择模式 < 100ms
  - 切换选中状态 < 50ms
- **Database Performance / 数据库性能**:
  - 使用批量删除操作优化数据库性能
  - 避免逐个删除导致的性能问题

### Security Requirements / 安全要求

- **Authentication / 身份验证**:
  - 所有 API 请求必须包含有效的 JWT token
  - 验证用户只能删除自己的订阅
- **Authorization / 权限控制**:
  - 严格验证订阅所有权
  - 防止跨用户删除攻击
- **Data Integrity / 数据完整性**:
  - 使用数据库事务确保关联数据的一致性删除
  - 记录删除操作的审计日志

### Usability Requirements / 可用性要求

- **Accessibility / 无障碍性**:
  - 所有按钮和交互元素支持键盘导航
  - 提供语义化的屏幕阅读器标签
  - 遵循 WCAG 2.1 AA 标准
- **User Feedback / 用户反馈**:
  - 每个操作都有明确的视觉反馈
  - Loading 状态显示进度指示器
  - 错误信息清晰易懂
- **Undo Capability / 撤销能力**:
  - 考虑实现"撤销删除"功能（可选，增强用户体验）

### Compatibility Requirements / 兼容性要求

- **Platforms / 平台**:
  - Desktop: Windows, macOS, Linux
  - Mobile: iOS, Android
  - Web: Chrome, Firefox, Safari, Edge
- **Screen Sizes / 屏幕尺寸**:
  - Mobile: < 600dp
  - Tablet: 600-840dp
  - Desktop: > 840dp
- **Material 3 Design**:
  - 遵循 Material 3 设计规范
  - 使用 `flutter_adaptive_scaffold` 实现响应式布局

## Task Breakdown / 任务分解

### Backend Tasks / 后端任务

- [ ] **TASK-B-001** 实现批量删除 API 端点
  - **负责人**: Backend Developer
  - **预估工时**: 4 小时
  - **验收标准**:
    - [ ] 实现 `DELETE /api/v1/podcasts/subscriptions/bulk` 端点
    - [ ] 请求体验证（订阅 ID 列表）
    - [ ] 权限验证（用户只能删除自己的订阅）
    - [ ] 数据库事务实现（确保关联数据一致性删除）
    - [ ] 返回成功/失败计数和详细错误信息
    - [ ] API 文档更新
  - **依赖**: 无
  - **状态**: Todo

- [ ] **TASK-B-002** 添加批量删除 Schema 定义
  - **负责人**: Backend Developer
  - **预估工时**: 1 小时
  - **验收标准**:
    - [ ] 在 `schemas.py` 中添加 `PodcastSubscriptionBulkDelete` request schema
    - [ ] 在 `schemas.py` 中添加 `PodcastSubscriptionBulkDeleteResponse` response schema
    - [ ] Pydantic 验证规则（至少 1 个订阅 ID，最多 100 个）
  - **依赖**: TASK-B-001
  - **状态**: Todo

- [ ] **TASK-B-003** 实现批量删除 Service 层方法
  - **负责人**: Backend Developer
  - **预估工时**: 3 小时
  - **验收标准**:
    - [ ] 在 `services.py` 中添加 `remove_subscriptions_bulk()` 方法
    - [ ] 优化批量删除性能（使用批量 SQL 操作）
    - [ ] 正确处理关联数据删除（单集、进度、总结、转录、对话）
    - [ ] 错误处理和日志记录
  - **依赖**: 无
  - **状态**: Todo

- [ ] **TASK-B-004** 编写后端单元测试
  - **负责人**: Backend Developer
  - **预估工时**: 3 小时
  - **验收标准**:
    - [ ] 测试正常删除场景
    - [ ] 测试部分失败场景
    - [ ] 测试权限验证
    - [ ] 测试请求体验证
    - [ ] 测试数据库事务回滚
    - [ ] 测试覆盖率 > 80%
  - **依赖**: TASK-B-001, TASK-B-002, TASK-B-003
  - **状态**: Todo

### Frontend Tasks / 前端任务

- [ ] **TASK-F-001** 添加批量删除按钮到 PodcastListPage
  - **负责人**: Frontend Developer
  - **预估工时**: 2 小时
  - **验收标准**:
    - [ ] 在页面右上角添加批量删除 IconButton
    - [ ] 使用 Material 3 图标和样式
    - [ ] 添加 Tooltip（中英文）
    - [ ] 仅在有订阅数据时显示
    - [ ] 响应式布局（移动端、平板、桌面）
  - **依赖**: 无
  - **状态**: Todo

- [ ] **TASK-F-002** 实现批量选择模式 UI
  - **负责人**: Frontend Developer
  - **预估工时**: 6 小时
  - **验收标准**:
    - [ ] 实现选择模式状态管理（Riverpod State）
    - [ ] 订阅卡片/列表项显示复选框
    - [ ] 支持单个选择和取消选择
    - [ ] 实现全选/取消全选功能
    - [ ] 显示已选数量统计
    - [ ] 选中状态的视觉反馈（Material 3 样式）
    - [ ] 移动端和桌面端适配
  - **依赖**: TASK-F-001
  - **状态**: Todo

- [ ] **TASK-F-003** 实现删除确认对话框
  - **负责人**: Frontend Developer
  - **预估工时**: 2 小时
  - **验收标准**:
    - [ ] 使用 Material 3 `AlertDialog` 组件
    - [ ] 显示选中订阅数量
    - [ ] 警告文本提示数据将永久删除
    - [ ] 取消和删除按钮（Material 3 样式）
    - [ ] 中英文双语支持
  - **依赖**: TASK-F-002
  - **状态**: Todo

- [ ] **TASK-F-004** 调用批量删除 API
  - **负责人**: Frontend Developer
  - **预估工时**: 3 小时
  - **验收标准**:
    - [ ] 在 `PodcastRepository` 中添加 `deleteSubscriptionsBulk()` 方法
    - [ ] 实现错误处理和网络异常处理
    - [ ] 添加 Loading 状态指示器
    - [ ] 处理成功、部分失败、完全失败三种场景
  - **依赖**: TASK-B-001
  - **状态**: Todo

- [ ] **TASK-F-005** 实现删除结果反馈
  - **负责人**: Frontend Developer
  - **预估工时**: 2 小时
  - **验收标准**:
    - [ ] 使用 SnackBar 显示操作结果
    - [ ] 成功: 显示成功删除数量
    - [ ] 部分失败: 显示成功和失败数量，提供查看详情选项
    - [ ] 完全失败: 显示错误消息
    - [ ] 删除成功后刷新订阅列表
    - [ ] 自动退出批量选择模式
  - **依赖**: TASK-F-004
  - **状态**: Todo

- [ ] **TASK-F-006** 添加国际化支持
  - **负责人**: Frontend Developer
  - **预估工时**: 1 小时
  - **验收标准**:
    - [ ] 添加中英文翻译字符串到 `app_localizations.dart`
    - [ ] 批量删除按钮 Tooltip
    - [ ] 选择模式提示文本
    - [ ] 确认对话框标题和内容
    - [ ] 成功/失败提示消息
  - **依赖**: TASK-F-001, TASK-F-003, TASK-F-005
  - **状态**: Todo

### Test Tasks / 测试任务

- [ ] **TASK-T-001** 编写前端 Widget 测试
  - **负责人**: Test Engineer
  - **预估工时**: 4 小时
  - **验收标准**:
    - [ ] 测试批量删除按钮渲染
    - [ ] 测试进入批量选择模式
    - [ ] 测试选择和取消选择订阅
    - [ ] 测试全选/取消全选
    - [ ] 测试删除确认对话框
    - [ ] 测试 API 调用（使用 Mock）
    - [ ] 测试成功、部分失败、完全失败场景
    - [ ] 测试退出批量选择模式
  - **依赖**: TASK-F-001, TASK-F-002, TASK-F-003, TASK-F-004, TASK-F-005
  - **状态**: Todo

- [ ] **TASK-T-002** 编写后端集成测试
  - **负责人**: Test Engineer
  - **预估工时**: 3 小时
  - **验收标准**:
    - [ ] 测试批量删除 API 端点
    - [ ] 测试权限验证
    - [ ] 测试关联数据正确删除
    - [ ] 测试事务回滚
    - [ ] 测试性能（批量删除 50 个订阅）
  - **依赖**: TASK-B-001, TASK-B-002, TASK-B-003, TASK-B-004
  - **状态**: Todo

- [ ] **TASK-T-003** 执行端到端测试
  - **负责人**: Test Engineer
  - **预估工时**: 2 小时
  - **验收标准**:
    - [ ] 手动测试完整用户流程
    - [ ] 测试不同屏幕尺寸（移动端、平板、桌面）
    - [ ] 测试边界情况（空列表、单个订阅、大量订阅）
    - [ ] 测试网络错误处理
    - [ ] 测试无障碍功能（键盘导航）
  - **依赖**: TASK-F-001, TASK-F-002, TASK-F-003, TASK-F-004, TASK-F-005, TASK-F-006, TASK-B-001
  - **状态**: Todo

## Acceptance Criteria / 验收标准

### Overall Acceptance / 整体验收

- [ ] 所有功能需求已实现并经过测试
- [ ] 性能指标达标（批量删除响应时间符合要求）
- [ ] 安全测试通过（权限验证、数据一致性）
- [ ] 用户验收测试通过（UX 符合预期）

### User Acceptance Criteria / 用户验收标准

- [ ] 用户可以在 Podcasts 页面右上角看到批量删除按钮
- [ ] 点击批量删除按钮后，页面进入选择模式
- [ ] 用户可以逐个选择订阅或全选
- [ ] 页面实时显示已选数量
- [ ] 点击确认后显示删除确认对话框
- [ ] 确认后订阅被删除，显示成功/失败反馈
- [ ] 删除成功后列表自动刷新
- [ ] 所有操作响应时间 < 2 秒
- [ ] 错误处理清晰友好
- [ ] 界面直观易用，符合 Material 3 设计规范

### Technical Acceptance Criteria / 技术验收标准

- [ ] 代码质量符合项目标准（Black、isort、mypy 通过）
- [ ] 后端单元测试覆盖率 > 80%
- [ ] 前端 Widget 测试覆盖所有场景
- [ ] API 文档完整且准确
- [ ] 国际化支持完整（中英文）
- [ ] 无障碍功能符合 WCAG 2.1 AA 标准
- [ ] 响应式设计在所有屏幕尺寸下正常工作

## Design Constraints / 设计约束

### Technical Constraints / 技术约束

**Backend / 后端**:
- 必须使用 FastAPI 框架
- 必须使用 SQLAlchemy async ORM
- 必须遵循项目的 DDD 架构（Service-Repository 模式）
- 必须使用 PostgreSQL 数据库
- 必须使用数据库事务确保数据一致性

**Frontend / 前端**:
- 必须使用 Flutter 框架
- 必须使用 Riverpod 进行状态管理
- 必须使用 Material 3 设计组件
- 必须使用 `flutter_adaptive_scaffold` 实现响应式布局
- 必须支持中英文双语

**Integration / 集成**:
- 必须与现有的 JWT 认证系统集成
- 必须与现有的订阅列表页面集成
- 不能破坏现有功能

### Business Constraints / 业务约束

- **Time Window / 时间窗口**: 目标在 2 个 Sprint 内完成（约 4 周）
- **Budget / 预算**: 使用现有开发资源，无额外预算需求
- **Compliance / 合规**: 遵守数据保护法规（GDPR），确保用户数据彻底删除

### Environment Constraints / 环境约束

- **Development / 开发**: 本地 Docker 环境测试
- **Staging / 预发布**: 云端测试环境验证
- **Production / 生产**: 需要通过 DevOps 部署流水线
- **Monitoring / 监控**: 需要添加删除操作的监控和日志

## Risk Assessment / 风险评估

### Technical Risks / 技术风险

| Risk / 风险项 | Probability / 概率 | Impact / 影响 | Mitigation / 缓解措施 |
|---------------|-------------------|--------------|----------------------|
| 批量删除导致数据库性能问题 | Medium / 中 | High / 高 | 使用批量删除 SQL 优化，添加索引，限制单次删除数量（最多 100 个） |
| 关联数据删除不完整导致数据孤立 | Low / 低 | High / 高 | 使用数据库事务，添加外键约束，编写完整的单元测试 |
| 前端选择模式性能问题（大量订阅） | Low / 低 | Medium / 中 | 使用虚拟滚动，懒加载，限制同时渲染的卡片数量 |
| API 兼容性问题 | Low / 低 | Medium / 中 | 严格版本控制，API 文档更新，向后兼容测试 |

### Business Risks / 业务风险

| Risk / 风险项 | Probability / 概率 | Impact / 影响 | Mitigation / 缓解措施 |
|---------------|-------------------|--------------|----------------------|
| 用户误删重要订阅 | Medium / 中 | High / 高 | 添加确认对话框，考虑实现"撤销删除"功能，添加警告提示 |
| 功能使用率低 | Low / 低 | Low / 低 | 用户教育，UI 提示，收集用户反馈优化设计 |
| 竞品压力 | Low / 低 | Medium / 中 | 关注竞品动态，持续改进用户体验 |

## Dependencies / 依赖关系

### External Dependencies / 外部依赖

| Dependency / 依赖 | Purpose / 用途 | Availability / 可用性 |
|-------------------|---------------|----------------------|
| FastAPI | Backend API framework | Available |
| SQLAlchemy | Database ORM | Available |
| PostgreSQL | Database | Available |
| Flutter | Frontend framework | Available |
| Riverpod | State management | Available |
| flutter_adaptive_scaffold | Responsive layout | Available |

### Internal Dependencies / 内部依赖

| Module / 模块 | Dependency / 依赖说明 |
|---------------|----------------------|
| `app.domains.podcast.services` | 依赖 PodcastService 的现有删除逻辑 |
| `app.domains.podcast.repositories` | 依赖 PodcastRepository 的数据访问方法 |
| `app.core.security` | 依赖 JWT 认证和权限验证 |
| `frontend/lib/features/podcast/presentation/pages/podcast_list_page.dart` | 在现有页面添加批量删除功能 |
| `frontend/lib/features/podcast/data/repositories/podcast_repository.dart` | 添加批量删除 API 调用方法 |

## Timeline / 时间线

### Milestones / 里程碑

- **Requirement Confirmation / 需求确认**: 2024-12-29 (已完成 / Completed)
- **Design Complete / 设计完成**: 2024-12-30
- **Backend Development / 后端开发**: 2025-01-03
- **Frontend Development / 前端开发**: 2025-01-10
- **Testing Complete / 测试完成**: 2025-01-15
- **Release / 上线发布**: 2025-01-17

### Critical Path / 关键路径

```
需求确认 → 后端 API 开发 → 前端 UI 开发 → 集成测试 → 上线
    ↓
Schema 定义
    ↓
Service 实现
    ↓
单元测试
    ↓
Widget 测试
```

**Parallel Tasks / 并行任务**:
- 后端 API 开发与前端 UI 开发可以部分并行（UI Mock 数据先行）
- 国际化支持可以与功能开发并行进行

## Change Record / 变更记录

| Version / 版本 | Date / 日期 | Change / 变更内容 | Author / 变更人 | Reviewer / 审批人 |
|----------------|-------------|-------------------|-----------------|-------------------|
| 1.0 | 2024-12-29 | Initial requirement creation / 初始需求创建 | Product Manager | - |

## Related Documents / 相关文档

- [Design Document / 设计文档] (待创建)
- [API Documentation / API 文档] (待更新)
- [UI Mockups / UI 原型] (待创建)
- [Test Plan / 测试计划] (待创建)

## Approval / 审批

### Requirement Review / 需求评审

- [x] Product Owner Approval / 产品负责人审批
- [ ] Tech Lead Approval / 技术负责人审批
- [ ] QA Lead Approval / QA 负责人审批

### Release Approval / 上线审批

- [ ] Product Owner / 产品负责人
- [ ] Tech Lead / 技术负责人
- [ ] DevOps Lead / 运维负责人

---

**Note / 注意**: This document is the core working document, please update it in time and keep version synchronization.
**注意**: 本文档是工作过程中的核心文档，请及时更新并保持版本同步。
