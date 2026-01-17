# AI 思考内容过滤功能 / AI Thinking Content Filter

## 基本信息 / Basic Information
- **需求ID**: REQ-20250117-001
- **创建日期**: 2025-01-17
- **最后更新**: 2026-01-17
- **负责人**: Product Manager
- **状态 / Status**: Completed
- **优先级 / Priority**: High

## 需求描述 / Requirement Description

### 用户故事 / User Story
**中文**: 作为系统管理员，我想要在保存 AI 模型输出到数据库之前自动过滤掉思考内容（如 `<thinking>` 或 `<think>` 标签），以便数据库中只保存最终的有效回复内容。

**English**: As a system administrator, I want to automatically filter out thinking content (such as `<thinking>` or `<think>` tags) from AI model outputs before saving to the database, so that only the final effective response content is stored.

### 业务价值 / Business Value
- **数据清洁性**: 数据库中保存的是干净的最终回复，不包含中间思考过程
- **存储优化**: 减少无效内容的存储占用
- **用户体验**: 用户查看历史记录时只看到有价值的回复内容
- **一致性**: 确保所有 AI 响应在持久化前都经过统一的处理

### 背景信息 / Background
- **当前状况**: 文本生成模型（如某些推理模型）输出可能包含 `<thinking>` 或 `<think>` 标签包裹的思考内容
- **问题**: 这些思考内容会随最终回复一起保存到数据库的 `messages` 表中
- **机会点**: 在数据持久化前统一处理，确保数据质量

## 功能需求 / Functional Requirements

### 核心功能 / Core Features
- [FR-001] 自动识别并过滤 AI 响应中的 `<thinking>` 和 `<think>` 标签内容
- [FR-002] 支持嵌套或多段思考标签的过滤
- [FR-003] 保留最终的有效回复内容，且不破坏原有的排版、换行和中文标点

### 功能详述 / Feature Details

#### 功能1：思考内容过滤 / Thinking Content Filter
- **描述 / Description**: 从 AI 模型输出中移除 `<thinking>...</thinking>` 和 `<think>...</think>` 标签及其包裹的内容
- **输入 / Input**: AI 模型原始响应文本（可能包含 thinking 标签）
- **处理 / Processing**:
  - 使用正则表达式匹配标签，如 `r"<think>.*?</think>"`
  - 支持多行内容的匹配 (DOTALL)
  - 支持多段 thinking 标签的匹配
  - 仅对结果进行首尾 `strip()`，保留正文内部的换行和标点
- **输出 / Output**: 清理后的纯回复内容

#### 功能2：过滤时机 / Filter Timing
- **描述 / Description**: 在正确的时机执行过滤操作
- **位置**:
  1. AI 服务层 (`AIModelConfigService._call_text_generation_model`) 返回结果前
  2. 助手服务层 (`AssistantService.create_assistant_message`) 保存消息前
- **实现位置**: 在 AI 服务层统一处理，确保所有调用点都受益

## 非功能需求 / Non-Functional Requirements

### 性能要求 / Performance
- 过滤操作处理时间: < 10ms (针对常规响应长度)
- 不影响现有 API 响应时间

### 安全要求 / Security
- 过滤操作不应引入安全漏洞
- 保持原有内容的完整性（仅移除思考标签，不触碰正常文本）

### 可用性要求 / Availability
- 过滤失败时不应导致整个请求失败
- 应记录过滤操作的日志

## 任务分解 / Task Breakdown

### Backend任务
- [x] [TASK-B-001] 实现思考内容过滤函数
  - **负责人 / Assignee**: Backend Developer
  - **状态 / Status**: Done
  - **验收标准 / Acceptance Criteria**:
    - [x] 创建 `app/core/utils.py` 中的 `filter_thinking_content()` 函数
    - [x] 支持标准 `<thinking>` 和 `<think>` 标签过滤
    - [x] 支持多行内容匹配
    - [x] 支持多段标签匹配
    - [x] 单元测试覆盖率 100%
    - [x] 性能测试: 处理时间 < 10ms

- [x] [TASK-B-002] 在 AI 服务层集成过滤功能
  - **负责人 / Assignee**: Backend Developer
  - **状态 / Status**: Done
  - **验收标准 / Acceptance Criteria**:
    - [x] 修改 `AIModelConfigService._call_text_generation_model()`
    - [x] 在返回结果前调用过滤函数
    - [x] 更新相关单元测试
    - [x] 验证 fallback 机制同样受益

- [x] [TASK-B-003] 添加过滤操作的日志和监控
  - **负责人 / Assignee**: Backend Developer
  - **状态 / Status**: Done
  - **验收标准 / Acceptance Criteria**:
    - [x] 添加过滤操作的 debug 日志
    - [x] 记录过滤前后的内容长度变化
    - [x] 统计过滤操作次数

### 测试任务
- [x] [TASK-T-001] 编写单元测试
  - **负责人 / Assignee**: Test Engineer
  - **状态 / Status**: Done
  - **验收标准 / Acceptance Criteria**:
    - [x] 测试标准 thinking 标签过滤
    - [x] 测试多行 thinking 内容过滤
    - [x] 测试多段 thinking 标签过滤
    - [x] 测试无 thinking 标签的原样返回
    - [x] 测试保留正常换行和标点
    - [x] 测试覆盖率 100%

- [x] [TASK-T-002] 集成测试
  - **负责人 / Assignee**: Test Engineer
  - **状态 / Status**: Done
  - **验收标准 / Acceptance Criteria**:
    - [x] 测试完整的 AI 调用流程
    - [x] 验证数据库中保存的是过滤后的内容
    - [x] 验证 fallback 机制正常工作

## 验收标准 / Acceptance Criteria

### 整体验收 / Overall Acceptance
- [x] 所有功能需求已实现
- [x] 单元测试覆盖率 > 95%
- [x] 集成测试通过
- [x] 性能测试通过

### 用户验收标准 / User Acceptance
- [x] AI 响应中不再包含 `<thinking>` 和 `<think>` 标签内容
- [x] 最终回复内容完整保留（含原始排版和标点）
- [x] API 响应时间无明显增加

### 技术验收标准 / Technical Acceptance
- [ ] 代码质量达标（通过 black, isort, flake8, mypy 检查）
- [ ] 测试覆盖率 > 95%
- [ ] 日志记录完整
- [ ] 无性能回退

## 设计约束 / Design Constraints

### 技术约束 / Technical Constraints
- 使用 Python 标准库 `re` 模块实现正则表达式匹配
- 不引入额外的第三方依赖
- 兼容现有的 AI 模型调用流程

### 实现约束 / Implementation Constraints
- 过滤逻辑应在 AI 服务层统一实现
- 不应破坏现有的 fallback 机制
- 保持 API 响应格式不变

## 风险评估 / Risk Assessment

### 技术风险 / Technical Risks
| 风险项 | 概率 | 影响 | 缓解措施 |
|--------|------|------|----------|
| 正则表达式匹配不准确 | 低 | 中 | 编写全面的单元测试覆盖各种格式 |
| 性能影响 | 低 | 低 | 使用高效的正则表达式，进行性能测试 |
| 某些模型使用不同标签格式 | 中 | 中 | 设计灵活的过滤机制，支持配置 |

## 依赖关系 / Dependencies

### 内部依赖 / Internal Dependencies
- `app/domains/ai/services.py` - AI 服务层
- `app/domains/assistant/services.py` - 助手服务层
- `app/core/utils.py` - 工具函数（新建）

## 变更记录 / Change Log

| 版本 | 日期 | 变更内容 | 变更人 | 审批人 |
|------|------|----------|--------|--------|
| 1.0 | 2025-01-17 | 初始创建 | Product Manager | - |

## 相关文档 / Related Documents
- AI 服务代码: `backend/app/domains/ai/services.py`
- 助手服务代码: `backend/app/domains/assistant/services.py`

---

**注意 / Note**: 本文档遵循双语格式，支持中英文团队协作。
