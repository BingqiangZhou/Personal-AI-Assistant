# Episode Description Display Optimization / 分集描述显示优化

## 基本信息 / Basic Information
- **需求ID**: FEP-20250104-001
- **创建日期**: 2025-01-04
- **最后更新**: 2025-01-04
- **负责人**: Product Manager
- **状态**: Completed
- **优先级**: Medium

## 需求描述 / Requirement Description

### 用户故事 / User Story
作为播客听众，我想要在Feed页面和分集列表中快速了解每集的核心内容，以便更高效地决定是否收听该节目。

### 业务价值 / Business Value
- 提升用户浏览效率，快速判断节目价值
- 充分利用AI总结提供的高质量内容
- 改善用户体验，减少阅读时间

### 背景信息 / Background
目前，Feed页面分集卡片和播客订阅分集列表卡片中的描述信息显示的是原始`description`字段（来自shownotes）。然而，系统已经为许多分集生成了AI总结，其中包含"主要话题"部分，这是对内容更精炼的概括。用户希望优先显示AI总结中的核心信息，以获得更好的浏览体验。

## 功能需求 / Functional Requirements

### 核心功能 / Core Features
- [FR-001] 在分集卡片中优先显示AI总结的"主要话题"部分
- [FR-002] 当没有AI总结时，回退到显示HTML标签清理后的shownotes纯文本
- [FR-003] 保持现有的显示样式和行数限制

### 功能详述 / Feature Details

#### 功能1：提取AI总结的主要话题
- **描述**: 从AI总结（`aiSummary`字段）中提取"主要话题"部分
- **输入**: `aiSummary`字符串（Markdown格式）
- **处理**:
  1. 检查`aiSummary`是否存在且不为空
  2. 使用正则表达式匹配`## 主要话题`和下一个`##`标题之间的内容
  3. 如果匹配成功，返回该部分内容
  4. 如果匹配失败，返回null
- **输出**: 提取的主要话题字符串，或null

#### 功能2：HTML标签清理
- **描述**: 从shownotes中移除HTML标签，提取纯文本
- **输入**: `description`字符串（可能包含HTML标签）
- **处理**:
  1. 使用HTML清理器移除所有HTML标签
  2. 保留文本内容的可读性
  3. 移除多余的空白字符
- **输出**: 清理后的纯文本字符串

#### 功能3：描述显示逻辑
- **描述**: 在分集卡片中实现智能的描述显示逻辑
- **逻辑流程**:
  1. 首先尝试从`aiSummary`中提取"主要话题"
  2. 如果提取成功，显示"主要话题"内容
  3. 如果没有AI总结或提取失败，显示清理后的`description`
  4. 如果两者都没有，不显示描述区域
- **显示位置**:
  - Feed页面分集卡片（`FeedStyleEpisodeCard`）
  - 播客订阅分集列表卡片（`SimplifiedEpisodeCard`）

## 非功能需求 / Non-Functional Requirements

### 性能要求 / Performance Requirements
- 文本处理应在10ms内完成
- 不影响页面滚动性能

### 兼容性要求 / Compatibility Requirements
- 支持桌面、Web和移动端
- 与现有Material 3设计保持一致

## 任务分解 / Task Breakdown

### Frontend任务
- [TASK-F-001] 创建episode描述显示工具函数
  - **负责人**: Frontend Developer
  - **文件**: `lib/features/podcast/core/utils/episode_description_helper.dart`
  - **验收标准**:
    - [x] 实现`extractMainTopicsFromAiSummary`函数
    - [x] 实现`stripHtmlTags`函数
    - [x] 实现`getDisplayDescription`函数（整合逻辑）
    - [x] 单元测试覆盖所有场景
  - **状态**: Done

- [TASK-F-002] 修改FeedStyleEpisodeCard组件
  - **负责人**: Frontend Developer
  - **文件**: `lib/features/podcast/presentation/widgets/feed_style_episode_card.dart`
  - **验收标准**:
    - [x] 使用新的`getDisplayDescription`函数
    - [x] 保持现有UI样式不变
    - [x] Widget测试验证显示逻辑
  - **状态**: Done

- [TASK-F-003] 修改SimplifiedEpisodeCard组件
  - **负责人**: Frontend Developer
  - **文件**: `lib/features/podcast/presentation/widgets/simplified_episode_card.dart`
  - **验收标准**:
    - [x] 使用新的`getDisplayDescription`函数
    - [x] 保持现有UI样式不变
    - [x] Widget测试验证显示逻辑
  - **状态**: Done

- [TASK-F-004] 编写Widget测试
  - **负责人**: Frontend Developer
  - **文件**: `test/widget/podcast/episode_description_test.dart`
  - **验收标准**:
    - [x] 测试有AI总结时显示主要话题
    - [x] 测试无AI总结时显示清理后的description
    - [x] 测试两者都无的情况
  - **状态**: Done

## 验收标准 / Acceptance Criteria

### 整体验收 / Overall Acceptance
- [x] 需求文档已完成
- [x] 所有功能需求已实现
- [x] 所有测试通过（24个测试用例全部通过）
- [x] 代码质量检查通过

### 用户验收标准 / User Acceptance Criteria
- [x] 用户在有AI总结的分集中看到"主要话题"而非原始description
- [x] 用户在没有AI总结的分集中看到清理后的纯文本description
- [x] HTML实体被正确解码（&nbsp; → 空格，&amp; → &，&quot; → " 等）
- [x] 数字HTML实体被正确解码（&#36; → $，&#8364; → € 等）
- [x] 显示样式与原有一致
- [x] 所有平台表现一致

### 技术验收标准 / Technical Acceptance Criteria
- [x] 工具函数单元测试覆盖率 100%（17个单元测试）
- [x] Widget测试覆盖所有场景（7个widget测试）
- [x] 代码通过flutter analyze
- [x] 性能无明显影响

## 设计约束 / Design Constraints

### 技术约束 / Technical Constraints
- 必须使用Dart/Flutter实现
- 不能修改后端API
- 使用现有的html_sanitizer工具进行HTML清理

### 数据约束 / Data Constraints
- AI总结格式为Markdown，包含`## 主要话题`部分
- Description可能包含HTML标签
- 最大显示行数保持4行

## 参考信息 / References

### AI总结格式示例 / AI Summary Format Example
```markdown
## 主要话题
- 探讨了AI技术在医疗领域的应用
- 分析了大型语言模型的发展趋势
- 讨论了数据隐私保护的重要性

## 关键见解
深入洞察内容...

## 行动建议
具体步骤...

## 扩展思考
关联问题...
```

### 相关文件 / Related Files
- `frontend/lib/features/podcast/data/models/podcast_episode_model.dart` - Episode数据模型
- `frontend/lib/features/podcast/presentation/widgets/feed_style_episode_card.dart` - Feed分集卡片
- `frontend/lib/features/podcast/presentation/widgets/simplified_episode_card.dart` - 简化分集卡片
- `frontend/lib/features/podcast/core/utils/html_sanitizer.dart` - HTML清理工具
- `backend/app/domains/podcast/services.py` - AI总结生成逻辑

## 变更记录 / Change Log

| 版本 | 日期 | 变更内容 | 变更人 |
|------|------|----------|--------|
| 1.0 | 2025-01-04 | 初始创建 | Product Manager |

---

**注意**: 本需求为纯前端优化，不涉及后端修改。所有逻辑在前端实现，确保向后兼容。
