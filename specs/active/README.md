# Personal AI Assistant - 活跃需求文档索引 / Active Requirements Index

**更新日期**: 2025-01-02

---

## 当前活跃功能 / Current Active Features

### 1. 播客功能增强 / Podcast Feature Enhancements
| 文档名称 | 文件路径 | 描述 | 状态 |
|---------|---------|------|------|
| 播客搜索功能需求 | `podcast-itunes-search-feature.md` | iTunes Search API 集成，支持播客搜索和订阅 | Active |
| **订阅状态指示器功能** | `podcast-subscription-status-indicator.md` | **搜索结果中显示订阅状态** | **Active** |
| **Shownotes HTML渲染功能** | `podcast-shownotes-html-rendering.md` | **富文本HTML内容渲染，支持图片和链接（NEW!）** | **Active** |

**功能概述**:
- 集成 iTunes Search API 实现播客搜索
- Material 3 搜索 UI 组件（SearchBar/SearchAnchor）
- 搜索结果展示和直接订阅
- **搜索结果中显示订阅状态指示器（已订阅/未订阅）**
- **Shownotes 富文本 HTML 渲染（图片、链接、格式）**
- 缓存机制避免 API 限流
- 中英文搜索支持
- 完整的错误处理和用户反馈

**快速导航**:
- 📋 [播客搜索需求文档](./podcast-itunes-search-feature.md)
- 📋 [订阅状态指示器需求](./podcast-subscription-status-indicator.md)
- 📋 [Shownotes HTML渲染需求](./podcast-shownotes-html-rendering.md)

**开发进度**: 搜索功能已完成 | 订阅状态指示器 0% | Shownotes HTML渲染 0% (需求阶段完成，待审批和开发)

---

### 2. 应用更新提醒功能 / App Update Notification Feature
| 文档名称 | 文件路径 | 描述 | 状态 |
|---------|---------|------|------|
| 应用更新提醒功能需求 | `app-update-notification-feature.md` | 完整的应用更新检查和提示功能 | Active |
| 任务跟踪文档 | `app-update-notification-task-tracking.md` | 详细任务分解和进度跟踪 | Active |

**功能概述**:
- 检查 GitHub Releases 获取最新版本
- 版本号对比（当前版本 vs 最新版本）
- 更新提示 UI（对话框显示新版本信息）
- 跳转到 GitHub 下载页面
- 支持手动检查和自动检查
- 双语支持（中文/英文）

**快速导航**:
- 📋 [需求文档](./app-update-notification-feature.md)
- 📊 [任务跟踪](./app-update-notification-task-tracking.md)

**开发进度**: 0% (需求阶段完成，待开发)

---

### 3. 播客转录功能 / Podcast Transcription Feature
| 文档名称 | 文件路径 | 描述 | 状态 |
|---------|---------|------|------|
| 播客音频转录功能需求 | `podcast-audio-transcription-feature.md` | 后端音频转录完整功能需求 | Draft |
| 前端转录文本显示需求 | `podcast-frontend-transcription-display.md` | 前端显示转录文本和Shownotes功能 | Draft |
| 开发计划与任务分配 | `podcast-transcription-development-plan.md` | 详细的开发计划和任务分解 | Draft |
| 验收标准与测试计划 | `podcast-transcription-acceptance-criteria.md` | 完整的测试用例和验收标准 | Draft |

**功能概述**:
- 播客音频自动转录
- AI 生成内容摘要
- 转录文本显示和搜索

**快速导航**:
- 📋 [需求概述](./podcast-audio-transcription-feature.md#需求概述)
- 📊 [开发计划](./podcast-transcription-development-plan.md)

---

## 其他活跃需求 / Other Active Requirements

### 4. 播客功能增强
| 文档名称 | 文件路径 | 描述 | 状态 |
|---------|---------|------|------|
| 播客批量删除功能 | `FEP-20241229-podcast-bulk-delete.md` | 播客订阅批量删除功能 | Completed |
| 播客详情页面优化 | `podcast-detail-page-optimization.md` | 播客详情页面优化 | Active |

### 5. UI/UX 相关
| 文档名称 | 文件路径 | 描述 | 状态 |
|---------|---------|------|------|
| Material 3 UI 重构 | `material-design-3-adaptive-refactor.md` | Material 3 自适应布局重构 | Active |
| Feed 懒加载优化 | `feed-lazy-load-and-navigation-fix-prd.md` | Feed 懒加载和导航修复 | Completed |

### 6. 配置和部署
| 文档名称 | 文件路径 | 描述 | 状态 |
|---------|---------|------|------|
| 服务器配置运行时更新 | `server-config-runtime-update.md` | 服务器配置动态更新 | Active |
| RSS 定时更新配置 | `rss-scheduled-update-configurable-frequency.md` | RSS 定时更新频率配置 | Active |

---

## 按角色快速导航 / Role-Based Quick Navigation

### 📋 产品经理 / Product Manager
- [播客搜索功能 - 需求概述](./podcast-itunes-search-feature.md#需求描述)
- [订阅状态指示器 - 需求概述](./podcast-subscription-status-indicator.md#1-执行摘要--executive-summary)
- [应用更新提醒功能 - 需求概述](./app-update-notification-feature.md#需求描述)
- [播客转录功能 - 功能优先级](./podcast-transcription-development-plan.md#功能优先级矩阵)
- [Material 3 重构 - 业务价值](./material-design-3-adaptive-refactor.md#业务价值)

### 🏛️ 架构师 / Architect
- [应用更新提醒功能 - 技术架构](./app-update-notification-feature.md#技术需求)
- [播客转录功能 - 系统设计](./podcast-transcription-development-plan.md#风险分析)
- [服务器配置 - 架构设计](./server-config-runtime-update.md#架构设计)

### ⚙️ 后端工程师 / Backend Developer
- [播客搜索功能 - API接口设计](./podcast-itunes-search-feature.md#api-接口设计)
- [订阅状态指示器 - 后端需求](./podcast-subscription-status-indicator.md#322-后端需求-backend-requirements)
- [播客转录功能 - API接口](./podcast-audio-transcription-feature.md#api接口)
- [RSS 定时更新 - 任务配置](./rss-scheduled-update-tasks.md#技术实现)
- [播客批量删除 - API 设计](./FEP-20241229-podcast-bulk-delete-api-contract.md)

### 🖥️ 前端工程师 / Frontend Developer
- [播客搜索功能 - UI/UX设计](./podcast-itunes-search-feature.md#uiux-设计要求)
- [订阅状态指示器 - 前端需求](./podcast-subscription-status-indicator.md#321-前端需求-frontend-requirements)
- **[Shownotes HTML渲染 - 前端任务](./podcast-shownotes-html-rendering.md#frontend-tasks--前端任务)**
- [应用更新提醒功能 - 组件结构](./app-update-notification-feature.md#架构设计)
- [Material 3 重构 - UI/UX设计](./material-design-3-adaptive-refactor.md#ui-ux设计要求)
- [播客转录显示 - 实现计划](./podcast-frontend-transcription-display.md#实现计划)

### 📱 移动端工程师 / Mobile Developer
- [Material 3 重构 - 响应式设计](./material-design-3-adaptive-refactor.md#响应式布局)
- [Feed 懒加载 - 性能优化](./feed-lazy-load-and-navigation-fix-prd.md#性能优化)

### 🧪 测试工程师 / Test Engineer
- [应用更新提醒功能 - 测试计划](./app-update-notification-task-tracking.md#testing-tasks)
- [订阅状态指示器 - 测试计划](./podcast-subscription-status-indicator.md#52-验收测试计划--acceptance-testing-plan)
- **[Shownotes HTML渲染 - 测试任务](./podcast-shownotes-html-rendering.md#testing-tasks--测试任务)**
- [播客转录功能 - 测试用例](./podcast-transcription-acceptance-criteria.md#测试用例)
- [播客批量删除 - 验证报告](./FEP-20241229-podcast-bulk-delete-verification-report.md)

### ⚙️ DevOps 工程师 / DevOps Engineer
- [服务器配置 - 运行时更新](./server-config-runtime-update.md#devops-tasks)
- [RSS 定时更新 - Celery 配置](./rss-scheduled-update-tasks.md#celery配置)

---

## 文档更新记录 / Document Update History

| 日期 | 版本 | 更新内容 | 更新人 |
|------|------|---------|--------|
| 2025-01-03 | 3.2 | 添加播客 Shownotes HTML 渲染功能需求 | Product Manager |
| 2026-01-02 | 3.1 | 添加播客订阅状态指示器功能需求 | Product Manager |
| 2025-01-02 | 3.0 | 添加播客搜索功能需求（iTunes Search API集成） | Product Manager |
| 2025-12-30 | 2.0 | 添加应用更新提醒功能需求 | Product Manager |
| 2025-12-21 | 1.0 | 初始版本（播客转录功能） | Product Manager |

---

## 重要说明 / Important Notes

1. **所有需求必须严格遵守产品驱动开发流程**
2. **每个阶段的完成需要相应角色签字确认**
3. **任何需求变更需要更新相应文档并通知所有相关方**
4. **开发过程中需要实时更新任务进度**

---

## 联系方式 / Contact

如有疑问，请联系：
- **产品经理**: 负责需求解释和优先级决策
- **架构师**: 负责技术方案和架构决策
- **各工程师**: 负责具体技术实现

---

**注意**: 本文档是活跃功能需求的入口索引，请根据角色和功能选择查看对应的详细文档。
