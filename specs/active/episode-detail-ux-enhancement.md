# Episode Detail Page UX Enhancement / 播客详情页用户体验优化

## Basic Information / 基本信息
- **Requirement ID**: REQ-20260110-001
- **Created Date**: 2026-01-10
- **Last Updated**: 2026-01-10
- **Owner**: Frontend Developer
- **Status**: Active
- **Priority**: High

## Requirement Description / 需求描述

### User Story / 用户故事
**Chinese**: 作为播客听众，我希望能够方便地复制播客 shownotes 内容，并且在滚动查看内容时顶部导航栏自动吸顶，以便更好地阅读和操作。

**English**: As a podcast listener, I want to easily copy the shownotes content and have a sticky navigation bar when scrolling, so I can better read and interact with the content.

### Business Value / 业务价值
- 提升用户体验，方便用户复制和分享播客信息
- 优化内容阅读体验，增加用户停留时间
- 减少用户在长内容浏览时的操作负担

### Background / 背景信息
- 当前 shownotes 内容不支持复制功能
- 顶部播客信息区固定显示，占据了大量屏幕空间
- 用户在滚动查看长内容时需要返回顶部才能切换标签页

## Functional Requirements / 功能需求

### Core Features / 核心功能
- [FR-001] Shownotes content copy support / Shownotes内容复制支持
- [FR-002] Sticky tab bar when scrolling / 滚动时标签栏吸顶效果

### Feature Details / 功能详述

#### Feature 1: Shownotes Copy Support / Shownotes复制支持
- **Description / 描述**: 添加复制按钮到 shownotes 区域，支持一键复制所有内容
- **Input / 输入**: 用户点击复制按钮
- **Processing / 处理**:
  - 提取纯文本内容（去除HTML标签）
  - 调用系统剪贴板API
  - 显示复制成功提示
- **Output / 输出**: 内容复制到剪贴板 + SnackBar 提示

#### Feature 2: Sticky Tab Bar / 标签栏吸顶效果
- **Description / 描述**: 当用户向下滚动内容时，顶部播客信息区域收起，只保留标签按钮栏吸顶
- **Input / 输入**: 用户滚动内容
- **Processing / 处理**:
  - 使用 ScrollController 监听滚动位置
  - 当滚动超过阈值时，顶部播客信息区域淡出/收起
  - 标签按钮栏保持固定在顶部
- **Output / 输出**: 视觉上的吸顶效果，只显示标签栏

## Non-Functional Requirements / 非功能需求

### Performance Requirements / 性能要求
- 滚动响应时间 < 16ms (60fps)
- 复制操作响应时间 < 100ms

### UI/UX Requirements / 界面体验要求
- 符合 Material 3 设计规范
- 平滑的动画过渡效果
- 支持桌面和移动端自适应

## Task Breakdown / 任务分解

### Frontend Tasks / 前端任务
- [ ] [TASK-F-001] Implement shownotes copy functionality
  - **Owner**: Frontend Developer
  - **Acceptance Criteria / 验收标准**:
    - [ ] Copy button added to shownotes header
    - [ ] Clipboard API integration working
    - [ ] Success/failure feedback with SnackBar
    - [ ] HTML to plain text conversion
  - **Status**: Todo

- [ ] [TASK-F-002] Implement sticky tab bar animation
  - **Owner**: Frontend Developer
  - **Acceptance Criteria / 验收标准**:
    - [ ] ScrollController setup for content area
    - [ ] Header fades out when scrolling down
    - [ ] Tab bar sticks to top when scrolling
    - [ ] Smooth animation transitions
  - **Status**: Todo

### Test Tasks / 测试任务
- [ ] [TASK-T-001] Widget tests for new features
  - **Owner**: Test Engineer
  - **Acceptance Criteria / 验收标准**:
    - [ ] Copy button tap test
    - [ ] Scroll behavior test
    - [ ] Animation behavior test
  - **Status**: Todo

## Acceptance Criteria / 验收标准

### Overall Acceptance / 整体验收
- [ ] Shownotes 内容可以一键复制
- [ ] 滚动时顶部信息区域自动收起
- [ ] 标签栏保持在顶部可见
- [ ] 动画效果流畅自然
- [ ] Material 3 设计规范符合

### User Acceptance Criteria / 用户验收标准
- [ ] 用户可以点击复制按钮复制 shownotes
- [ ] 用户滚动时看到顶部信息收起
- [ ] 用户可以随时切换标签页
- [ ] 复制成功有明确提示

### Technical Acceptance Criteria / 技术验收标准
- [ ] Widget 测试通过
- [ ] 无内存泄漏
- [ ] 60fps 滚动性能
- [ ] 剪贴板权限正确处理

## Design Constraints / 设计约束

### Technical Constraints / 技术约束
- 使用 Flutter 框架
- Material 3 设计规范
- 需要处理剪贴板权限（移动端）

### UI/UX Constraints / 界面约束
- 保持与现有设计风格一致
- 支持双语（中文/英文）
- 响应式布局（桌面/移动端）

## Dependencies / 依赖关系

### Internal Dependencies / 内部依赖
- `podcast_episode_detail_page.dart` - 需要修改
- `shownotes_display_widget.dart` - 需要添加复制功能

### External Dependencies / 外部依赖
- `flutter/services.dart` - Clipboard API
- 现有的 Material 3 组件

## Implementation Plan / 实施计划

### Phase 1: Shownotes Copy / 第一阶段：复制功能
1. 添加复制按钮到 `ShownotesDisplayWidget`
2. 实现 HTML 转纯文本逻辑
3. 集成剪贴板 API
4. 添加成功/失败提示

### Phase 2: Sticky Tab Bar / 第二阶段：吸顶效果
1. 设置 ScrollController
2. 实现滚动监听逻辑
3. 添加头部淡出动画
4. 确保标签栏固定在顶部

### Phase 3: Testing / 第三阶段：测试
1. 编写 Widget 测试
2. 手动测试不同场景
3. 性能测试和优化

## Related Documents / 相关文档
- Existing: `specs/active/podcast-episode-detail-page.md`
- Code: `frontend/lib/features/podcast/presentation/pages/podcast_episode_detail_page.dart`

---

**Note / 注意**: This is a UI/UX enhancement focused on improving user experience when viewing podcast episode details.
