# Task Board / 任务看板

**Last Updated**: 2025-01-06
**Current Feature**: Speed Ruler Control (倍速播放控件)

---

## 📋 Active Tasks / 活跃任务

### Feature: Speed Ruler Control / 倍速播放控件

**Status**: 🔵 In Development / 开发中
**Priority**: High / 高优先级
**Assigned To**: Frontend Developer (前端开发者)

---

## 📝 Task Breakdown / 任务分解

### Phase 1: Core SpeedRuler Component / 第一阶段：核心 SpeedRuler 组件

**Assigned To**: Frontend Developer
**Status**: ⏳ Pending / 待处理
**Estimated Complexity**: Medium-High / 中-高

#### Tasks / 任务:

- [ ] **Task 1.1**: Create file structure
  - [ ] Create `lib/features/podcast/shared/widgets/speed_ruler/` directory
  - [ ] 创建 `lib/features/podcast/shared/widgets/speed_ruler/` 目录
  - [ ] Create placeholder files: `speed_ruler.dart`, `speed_ruler_painter.dart`, `speed_ruler_sheet.dart`
  - [ ] 创建占位文件

- [ ] **Task 1.2**: Implement `SpeedRulerPainter` (CustomPainter)
  - [ ] Draw major ticks (0.5, 1.0, 1.5, 2.0, 2.5, 3.0) with labels
  - [ ] 绘制主要刻度（0.5, 1.0, 1.5, 2.0, 2.5, 3.0）及标签
  - [ ] Draw minor ticks (0.1 intervals)
  - [ ] 绘制次要刻度（0.1 间隔）
  - [ ] Draw center indicator line
  - [ ] 绘制中心指示线
  - [ ] Use Theme colors (no hardcoded colors)
  - [ ] 使用主题颜色（无硬编码颜色）
  - [ ] Add comments for key calculations
  - [ ] 为关键计算添加注释

- [ ] **Task 1.3**: Implement `SpeedRuler` widget (StatefulWidget)
  - [ ] Define parameters: min, max, step, majorStep, value, onChanged
  - [ ] 定义参数：min, max, step, majorStep, value, onChanged
  - [ ] Implement horizontal drag gesture handling
  - [ ] 实现横向拖拽手势处理
  - [ ] Implement snap-to-grid logic (round to nearest 0.1)
  - [ ] 实现吸附到网格逻辑（四舍五入到最近的 0.1）
  - [ ] Implement boundary enforcement (0.5x - 3.0x)
  - [ ] 实现边界强制（0.5x - 3.0x）
  - [ ] Implement haptic feedback (HapticFeedback.selectionClick)
  - [ ] 实现触感反馈（HapticFeedback.selectionClick）
  - [ ] Implement tap-to-select gesture
  - [ ] 实现点击选择手势

### Phase 2: SpeedRulerSheet Wrapper / 第二阶段：SpeedRulerSheet 包装器

**Assigned To**: Frontend Developer
**Status**: ⏳ Pending / 待处理
**Estimated Complexity**: Medium / 中

#### Tasks / 任务:

- [ ] **Task 2.1**: Create `SpeedRulerSheet` widget
  - [ ] Wrap SpeedRuler in a bottom sheet / dialog
  - [ ] 将 SpeedRuler 包装在底部弹窗/对话框中
  - [ ] Add header with title "倍速播放" (top-left)
  - [ ] 添加标题"倍速播放"的头部（左上角）
  - [ ] Add current speed value display (top-right)
  - [ ] 添加当前速度值显示（右上角）
  - [ ] Apply Material 3 panel styling (large rounded corners, surface color)
  - [ ] 应用 Material 3 面板样式（大圆角，表面颜色）

- [ ] **Task 2.2**: Implement value synchronization
  - [ ] Sync top-right value with selected value
  - [ ] 同步右上角值与选中值
  - [ ] Sync center indicator value with selected value
  - [ ] 同步中心指示线值与选中值
  - [ ] Add fade/scale animation on value change (optional)
  - [ ] 在值变化时添加淡入/缩放动画（可选）

### Phase 3: Demo Page & Testing / 第三阶段：演示页面和测试

**Assigned To**: Frontend Developer + Test Engineer
**Status**: ⏳ Pending / 待处理
**Estimated Complexity**: Medium / 中

#### Tasks / 任务:

- [ ] **Task 3.1**: Create demo page (Frontend Developer)
  - [ ] Create `speed_ruler_demo_page.dart`
  - [ ] 创建 `speed_ruler_demo_page.dart`
  - [ ] Add button to open SpeedRulerSheet
  - [ ] 添加打开 SpeedRulerSheet 的按钮
  - [ ] Display selected speed result
  - [ ] 显示选定的速度结果
  - [ ] Add navigation to demo page in app
  - [ ] 在应用中添加到演示页面的导航

- [ ] **Task 3.2**: Write widget tests (Frontend Developer)
  - [ ] Create `test/widget/features/podcast/speed_ruler_test.dart`
  - [ ] 创建测试文件
  - [ ] Test: Component renders without errors
  - [ ] 测试：组件渲染无错误
  - [ ] Test: Initial value 1.5x is selected
  - [ ] 测试：初始值 1.5x 被选中
  - [ ] Test: Dragging updates value
  - [ ] 测试：拖拽更新值
  - [ ] Test: Release snaps to nearest 0.1x
  - [ ] 测试：释放时吸附到最近的 0.1x
  - [ ] Test: Boundary handling (0.5x min, 3.0x max)
  - [ ] 测试：边界处理（0.5x 最小值，3.0x 最大值）
  - [ ] Test: Tap gesture selects value
  - [ ] 测试：点击手势选择值

- [ ] **Task 3.3**: Manual testing & verification (Test Engineer)
  - [ ] Test in light theme
  - [ ] 在浅色主题中测试
  - [ ] Test in dark theme
  - [ ] 在深色主题中测试
  - [ ] Verify smooth dragging (60fps)
  - [ ] 验证流畅拖拽（60fps）
  - [ ] Verify haptic feedback works
  - [ ] 验证触感反馈有效
  - [ ] Verify visual alignment accuracy
  - [ ] 验证视觉对齐准确性
  - [ ] Test on different screen sizes
  - [ ] 在不同屏幕尺寸上测试

---

## 🔄 Task Status / 任务状态

### Legend / 图例:
- ⏳ **Pending** / 待处理 - Not started
- 🔵 **In Progress** / 进行中 - Currently being worked on
- 🟢 **Review** / 审查中 - Waiting for review
- ✅ **Complete** / 已完成 - Finished and verified
- ❌ **Blocked** / 阻塞 - Cannot proceed

### Current Status Summary / 当前状态摘要:

| Phase | Status | Assigned To | Start Date | Target Completion |
|-------|--------|-------------|------------|-------------------|
| Phase 1: Core Component | ⏳ Pending | Frontend Developer | - | - |
| Phase 2: Sheet Wrapper | ⏳ Pending | Frontend Developer | - | - |
| Phase 3: Demo & Tests | ⏳ Pending | Frontend + Test Engineer | - | - |

---

## 📊 Progress Metrics / 进度指标

- **Overall Progress**: 0% (0/9 tasks complete)
- **整体进度**：0%（0/9 任务完成）
- **Tasks Completed**: 0/9
- **已完成任务**：0/9
- **Tasks In Progress**: 0/9
- **进行中任务**：0/9
- **Tasks Pending**: 9/9
- **待处理任务**：9/9

---

## 🚧 Blockers / 阻塞因素

None / 无

---

## 📝 Notes / 备注

### Implementation Guidelines / 实施指南:

1. **Material 3 Compliance**:
   - Use `Theme.of(context)` for all colors and styles
   - Ensure `useMaterial3: true` in ThemeData
   - Follow Material 3 design tokens

2. **Performance**:
   - Use CustomPainter for optimal performance
   - Avoid unnecessary rebuilds
   - Test on low-end devices

3. **Code Quality**:
   - Add comments for key calculations (dx->value, snap logic)
   - Follow project naming conventions
   - Write tests alongside implementation

4. **Verification**:
   - Must test in both light and dark themes
   - Must verify on multiple screen sizes
   - Must ensure 60fps during drag

---

## 🔗 Related Documents / 相关文档

- **PRD**: `specs/active/speed-ruler-control.md`
- **Location**: `lib/features/podcast/shared/widgets/speed_ruler/`
- **Tests**: `test/widget/features/podcast/speed_ruler_test.dart`

---

**Last Updated By**: Product Manager
**Next Review**: After Phase 1 completion
