# Product Requirements Document (PRD)
# 产品需求文档 (PRD)

## Feature: Speed Ruler Control / 倍速播放控件

**Document ID**: PRD-2025-001
**Status**: Completed / 已完成
**Priority**: High / 高优先级
**Created**: 2025-01-06
**Completed**: 2025-01-06
**Owner**: Product Manager

---

## 📝 Overview / 概述

### English
A reusable Flutter UI component for playback speed selection with a ruler-style interface. The component provides an intuitive, visual way to select playback speeds between 0.5x and 3.0x with smooth drag gestures, automatic snapping, and haptic feedback.

### 中文
一个可复用的 Flutter UI 组件，用于播放速度选择，采用刻度尺式界面。该组件提供直观的视觉方式来选择 0.5x 到 3.0x 之间的播放速度，支持流畅的拖拽手势、自动吸附和触感反馈。

---

## 🎯 User Stories / 用户故事

### US-001: As a user, I want to visually select playback speed
**作为用户，我希望能够通过可视化方式选择播放速度**

- I want to see a ruler-style interface showing all available speeds
- 我希望看到刻度尺式界面显示所有可用速度
- I want to drag along the ruler to adjust speed smoothly
- 我希望沿着刻度尺拖拽以平滑调整速度
- I want to tap on a specific speed to jump directly to it
- 我希望点击特定速度直接跳转

### US-002: As a user, I want clear visual feedback
**作为用户，我希望获得清晰的视觉反馈**

- I want to see the current speed highlighted in the center
- 我希望看到当前速度在中心高亮显示
- I want the component to adapt to dark/light theme automatically
- 我希望组件自动适应深色/浅色主题
- I want haptic feedback when changing speeds
- 我希望在更改速度时获得触感反馈

### US-003: As a developer, I want a reusable component
**作为开发者，我希望建立一个可复用的组件**

- I want to easily integrate the speed selector into audio/video players
- 我希望轻松将速度选择器集成到音频/视频播放器中
- I want to customize the range and step values
- 我希望自定义范围和步长值
- I want consistent Material 3 design
- 我希望保持一致的 Material 3 设计

---

## ✅ Acceptance Criteria / 验收标准

### AC-001: Visual Design / 视觉设计
- [ ] Panel has large rounded corners (28-32px radius)
- [ ] 面板具有大圆角（28-32px 半径）
- [ ] Title "倍速播放" in top-left using theme's titleLarge/headlineSmall
- [ ] 左上角标题"倍速播放"使用主题的 titleLarge/headlineSmall
- [ ] Current speed value in top-right using theme's primary color
- [ ] 右上角当前速度值使用主题的 primary 颜色
- [ ] Ruler shows range 0.5x to 3.0x with 0.1x steps
- [ ] 刻度尺显示 0.5x 到 3.0x 范围，步长 0.1x
- [ ] Major ticks at 0.5x intervals (higher and bolder)
- [ ] 主要刻度每 0.5x 间隔（更高更粗）
- [ ] Minor ticks at 0.1x intervals (shorter and lighter)
- [ ] 次要刻度每 0.1x 间隔（更短更浅）
- [ ] Center indicator line using theme's primary color
- [ ] 中心指示线使用主题的 primary 颜色
- [ ] All colors derived from Theme/ColorScheme (no hardcoded colors)
- [ ] 所有颜色派生自 Theme/ColorScheme（无硬编码颜色）

### AC-002: Interaction / 交互
- [ ] Drag gesture updates speed in real-time
- [ ] 拖拽手势实时更新速度
- [ ] Release automatically snaps to nearest 0.1x
- [ ] 释放时自动吸附到最近的 0.1x
- [ ] Tap on any tick jumps directly to that speed
- [ ] 点击任何刻度直接跳转到该速度
- [ ] Haptic feedback triggers on each 0.1x change
- [ ] 每 0.1x 变化触发触感反馈
- [ ] Smooth inertia scrolling (optional but recommended)
- [ ] 平滑的惯性滚动（可选但推荐）
- [ ] Boundary enforcement: cannot go below 0.5x or above 3.0x
- [ ] 边界强制：不能低于 0.5x 或高于 3.0x

### AC-003: Component API / 组件 API
- [ ] `SpeedRuler` widget is reusable and configurable
- [ ] `SpeedRuler` widget 可复用且可配置
- [ ] Parameters: `min`, `max`, `step`, `majorStep`, `value`, `onChanged`
- [ ] 参数：`min`, `max`, `step`, `majorStep`, `value`, `onChanged`
- [ ] `SpeedRulerSheet` wrapper for bottom sheet display
- [ ] `SpeedRulerSheet` 包装器用于底部弹窗显示
- [ ] Demo page shows usage example
- [ ] Demo 页面显示使用示例
- [ ] Visual alignment: indicator line, speed text, and tick positions match perfectly
- [ ] 视觉对齐：指示线、速度文本和刻度位置完美匹配

### AC-004: Performance / 性能
- [ ] Dragging is smooth with no lag (60fps)
- [ ] 拖拽流畅无延迟（60fps）
- [ ] CustomPainter approach preferred for performance
- [ ] 优先使用 CustomPainter 方法以获得更好性能
- [ ] No visual artifacts during interactions
- [ ] 交互期间无视觉伪影

### AC-005: Code Quality / 代码质量
- [ ] Clear code structure with reusable components
- [ ] 代码结构清晰，组件可复用
- [ ] Comments on key calculations (dx->value, snap logic, tick layout)
- [ ] 关键计算处有注释（dx->value、吸附逻辑、刻度布局）
- [ ] Follows Material 3 design guidelines
- [ ] 遵循 Material 3 设计指南
- [ ] Widget tests for component functionality
- [ ] 组件功能的 widget 测试

---

## 🎨 Design Specifications / 设计规格

### Visual Specifications / 视觉规格

**Panel Layout / 面板布局:**
```
┌────────────────────────────────────┐
│ 倍速播放              1.5x          │  ← Header
├────────────────────────────────────┤
│                                    │
│   0.5   1.0   1.5   2.0   2.5   3.0│  ← Major ticks with labels
│    |     |     |     |     |     | │
│    |     |     |     |     |     | │
│  | | | | | | | | | | | | | | | | |│  ← Minor ticks
│    |     |     |     |     |     | │
│          ║                           │  ← Center indicator
│         1.5x                         │  ← Selected value
│                                    │
└────────────────────────────────────┘
```

**Dimensions / 尺寸:**
- Panel corner radius: 28-32px
- 面板圆角半径：28-32px
- Padding: horizontal 24px, vertical 18px
- 内边距：水平 24px，垂直 18px
- Major tick height: ~24px
- 主要刻度高度：~24px
- Minor tick height: ~12px
- 次要刻度高度：~12px
- Indicator line width: 3-4px
- 指示线宽度：3-4px

**Colors (from Theme) / 颜色（派生自主题）:**
- Panel background: `Theme.of(context).colorScheme.surface`
- 面板背景：`Theme.of(context).colorScheme.surface`
- Title: `Theme.of(context).textTheme.titleLarge`
- 标题：`Theme.of(context).textTheme.titleLarge`
- Current speed (top-right): `Theme.of(context).colorScheme.primary`
- 当前速度（右上角）：`Theme.of(context).colorScheme.primary`
- Indicator line: `Theme.of(context).colorScheme.primary`
- 指示线：`Theme.of(context).colorScheme.primary`
- Major tick: `Theme.of(context).colorScheme.onSurfaceVariant`
- 主要刻度：`Theme.of(context).colorScheme.onSurfaceVariant`
- Minor tick: `Theme.of(context).colorScheme.outline.withOpacity(0.5)`
- 次要刻度：`Theme.of(context).colorScheme.outline.withOpacity(0.5)`
- Unselected label: `Theme.of(context).colorScheme.onSurfaceVariant`
- 未选中标签：`Theme.of(context).colorScheme.onSurfaceVariant`

### Interaction Specifications / 交互规格

**Gesture Handling / 手势处理:**
1. **Horizontal Drag / 横向拖拽**
   - Track pointer movement delta
   - 跟踪指针移动增量
   - Convert dx to value change
   - 将 dx 转换为值变化
   - Update in real-time
   - 实时更新

2. **Snap to Grid / 吸附到网格**
   - On drag end: `snap(value) = round(value / 0.1) * 0.1`
   - 拖拽结束时：`snap(value) = round(value / 0.1) * 0.1`
   - Animate to snapped position
   - 动画到吸附位置

3. **Haptic Feedback / 触感反馈**
   - Trigger `HapticFeedback.selectionClick` on each 0.1x threshold crossed
   - 每跨越 0.1x 阈值触发 `HapticFeedback.selectionClick`

4. **Tap to Select / 点击选择**
   - Calculate nearest tick from tap position
   - 从点击位置计算最近的刻度
   - Snap and animate to that tick
   - 吸附并动画到该刻度

---

## 🔧 Technical Requirements / 技术要求

### Component Architecture / 组件架构

```
lib/features/podcast/shared/widgets/
├── speed_ruler/
│   ├── speed_ruler.dart              # Main ruler widget
│   ├── speed_ruler_sheet.dart        # Bottom sheet wrapper
│   ├── speed_ruler_painter.dart      # Custom painter for drawing
│   └── speed_ruler_demo_page.dart    # Demo page
```

### Implementation Approach / 实现方式

**Recommended: CustomPainter Approach / 推荐：CustomPainter 方法**

Advantages / 优势:
- Better performance for custom drawing
- 自定义绘制的性能更好
- Precise control over visual elements
- 对视觉元素的精确控制
- Smooth 60fps rendering
- 流畅的 60fps 渲染

Alternative: ListView Approach / 备选：ListView 方法
- Easier to implement for simple cases
- 简单情况下更容易实现
- May have alignment precision issues
- 可能存在对齐精度问题

### Key Components / 关键组件

**1. SpeedRuler Widget / SpeedRuler 组件**
```dart
class SpeedRuler extends StatefulWidget {
  final double min;           // Default: 0.5
  final double max;           // Default: 3.0
  final double step;          // Default: 0.1
  final double majorStep;     // Default: 0.5
  final double value;
  final ValueChanged<double>? onChanged;

  // Visual customization parameters
  // 视觉自定义参数
  final double tickWidth;
  final double majorTickHeight;
  final double minorTickHeight;
  final double indicatorWidth;
}
```

**2. SpeedRulerSheet Widget / SpeedRulerSheet 组件**
```dart
class SpeedRulerSheet extends StatelessWidget {
  final String title;         // Default: "倍速播放"
  final double initialValue;  // Default: 1.5
  final ValueChanged<double>? onSpeedChanged;
}
```

**3. Demo Page / Demo 页面**
```dart
class SpeedRulerDemoPage extends StatelessWidget {
  // Show button to open speed ruler sheet
  // Display selected speed result
}
```

---

## 🧪 Testing Requirements / 测试要求

### Widget Tests / Widget 测试

**Required Test Scenarios / 必需测试场景:**

1. **Rendering / 渲染**
   - [ ] Component renders without errors
   - [ ] 组件渲染无错误
   - [ ] All ticks are visible
   - [ ] 所有刻度可见
   - [ ] Indicator line is centered
   - [ ] 指示线居中

2. **Initial State / 初始状态**
   - [ ] Default value 1.5x is selected
   - [ ] 默认值 1.5x 被选中
   - [ ] Top-right displays correct value
   - [ ] 右上角显示正确值
   - [ ] Center indicator aligns with 1.5 tick
   - [ ] 中心指示线与 1.5 刻度对齐

3. **Drag Interaction / 拖拽交互**
   - [ ] Dragging updates value in real-time
   - [ ] 拖拽实时更新值
   - [ ] Dragging left decreases speed
   - [ ] 向左拖拽降低速度
   - [ ] Dragging right increases speed
   - [ ] 向右拖拽增加速度
   - [ ] Release snaps to nearest 0.1x
   - [ ] 释放时吸附到最近的 0.1x

4. **Boundary Handling / 边界处理**
   - [ ] Cannot go below 0.5x
   - [ ] 不能低于 0.5x
   - [ ] Cannot go above 3.0x
   - [ ] 不能高于 3.0x
   - [ ] Boundary values are selectable
   - [ ] 边界值可选

5. **Theme Adaptation / 主题适配**
   - [ ] Colors change with theme
   - [ ] 颜色随主题变化
   - [ ] No hardcoded colors visible
   - [ ] 无可见的硬编码颜色

---

## 📊 Success Metrics / 成功指标

1. **Usability / 可用性**
   - Average time to select speed: < 3 seconds
   - 选择速度的平均时间：< 3 秒
   - User satisfaction score: > 4/5
   - 用户满意度评分：> 4/5

2. **Performance / 性能**
   - 60fps during drag interactions
   - 拖拽交互期间 60fps
   - < 16ms frame time
   - < 16ms 帧时间

3. **Code Quality / 代码质量**
   - 100% test coverage for core logic
   - 核心逻辑 100% 测试覆盖率
   - No lint warnings
   - 无 lint 警告

---

## 🚀 Implementation Plan / 实施计划

### Phase 1: Core Component (Priority: High / 第一阶段：核心组件 优先级：高)
- Create `SpeedRuler` widget with CustomPainter
- 创建具有 CustomPainter 的 `SpeedRuler` widget
- Implement tick drawing and layout
- 实现刻度绘制和布局
- Add drag gesture handling
- 添加拖拽手势处理
- Implement snap logic
- 实现吸附逻辑

### Phase 2: Wrapper & UI (Priority: High / 第二阶段：包装器和 UI 优先级：高)
- Create `SpeedRulerSheet` bottom sheet wrapper
- 创建 `SpeedRulerSheet` 底部弹窗包装器
- Add header with title and current value
- 添加带标题和当前值的头部
- Implement haptic feedback
- 实现触感反馈
- Add theme adaptation
- 添加主题适配

### Phase 3: Demo & Testing (Priority: Medium / 第三阶段：演示和测试 优先级：中)
- Create demo page
- 创建演示页面
- Write widget tests
- 编写 widget 测试
- Add tap gesture support
- 添加点击手势支持
- Polish animations
- 优化动画

---

## 📝 Notes / 备注

### Integration Points / 集成点
- This component will be integrated into the existing audio player
- 该组件将集成到现有音频播放器中
- Location: `lib/features/podcast/shared/widgets/`
- 位置：`lib/features/podcast/shared/widgets/`
- Will be used in podcast episode playback
- 将在播客剧集播放中使用

### Dependencies / 依赖
- Flutter SDK (Material 3)
- `flutter/services.dart` (for HapticFeedback)
- 无外部包依赖

### Risks & Mitigations / 风险和缓解措施
- **Risk**: CustomPainter performance on low-end devices
- **风险**：低端设备上的 CustomPainter 性能
  **Mitigation**: Optimize painting, cache where possible
  **缓解**：优化绘制，尽可能缓存
- **Risk**: Precision issues with tick alignment
- **风险**：刻度对齐的精度问题
  **Mitigation**: Use precise double calculations, test on multiple values
  **缓解**：使用精确的 double 计算，测试多个值

---

## 📋 Checklist / 检查清单

### Before Development / 开发前
- [x] Requirements analyzed and documented
- [x] 需求已分析并记录
- [ ] Design mockups reviewed (if available)
- [ ] 设计模型已审查（如果有）
- [ ] Technical approach confirmed
- [ ] 技术方法已确认

### During Development / 开发中
- [ ] Component implementation started
- [ ] 组件实施已开始
- [ ] Code follows project conventions
- [ ] 代码遵循项目约定
- [ ] Tests written alongside code
- [ ] 测试与代码一起编写

### Before Completion / 完成前
- [ ] All acceptance criteria met
- [ ] 所有验收标准已满足
- [ ] Widget tests passing
- [ ] Widget 测试通过
- [ ] Code reviewed
- [ ] 代码已审查
- [ ] Documentation updated
- [ ] 文档已更新

---

**Document Status**: Ready for Development / 准备开发
**Next Action**: Assign to Frontend Developer / 下一步：分配给前端开发者
