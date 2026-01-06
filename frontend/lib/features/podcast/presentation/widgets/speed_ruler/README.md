# SpeedRuler Widget / 倍速播放控件

一个可复用的 Flutter 倍速选择控件，采用刻度尺样式设计。

## 功能特性 / Features

- ✅ 刻度尺样式设计（0.5x - 3.0x）
- ✅ 横向拖拽选择倍速
- ✅ 点击刻度直接跳转
- ✅ 自动吸附到 0.1x 步长
- ✅ 触感反馈（HapticFeedback）
- ✅ 边界强制（0.5x - 3.0x）
- ✅ Material 3 主题适配
- ✅ 深色/浅色模式自适应

## 快速开始 / Quick Start

### 基本使用 / Basic Usage

```dart
import 'package:flutter/material.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/speed_ruler/speed_ruler_sheet.dart';

// 显示倍速选择底部弹窗
await SpeedRulerSheet.show(
  context: context,
  initialValue: 1.5,
  onSpeedChanged: (speed) {
    print('Selected speed: $speed');
  },
);
```

### 自定义参数 / Customization

```dart
SpeedRuler(
  min: 0.5,
  max: 3.0,
  step: 0.1,
  majorStep: 0.5,
  value: _currentSpeed,
  onChanged: (value) {
    setState(() {
      _currentSpeed = value;
    });
  },
  // 可选：自定义视觉参数
  tickWidth: 2.0,
  majorTickHeight: 24.0,
  minorTickHeight: 12.0,
  indicatorWidth: 4.0,
)
```

## API 参考 / API Reference

### SpeedRuler / 刻度尺组件

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `min` | double | 0.5 | 最小倍速 |
| `max` | double | 3.0 | 最大倍速 |
| `step` | double | 0.1 | 步长 |
| `majorStep` | double | 0.5 | 主要刻度间隔 |
| `value` | double | - | 当前值 |
| `onChanged` | ValueChanged<double>? | - | 值变化回调 |
| `tickWidth` | double | 2.0 | 刻度宽度 |
| `majorTickHeight` | double | 24.0 | 主要刻度高度 |
| `minorTickHeight` | double | 12.0 | 次要刻度高度 |
| `indicatorWidth` | double | 4.0 | 指示线宽度 |

### SpeedRulerSheet / 底部弹窗

```dart
SpeedRulerSheet.show(
  context: context,
  title: '倍速播放',           // 弹窗标题
  initialValue: 1.5,           // 初始值
  min: 0.5,                    // 最小值
  max: 3.0,                    // 最大值
  step: 0.1,                   // 步长
  majorStep: 0.5,              // 主要刻度间隔
  onSpeedChanged: (speed) {    // 实时变化回调
    print('Speed: $speed');
  },
)
```

## 文件结构 / File Structure

```
lib/features/podcast/presentation/widgets/speed_ruler/
├── speed_ruler_component.dart   # 核心组件（CustomPainter + 手势处理）
├── speed_ruler_sheet.dart        # 底部弹窗包装器
├── speed_ruler_demo_page.dart    # 演示页面
└── speed_ruler_widgets.dart      # 导出文件
```

## 测试 / Tests

运行测试：

```bash
flutter test test/widget/features/podcast/widgets/speed_ruler/
```

测试覆盖：
- ✅ 渲染测试
- ✅ 交互测试（拖拽、点击）
- ✅ 边界测试
- ✅ 主题适配测试
- ✅ 自定义参数测试

## 验收标准 / Acceptance Criteria

- ✅ 视觉对齐：指示线、倍速文本、刻度位置完全一致
- ✅ 吸附准确：永远是 0.1 的整数倍
- ✅ 边界处理：不能小于 0.5、不能大于 3.0
- ✅ 主题适配：所有颜色派生自 Theme，无硬编码
- ✅ 拖拽流畅：60fps，支持触感反馈
- ✅ 所有测试通过：18/18

## 示例 / Demo

查看演示页面：

```dart
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/speed_ruler/speed_ruler_demo_page.dart';

// 导航到演示页面
Navigator.push(
  context,
  MaterialPageRoute(
    builder: (context) => const SpeedRulerDemoPage(),
  ),
);
```

## 技术实现 / Technical Implementation

- **CustomPainter**: 用于绘制刻度尺和指示线
- **GestureDetector**: 处理拖拽和点击手势
- **AnimationController**: 实现平滑的吸附动画
- **HapticFeedback**: 提供触感反馈
- **Material 3**: 所有颜色和样式派生自 Theme

## 集成到音频播放器 / Integration with Audio Player

```dart
// 在音频播放器页面中使用
void _showSpeedSelector() async {
  final selectedSpeed = await SpeedRulerSheet.show(
    context: context,
    initialValue: _audioPlayer.speed,
    onSpeedChanged: (speed) {
      // 实时更新播放速度
      _audioPlayer.setSpeed(speed);
    },
  );

  if (selectedSpeed != null) {
    // 确认最终速度
    _audioPlayer.setSpeed(selectedSpeed);
    setState(() {
      _currentSpeed = selectedSpeed;
    });
  }
}
```

## 注意事项 / Notes

1. 所有颜色均从 Theme 派生，自动适配深色/浅色模式
2. 触感反馈仅在支持的设备上有效
3. 拖拽结束时自动吸附到最近的 0.1x
4. 边界值会被强制限制在 min 和 max 范围内
