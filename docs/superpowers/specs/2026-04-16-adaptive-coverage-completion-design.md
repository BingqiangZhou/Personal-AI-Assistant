# Adaptive 组件覆盖率补齐设计

## 概述

在已完成 iOS 优化 8 个 Adaptive 组件的基础上，补齐所有遗漏页面的 Adaptive 组件替换，确保全部功能页面都具备双平台分化体验。同时新增 `AdaptiveScaffold` 组件，完成页面骨架层的平台适配。

### 目标

- 所有功能页面使用 Adaptive 组件，无遗漏的原始 Material 组件
- 新增 `AdaptiveScaffold`，完成页面骨架层分化
- 延续逐文件替换策略，增量安全

### 策略

**方案 A：逐文件替换** — 按现有模式，逐个文件将原始 Material 组件替换为已有的 Adaptive 组件 + 新增 `AdaptiveScaffold`。每个文件可独立测试和提交。

---

## 第一节：新增 AdaptiveScaffold

### 组件规格

创建 `frontend/lib/core/widgets/adaptive/adaptive_scaffold.dart`。

**API 设计：**

```dart
class AdaptiveScaffold extends StatelessWidget {
  const AdaptiveScaffold({
    super.key,
    this.navigationBar,
    this.child,
    this.backgroundColor,
    this.resizeToAvoidBottomInset,
  });

  final Widget? navigationBar;
  final Widget? child;
  final Color? backgroundColor;
  final bool? resizeToAvoidBottomInset;
}
```

**实现逻辑：**

- **iOS 路径**：使用 `CupertinoPageScaffold`，背景色默认 `CupertinoColors.systemBackground`
- **Android 路径**：使用标准 `Scaffold`，背景色默认 `theme.scaffoldBackgroundColor`
- **navigationBar**：iOS 传入 `CupertinoNavigationBar` 或 null（大标题场景由 `CupertinoSliverNavigationBar` 处理），Android 传入 `AppBar` 或 null
- **resizeToAvoidBottomInset**：两端语义相同，透传即可

### 设计约束

- `AdaptiveScaffold` 只负责页面骨架和底部导航区域
- 大标题导航栏通过已有的 `CupertinoSliverNavigationBar`（在 `CustomScrollView` 内部）处理，不属于 `AdaptiveScaffold` 的职责
- 不暴露 `appBar` 参数，因为 `CupertinoPageScaffold` 的 `navigationBar` 和 `Scaffold` 的 `appBar` 语义不同

### 页面迁移清单

以下页面将 `Scaffold` 替换为 `AdaptiveScaffold`：

1. **`PodcastFeedPage`** — 最主要的播客发现列表页
2. **`PodcastEpisodesPage`** — 单集列表页
3. **`ProfilePage`** — 个人主页
4. **`AppearancePage`** — 设置外观页
5. **`LoginPage`** — 登录页
6. **`RegisterPage`** — 注册页

**不迁移：**
- `HomeShellWidget` — 已使用 `CustomAdaptiveNavigation` 作为容器
- 使用 `ContentShell` / `ProfileShell` 的页面 — 这些 Shell 内部已做平台适配

---

## 第二节：播客功能组件替换清单

### 9.1 transcript_display_widget.dart

| 当前组件 | 替换为 | 说明 |
|----------|--------|------|
| `SegmentedButton` (1处) | `AdaptiveSegmentedControl` | 语言/格式切换控件 |

### 9.2 transcript_result_widget.dart

| 当前组件 | 替换为 | 说明 |
|----------|--------|------|
| `ElevatedButton` (2处) | `AdaptiveButton(style: AdaptiveButtonStyle.filled)` | 操作按钮 |

### 9.3 ai_summary_control_widget.dart

| 当前组件 | 替换为 | 说明 |
|----------|--------|------|
| `ElevatedButton` (1处) | `AdaptiveButton(style: AdaptiveButtonStyle.filled)` | AI 摘要触发按钮 |

### 9.4 transcription_status_widget.dart

| 当前组件 | 替换为 | 说明 |
|----------|--------|------|
| `ElevatedButton` (1处) | `AdaptiveButton(style: AdaptiveButtonStyle.filled)` | 转录操作按钮 |

### 9.5 add_podcast_dialog.dart

| 当前组件 | 替换为 | 说明 |
|----------|--------|------|
| `TextFormField` (1处) | `AdaptiveTextField` | URL 输入框 |
| `ElevatedButton` (1处) | `AdaptiveButton(style: AdaptiveButtonStyle.filled)` | 添加按钮 |

### 9.6 playback_speed_selector_sheet.dart

| 当前组件 | 替换为 | 说明 |
|----------|--------|------|
| `CheckboxListTile` (1处) | 平台适配的选项行 | iOS 使用 checkmark 样式行，Android 保持 CheckboxListTile |

对于 `CheckboxListTile`，由于没有 `AdaptiveCheckboxListTile` 组件，在此文件中直接使用 `PlatformHelper.isIOS()` 条件判断：
- iOS：使用 `CupertinoListTile` + `CupertinoCheckBox`（或自定义 checkmark 图标）
- Android：保持 `CheckboxListTile`

### 9.7 sleep_timer_selector_sheet.dart

| 当前组件 | 替换为 | 说明 |
|----------|--------|------|
| `ListTile` (2处) | `AdaptiveListTile` | 定时器选项行 |

### 9.8 chat_sessions_drawer.dart

| 当前组件 | 替换为 | 说明 |
|----------|--------|------|
| `ListTile` (1处) | `AdaptiveListTile` | 聊天会话列表项 |

### 9.9 podcast_episodes_page_view.dart

| 当前组件 | 替换为 | 说明 |
|----------|--------|------|
| `ElevatedButton` (1处) | `AdaptiveButton(style: AdaptiveButtonStyle.filled)` | 错误状态重试按钮 |

**注意：** 此文件中的 `FilterChip`、`PopupMenuButton`、`CheckboxListTile` 已有平台分支处理（iOS 使用 CupertinoActionSheet 等原生组件，Android 使用 Material 组件），不需要替换。

---

## 第三节：Profile 功能组件替换清单

### 10.1 profile_page.dart

| 当前组件 | 替换为 | 说明 |
|----------|--------|------|
| `TextFormField` (3处) | `AdaptiveTextField` | 密码修改对话框中的旧密码、新密码、确认密码输入框 |

**注意：** 此文件中的 `ListTile`（Android 路径）和 `PopupMenuButton`（Android 路径）是设计上就是 Android 特定的，不需要替换。

---

## 第四节：不替换的组件

以下组件保持现状，不进行 Adaptive 替换：

| 组件 | 出现位置 | 原因 |
|------|----------|------|
| `RefreshIndicator` | 6+ 处（podcast_feed_page, podcast_list_page, podcast_queue_sheet, profile_subscriptions_page, profile_cache_management_page, profile_history_page） | Flutter 的 `RefreshIndicator.adaptive()` 已处理双平台差异，无需额外封装 |
| `FilterChip` | podcast_episodes_page_view (Android 路径) | Android 特定组件，iOS 路径已使用 pill-shaped 按钮 |
| `PopupMenuButton` | podcast_episodes_page_view (Android 路径), profile_page (Android 路径) | Android 特定组件，iOS 路径已使用 CupertinoActionSheet |
| `CheckboxListTile` | podcast_episodes_page_view (Android 路径) | Android 特定组件，iOS 路径已使用 CupertinoSwitch |

---

## 现有基础设施复用

以下已有组件直接复用：

- `AdaptiveButton` — 3 种样式（filled/text/outlined），支持 loading 状态
- `AdaptiveTextField` — iOS CupertinoTextField / Android Material TextField
- `AdaptiveListTile` — iOS CupertinoListTile / Android Material ListTile
- `AdaptiveSegmentedControl` — iOS CupertinoSlidingSegmentedControl / Android SegmentedButton
- `PlatformHelper` — 平台检测和值切换
- `AppTheme` iOS/Android 主题分支 — 已有 iOS-specific radii、shadows
