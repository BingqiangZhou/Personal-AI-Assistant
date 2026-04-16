# iOS 优化与双平台分化设计

## 概述

对 Stella 播客应用进行全面的 iOS 优化，实现双平台完全分化体验：iOS 使用 Cupertino 原生组件，Android 保持 Material 3 风格。两端共享统一的色彩体系（以 Apple HIG 为基准），仅在组件形态上按平台区分。

### 目标

- 按 Apple HIG 规范全面升级 iOS 体验
- 双平台组件形态分化，色彩统一
- 优化滚动、内存、启动性能
- 集成触觉反馈、分享表、Widget 等平台能力

### 策略

**方案 A：分层替换** — 按层级从下往上替换：核心组件 → 页面级组件 → 完整页面。增量可行，每步可测试。

---

## 第一节：核心架构层

### 四层架构

```
┌─────────────────────────────────────────────┐
│  页面层 (Feature Pages)                      │
│  各 feature 通过 Adaptive 组件渲染 widget 树   │
├─────────────────────────────────────────────┤
│  适配层 (Adaptive Widgets)                   │
│  AdaptiveScaffold, AdaptiveSliverAppBar 等   │
│  内部根据 PlatformHelper.isIOS() 切换实现     │
├─────────────────────────────────────────────┤
│  平台层 (Platform Helper)                    │
│  PlatformHelper + platformValue<T>()         │
├─────────────────────────────────────────────┤
│  基础层 (Theme + Config)                     │
│  AppTheme + CupertinoTheme + AppColors        │
└─────────────────────────────────────────────┘
```

### Adaptive Widget 模式

每个 Adaptive 组件内部根据 `PlatformHelper.isIOS()` 自动切换 Cupertino / Material 实现。页面层只使用 Adaptive 组件，不直接写平台判断代码。

### 新增 Adaptive 组件

| 组件 | 职责 |
|------|------|
| `AdaptiveScaffold` | 页面脚手架，iOS 用 CupertinoPageScaffold，Android 用 Scaffold |
| `AdaptiveSliverAppBar` | 大标题/折叠导航栏 |
| `AdaptiveListSection` | 分组列表容器 |
| `AdaptiveListTile` | 列表项 |
| `AdaptiveSearchBar` | 搜索栏 |
| `AdaptiveSegmentedControl` | 分段控件（iOS SegmentedControl / Android TabBar） |
| `AdaptiveButton` | 按钮（CupertinoButton / ElevatedButton） |
| `AdaptiveTextField` | 输入框（CupertinoTextField / TextField） |

---

## 第二节：视觉/交互体验层

### 统一色彩体系

两端共享同一套 AppColors（已基于 Apple HIG system colors），不分平台颜色分支。

**实施要点：**
- 移除 `AppThemeExtension` 中的 iOS/Android 颜色分支，两端共享同一 color scheme
- 保留 iOS/Android 形态分支：圆角大小、阴影有无、边框样式
- 暗色模式两端统一使用同一套 brightness-based 颜色映射
- 所有颜色通过 `Theme.of(context).colorScheme` 访问，不硬编码

### 组件替换清单

| 当前组件 | iOS 替换 | Android 保持 |
|----------|----------|-------------|
| AppBar + centerTitle | CupertinoNavigationBar | Material AppBar |
| SliverAppBar | CupertinoSliverNavigationBar | Material SliverAppBar |
| ListTile | CupertinoListTile | Material ListTile |
| Card 分组 | CupertinoListSection | Material Card |
| TextField | CupertinoTextField | Material TextField |
| Switch.adaptive() | CupertinoSwitch | Material Switch |
| Slider.adaptive() | CupertinoSlider | Material Slider |
| ElevatedButton | CupertinoButton | Material ElevatedButton |

### 大标题导航栏

iOS 使用 `CupertinoSliverNavigationBar`：
- 展开状态：34px 粗体大标题，左对齐
- 折叠状态：17px 半粗体标题，居中，底部 0.5px 分割线
- 无阴影、无 surface tint
- 搜索栏固定在大标题下方

### 分组列表

iOS 使用 `CupertinoListSection` + `CupertinoListTile`：
- `#F2F2F7` 灰色背景 + 白色圆角卡片（radius: 10）
- 0.5px 分割线（`C6C6C8`）
- 分组标题用 13px 灰色大写字母标签

### 搜索栏

iOS 使用 `CupertinoSearchTextField`：
- 灰色圆角背景（`rgba(118,118,128,0.12)`）
- 10px 圆角
- 嵌入在大标题导航栏下方

---

## 第三节：手势与导航层

### 大标题折叠导航

- `CupertinoSliverNavigationBar` 自动处理大标题 ↔ 小标题过渡
- 支持边缘右滑返回手势（已有）
- 搜索栏可配置为跟随折叠或固定显示

### Tab 导航手势

- 左右滑动切换相邻 Tab（通过 `PageView` 包裹 Tab 内容）
- Tab 切换时触发 light impact 触觉反馈
- 双击当前 Tab 回到顶部并刷新
- 底部导航栏保持当前 `_CleanDock` 样式，iOS 路径使用 `GestureDetector` + 原生色值

### 列表滑动手势

iOS：
- 左滑露出「删除」（红色 `#FF3B30`）和「更多」（蓝色 `#007AFF`）按钮
- 右滑露出「收藏」按钮
- 使用 `CupertinoListTile` 内置的 `leadingToTitle` 间距和 `CupertinoSliverReorderableList`

Android：
- 长按或点击 ⋮ 弹出 PopupMenu
- Material `Dismissible` 滑动删除

### 下拉刷新

- iOS：系统风格 `CupertinoActivityIndicator` 旋转指示器
- Android：Material `RefreshIndicator` 圆形刷新指示器

---

## 第四节：性能优化层

### 滚动性能

1. **图片缓存**：CachedNetworkImage 配置优化，内存缓存上限 100MB，磁盘缓存 200MB，预加载可视区域外 ±2 项缩略图
2. **列表懒加载**：`ListView.builder` + const 构造函数 + 稳定 Key（episodeId/podcastId 而非 index），避免 NestedScrollView 嵌套过深
3. **Widget 重建控制**：使用 `Selector` / `select()` 精确订阅状态，`RepaintEdge` 隔离播放器控件重绘区域
4. **Sliver 优化**：`CupertinoSliverNavigationBar` 替代 SliverAppBar 减少 layer 复杂度，`SliverPersistentHeader` 做粘性分组头

### 内存管理

- **音频缓冲**：单集预加载上限 5MB，后台播放时释放封面大图内存
- **页面生命周期**：页面 dispose 时取消 stream 订阅、释放 controller，`AutomaticKeepAliveClientMixin` 保持 Tab 页状态
- **图片解码**：列表缩略图用 `ResizeImage` 限制解码尺寸（200x200），详情页才加载原图
- **Shading 编译**：iOS 首次运行 Skia shader 编译可能导致 jank，通过 `flutter build` 提前编译或简化动画

### 启动与导航性能

| 指标 | 目标 |
|------|------|
| 冷启动到可交互 | < 2s |
| 页面转场帧率 | 16ms (60fps) |
| 列表滑动 | 0 jank |

**实施手段：** SplashScreen 预加载关键数据 → GoRouter 延迟路由注册 → CupertinoPage transition 避免复杂动画 → Hero animation 仅在必要时使用

---

## 第五节：平台集成层

### 触觉反馈 (AdaptiveHaptic)

通过 `AdaptiveHaptic` 封装，iOS 调用 `HapticFeedback`，Android 使用 View vibrate 或跳过。

| 反馈类型 | 触发场景 |
|----------|----------|
| Light Impact | Tab 切换、列表项点击、分段控件选择 |
| Medium Impact | 点赞/收藏成功、下载完成、刷新完成 |
| Selection Click | Slider 滑动到刻度点、Picker 选择项 |
| Notification Success | 登录成功、订阅/取消订阅操作 |

### 分享表

使用 `share_plus` 包，自动调用平台原生 Share Sheet：
- iOS：UIActivityViewController（圆形图标 + 横向排列）
- Android：Intent Chooser（列表排列）

### 主屏 Widget

使用 `home_widget` 包 + WidgetKit (SwiftUI)，Android 使用 GlanceWidget。

**Widget 类型：**
- Small：正在播放（封面 + 播客名 + 播放按钮）
- Medium：最近更新（2-3 条新单集，含封面和标题）

Flutter 侧通过 `AppWidgetProvider` 同步数据到原生 Widget。

### 集成优先级

| 功能 | 方案 | 优先级 |
|------|------|--------|
| 触觉反馈 | HapticFeedback + AdaptiveHaptic 封装 | P0 |
| 分享 | share_plus 原生 Share Sheet | P0 |
| 推送通知 | flutter_local_notifications + APNs | P1 |
| 主屏 Widget | home_widget + WidgetKit / Glance | P1 |
| Siri 快捷指令 | flutter_siri_suggestion / App Intents | P2 |
| Spotlight 索引 | Core Spotlight Framework via method channel | P2 |

---

## 现有基础设施评估

以下已有的基础设施将直接复用，无需重建：

- `PlatformHelper` — 平台检测和值切换（7 个文件使用）
- `AppTheme` iOS 分支 — 已有 iOS-specific radii、shadows、colors
- `CupertinoTheme` 根包装 — 全局生效
- `adaptivePageTransition` — 所有 GoRouter 路由已使用 CupertinoPage
- `showAdaptiveSheet` / `showAppDialog` / `showAppConfirmationDialog` — 平台感知对话框
- `adaptiveAppBar` — 基础 AppBar 适配
- `TopFloatingNotice` — iOS 反馈通知
- `.adaptive()` 构造函数 — 50+ 处已使用
