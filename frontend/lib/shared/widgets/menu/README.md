# Material 3 自适应菜单组件库

## 概述

本组件库提供了一套完整的 Material 3 自适应菜单解决方案，支持从移动端到桌面端的全平台响应式布局。

## 核心特性

### 🎨 Material 3 设计规范
- 完全遵循 Material 3 设计语言
- 支持 Material 3 颜色方案和主题
- 动态颜色和主题适应

### 📱 响应式布局
- **小屏幕 (< 600dp)**: 底部导航 + 顶部应用栏 + 抽屉菜单
- **中等屏幕 (600-840dp)**: 左侧折叠导航栏（仅图标）+ 完整应用栏
- **大屏幕 (≥ 840dp)**: 左侧完整导航栏（图标 + 标签）

### 🚀 高级功能
- ✅ 可折叠/展开侧边栏
- ✅ 图标-only 模式（桌面端收起）
- ✅ 徽章通知系统
- ✅ 模态抽屉（移动端）
- ✅ 悬浮操作按钮集成
- ✅ 动画过渡效果
- ✅ 键盘快捷键支持
- ✅ 无障碍访问

## 组件对比

| 特性 | AdaptiveMenu | AdaptiveScaffoldMenu | M3AdaptiveMenu |
|------|--------------|---------------------|----------------|
| Material 3 规范 | ✅ | ✅ | ✅✅✅ |
| 响应式自适应 | 手动 | 自动 | 自动 |
| 移动端抽屉 | ❌ | ✅ | ✅ |
| 折叠/展开 | ✅ | ❌ | ✅ |
| 图标-only 模式 | ✅ | ✅ | ✅ |
| 徽章通知 | ✅ | ❌ | ✅ |
| 快捷键支持 | ✅ | ❌ | ✅ |
| 用户菜单 | ✅ | ✅ | ✅ |
| 自定义构建器 | ❌ | ❌ | ✅ |
| 动画效果 | ✅ | ✅ | ✅✅ |

## 快速开始

### 1. 基础使用（推荐）

```dart
import 'package:flutter/material.dart';
import 'package:personal_ai_assistant/shared/widgets/menu/menu.dart';

class MyPage extends StatefulWidget {
  @override
  State<MyPage> createState() => _MyPageState();
}

class _MyPageState extends State<MyPage> {
  String _selectedId = 'dashboard';

  @override
  Widget build(BuildContext context) {
    return M3AdaptiveMenu(
      config: M3MenuConfig(
        items: [
          M3MenuItem(
            id: 'dashboard',
            icon: Icons.dashboard_outlined,
            selectedIcon: Icons.dashboard,
            label: '仪表板',
            shortcut: 'Ctrl+1',
          ),
          M3MenuItem(
            id: 'analytics',
            icon: Icons.analytics_outlined,
            selectedIcon: Icons.analytics,
            label: '分析',
            badgeCount: 3,
          ),
          M3MenuDivider(),
          M3MenuItem(
            id: 'settings',
            icon: Icons.settings_outlined,
            selectedIcon: Icons.settings,
            label: '设置',
            shortcut: 'Ctrl+,',
          ),
        ],
        selectedId: _selectedId,
        onSelected: (id) {
          setState(() {
            _selectedId = id;
          });
          // 处理导航逻辑
        },
        title: 'My App',
        subtitle: 'v1.0.0',
        expandedWidth: 280,
        collapsedWidth: 72,
        showShortcuts: true,
        showUserInfo: true,
        autoAdapt: true, // 自动根据屏幕大小调整
      ),
    );
  }
}
```

### 2. 独立使用（全屏应用）

```dart
class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: M3AdaptiveMenu(
        config: M3MenuConfig(
          items: _menuItems,
          onSelected: (id) => print('Selected: $id'),
          title: 'My App',
          subtitle: 'v1.0.0',
          floatingActionButton: FloatingActionButton(
            onPressed: () {},
            child: Icon(Icons.add),
          ),
        ),
      ),
    );
  }
}
```

### 3. 与内容区域结合

```dart
class MainScreen extends StatefulWidget {
  @override
  State<MainScreen> createState() => _MainScreenState();
}

class _MainScreenState extends State<MainScreen> {
  String _selectedId = 'home';

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(
        children: [
          // 侧边栏
          Expanded(
            flex: 0,
            child: M3AdaptiveMenu(
              config: M3MenuConfig(
                items: _menuItems,
                selectedId: _selectedId,
                onSelected: (id) => setState(() => _selectedId = id),
                autoAdapt: false, // 手动控制
              ),
            ),
          ),

          // 内容区域
          Expanded(
            child: _buildContent(_selectedId),
          ),
        ],
      ),
    );
  }

  Widget _buildContent(String id) {
    // 根据选中的菜单项显示不同内容
    switch (id) {
      case 'dashboard':
        return DashboardPage();
      case 'analytics':
        return AnalyticsPage();
      case 'settings':
        return SettingsPage();
      default:
        return Center(child: Text('Unknown page'));
    }
  }
}
```

## 配置选项

### M3MenuConfig

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `items` | `List<M3MenuItem>` | 必填 | 菜单项列表 |
| `onSelected` | `ValueChanged<String>` | 必填 | 选中回调 |
| `selectedId` | `String?` | `null` | 当前选中的ID |
| `expandedWidth` | `double` | `280` | 展开时宽度 |
| `collapsedWidth` | `double` | `72` | 折叠时宽度 |
| `showUserInfo` | `bool` | `true` | 显示用户信息 |
| `showShortcuts` | `bool` | `true` | 显示快捷键 |
| `animated` | `bool` | `true` | 启用动画 |
| `title` | `String?` | `null` | 菜单标题 |
| `subtitle` | `String?` | `null` | 菜单副标题 |
| `autoAdapt` | `bool` | `true` | 自动响应式 |
| `useDrawerOnMobile` | `bool` | `true` | 移动端抽屉 |
| `keyboardShortcuts` | `bool` | `true` | 键盘快捷键 |
| `floatingActionButton` | `Widget?` | `null` | 悬浮按钮 |
| `userMenuBuilder` | `WidgetBuilder?` | `null` | 自定义用户菜单 |
| `headerBuilder` | `WidgetBuilder?` | `null` | 自定义头部 |
| `bottomBuilder` | `WidgetBuilder?` | `null` | 自定义底部 |

### M3MenuItem

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `id` | `String` | 必填 | 唯一标识符 |
| `icon` | `IconData` | 必填 | 图标 |
| `label` | `String` | 必填 | 标签 |
| `selectedIcon` | `IconData?` | `null` | 选中图标 |
| `description` | `String?` | `null` | 描述 |
| `shortcut` | `String?` | `null` | 快捷键 |
| `badgeCount` | `int?` | `null` | 徽章数量 |
| `badgeColor` | `Color?` | `null` | 徽章颜色 |
| `enabled` | `bool` | `true` | 是否启用 |
| `visible` | `bool` | `true` | 是否可见 |
| `children` | `List<M3MenuItem>?` | `null` | 子菜单 |

## 高级用法

### 1. 自定义构建器

```dart
M3AdaptiveMenu(
  config: M3MenuConfig(
    items: _items,
    onSelected: (id) {},
    // 自定义头部
    headerBuilder: (context) {
      return Container(
        padding: EdgeInsets.all(20),
        child: Column(
          children: [
            CircleAvatar(
              radius: 24,
              child: Icon(Icons.rocket_launch),
            ),
            SizedBox(height: 8),
            Text('Custom Header'),
          ],
        ),
      );
    },
    // 自定义用户菜单
    userMenuBuilder: (context) {
      return PopupMenuButton<String>(
        child: CircleAvatar(child: Icon(Icons.person)),
        itemBuilder: (context) => [
          PopupMenuItem(value: 'profile', child: Text('Profile')),
          PopupMenuItem(value: 'logout', child: Text('Logout')),
        ],
      );
    },
  ),
)
```

### 2. 键盘快捷键

```dart
M3AdaptiveMenu(
  config: M3MenuConfig(
    items: [
      M3MenuItem(
        id: 'dashboard',
        icon: Icons.dashboard,
        label: '仪表板',
        shortcut: 'Ctrl+1', // 自动绑定
      ),
    ],
    keyboardShortcuts: true,
    onSelected: (id) {
      // 处理选中
    },
  ),
)
```

### 3. 徽章通知

```dart
M3MenuItem(
  id: 'notifications',
  icon: Icons.notifications_outlined,
  selectedIcon: Icons.notifications,
  label: '通知',
  badgeCount: 99, // 显示数字
  badgeColor: Colors.red, // 自定义颜色
),
```

### 4. 响应式控制

```dart
// 自动响应式（推荐）
M3AdaptiveMenu(
  config: M3MenuConfig(
    autoAdapt: true, // 自动根据屏幕大小调整
    // ...
  ),
)

// 手动控制
LayoutBuilder(
  builder: (context, constraints) {
    final isMobile = constraints.maxWidth < 600;
    return M3AdaptiveMenu(
      config: M3MenuConfig(
        autoAdapt: false,
        expandedWidth: isMobile ? 0 : 280,
        // ...
      ),
    );
  },
)
```

## 演示页面

组件库提供了完整的演示页面：

### 1. M3MenuDemoPage
完整的功能演示，展示所有特性。

```dart
Navigator.push(
  context,
  MaterialPageRoute(
    builder: (context) => M3MenuDemoPage(),
  ),
);
```

### 2. M3MenuStandalonePage
独立使用示例。

### 3. M3AdaptiveScaffoldPage
与 flutter_adaptive_scaffold 集成示例。

## 最佳实践

### 1. 状态管理
建议使用 Riverpod 或其他状态管理工具：

```dart
final menuProvider = StateNotifierProvider<MenuNotifier, String>((ref) {
  return MenuNotifier();
});

class MenuNotifier extends StateNotifier<String> {
  MenuNotifier() : super('dashboard');

  void select(String id) => state = id;
}

// 使用
Consumer(
  builder: (context, ref, child) {
    final selectedId = ref.watch(menuProvider);
    return M3AdaptiveMenu(
      config: M3MenuConfig(
        items: _items,
        selectedId: selectedId,
        onSelected: (id) => ref.read(menuProvider.notifier).select(id),
      ),
    );
  },
)
```

### 2. 导航集成
与 GoRouter 集成：

```dart
final router = GoRouter(
  routes: [
    GoRoute(
      path: '/dashboard',
      builder: (context, state) => DashboardPage(),
    ),
  ],
);

M3AdaptiveMenu(
  config: M3MenuConfig(
    items: _items,
    onSelected: (id) {
      switch(id) {
        case 'dashboard':
          context.go('/dashboard');
          break;
        case 'settings':
          context.go('/settings');
          break;
      }
    },
  ),
)
```

### 3. 性能优化
对于大量菜单项，使用懒加载：

```dart
M3AdaptiveMenu(
  config: M3MenuConfig(
    items: _items,
    onSelected: (id) {
      // 只在需要时加载内容
      _loadContent(id);
    },
  ),
)
```

## 无障碍访问

组件内置无障碍支持：
- ✅ 语义化标签
- ✅ 键盘导航
- ✅ 屏幕阅读器支持
- ✅ 焦点管理

```dart
M3MenuItem(
  id: 'dashboard',
  icon: Icons.dashboard,
  label: '仪表板',
  description: '查看应用概览数据', // 用于屏幕阅读器
),
```

## 主题定制

### 自定义颜色

```dart
MaterialApp(
  theme: ThemeData(
    useMaterial3: true,
    colorScheme: ColorScheme.fromSeed(
      seedColor: Colors.blue,
      brightness: Brightness.light,
    ),
  ),
  darkTheme: ThemeData(
    useMaterial3: true,
    colorScheme: ColorScheme.fromSeed(
      seedColor: Colors.blue,
      brightness: Brightness.dark,
    ),
  ),
  home: M3AdaptiveMenu(
    config: M3MenuConfig(
      // ...
    ),
  ),
)
```

### 自定义样式

```dart
M3AdaptiveMenu(
  config: M3MenuConfig(
    expandedWidth: 320, // 更宽的侧边栏
    collapsedWidth: 64, // 更窄的折叠状态
    showShortcuts: false, // 隐藏快捷键
    showUserInfo: false, // 隐藏用户信息
  ),
)
```

## 常见问题

### Q: 如何在移动端隐藏侧边栏？
A: 使用 `autoAdapt: true`，组件会自动在小屏幕上显示抽屉。

### Q: 如何自定义菜单项的外观？
A: 使用 `M3MenuItem` 的 `description`、`badgeColor` 等属性，或自定义构建器。

### Q: 如何添加子菜单？
A: 使用 `M3MenuItem` 的 `children` 属性（当前版本暂不支持嵌套显示，将在未来版本添加）。

### Q: 如何与现有导航系统集成？
A: 在 `onSelected` 回调中处理导航逻辑，或使用状态管理工具。

## 版本历史

### v2.0.0 (当前)
- ✅ 新增 M3AdaptiveMenu 组件
- ✅ 增强响应式支持
- ✅ 添加模态抽屉
- ✅ 改进动画效果
- ✅ 优化无障碍访问

### v1.0.0
- ✅ 基础自适应菜单
- ✅ AdaptiveScaffoldMenu
- ✅ 演示页面

## 贡献

欢迎提交 Issue 和 PR！

## 许可证

MIT License
