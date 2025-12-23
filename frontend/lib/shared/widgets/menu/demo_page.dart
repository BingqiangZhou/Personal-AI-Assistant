import 'package:flutter/material.dart';
import 'adaptive_menu.dart';
import 'adaptive_scaffold_menu.dart';

/// 自适应菜单演示页面
class AdaptiveMenuDemoPage extends StatefulWidget {
  const AdaptiveMenuDemoPage({super.key});

  @override
  State<AdaptiveMenuDemoPage> createState() => _AdaptiveMenuDemoPageState();
}

class _AdaptiveMenuDemoPageState extends State<AdaptiveMenuDemoPage> {
  int _selectedIndex = 0;

  // 菜单项定义
  final List<MenuItem> _menuItems = [
    const MenuItem(
      icon: Icons.chat_outlined,
      selectedIcon: Icons.chat,
      label: 'AI Assistant',
      shortcut: 'Ctrl+1',
    ),
    const MenuItem(
      icon: Icons.library_books_outlined,
      selectedIcon: Icons.library_books,
      label: 'Knowledge Base',
      shortcut: 'Ctrl+2',
    ),
    const MenuItem(
      icon: Icons.rss_feed_outlined,
      selectedIcon: Icons.rss_feed,
      label: 'Subscriptions',
      shortcut: 'Ctrl+3',
      badgeCount: 3,
    ),
    const MenuDivider(),
    const MenuItem(
      icon: Icons.analytics_outlined,
      selectedIcon: Icons.analytics,
      label: 'Analytics',
      shortcut: 'Ctrl+4',
    ),
    const MenuItem(
      icon: Icons.history_outlined,
      selectedIcon: Icons.history,
      label: 'History',
      shortcut: 'Ctrl+5',
    ),
    const MenuDivider(),
    const MenuItem(
      icon: Icons.settings_outlined,
      selectedIcon: Icons.settings,
      label: 'Settings',
      shortcut: 'Ctrl+,',
    ),
  ];

  // NavigationDestination 列表（用于自定义自适应布局）
  final List<NavigationDestination> _destinations = [
    const NavigationDestination(
      icon: Icon(Icons.chat_outlined),
      selectedIcon: Icon(Icons.chat),
      label: 'AI Assistant',
    ),
    const NavigationDestination(
      icon: Icon(Icons.library_books_outlined),
      selectedIcon: Icon(Icons.library_books),
      label: 'Knowledge Base',
    ),
    const NavigationDestination(
      icon: Icon(Icons.rss_feed_outlined),
      selectedIcon: Icon(Icons.rss_feed),
      label: 'Subscriptions',
    ),
    const NavigationDestination(
      icon: Icon(Icons.analytics_outlined),
      selectedIcon: Icon(Icons.analytics),
      label: 'Analytics',
    ),
    const NavigationDestination(
      icon: Icon(Icons.history_outlined),
      selectedIcon: Icon(Icons.history),
      label: 'History',
    ),
    const NavigationDestination(
      icon: Icon(Icons.settings_outlined),
      selectedIcon: Icon(Icons.settings),
      label: 'Settings',
    ),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('自适应菜单演示'),
        actions: [
          IconButton(
            icon: const Icon(Icons.info_outline),
            onPressed: () {
              _showInfoDialog();
            },
            tooltip: '使用说明',
          ),
        ],
      ),
      body: Column(
        children: [
          // 演示说明
          Container(
            padding: const EdgeInsets.all(16),
            color: Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.2),
            child: Row(
              children: [
                Icon(
                  Icons.touch_app,
                  color: Theme.of(context).colorScheme.primary,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    '调整窗口大小查看自适应效果：小屏幕显示底部导航，中等屏幕显示折叠菜单，大屏幕显示完整菜单',
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: Theme.of(context).colorScheme.onPrimaryContainer,
                        ),
                  ),
                ),
              ],
            ),
          ),

          // 演示区域
          Expanded(
            child: Row(
              children: [
                // 左侧：自定义自适应菜单
                Expanded(
                  flex: 1,
                  child: Container(
                    decoration: BoxDecoration(
                      border: Border(
                        right: BorderSide(
                          color: Theme.of(context).dividerColor.withValues(alpha: 0.3),
                        ),
                      ),
                    ),
                    child: AdaptiveMenu(
                      config: AdaptiveMenuConfig(
                        items: _menuItems,
                        selectedIndex: _selectedIndex,
                        onSelected: (index) {
                          setState(() {
                            _selectedIndex = index;
                          });
                        },
                        title: 'Custom Menu',
                        subtitle: '自定义组件',
                        expandedWidth: 280,
                        collapsedWidth: 72,
                        showShortcuts: true,
                      ),
                    ),
                  ),
                ),

                // 右侧：自定义 AdaptiveScaffoldMenu 实现
                Expanded(
                  flex: 1,
                  child: AdaptiveScaffoldMenu(
                    body: _buildContent(),
                    destinations: _destinations,
                    selectedIndex: _selectedIndex,
                    onDestinationSelected: (index) {
                      setState(() {
                        _selectedIndex = index;
                      });
                    },
                    title: 'Adaptive Scaffold',
                    subtitle: '自定义组件',
                    floatingActionButton: FloatingActionButton(
                      onPressed: () {},
                      child: const Icon(Icons.add),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  /// 构建内容区域
  Widget _buildContent() {
    final selectedItem = _menuItems.where((item) => item is! MenuDivider).toList()[_selectedIndex];

    return Container(
      color: Theme.of(context).colorScheme.surface,
      child: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              selectedItem.selectedIcon ?? selectedItem.icon,
              size: 64,
              color: Theme.of(context).colorScheme.primary,
            ),
            const SizedBox(height: 16),
            Text(
              selectedItem.label,
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
            ),
            const SizedBox(height: 8),
            Text(
              '当前选中: $_selectedIndex',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.7),
                  ),
            ),
            const SizedBox(height: 24),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 32),
              child: Text(
                '这是一个演示页面，展示了两种不同的自适应菜单实现方式。\n\n'
                '左侧使用自定义组件，右侧使用自定义 AdaptiveScaffoldMenu。\n\n'
                '两者都支持响应式布局，根据屏幕大小自动调整显示方式。',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.8),
                    ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// 显示信息对话框
  void _showInfoDialog() {
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('自适应菜单使用说明'),
          content: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                _buildInfoSection(
                  '📱 小屏幕 (< 600dp)',
                  '底部导航栏，仅显示图标和标签',
                ),
                _buildInfoSection(
                  '🖥️ 中等屏幕 (600-840dp)',
                  '左侧折叠导航栏，仅显示图标',
                ),
                _buildInfoSection(
                  '💻 大屏幕 (840-1200dp)',
                  '左侧导航栏，显示图标和简短标签',
                ),
                _buildInfoSection(
                  '🖥️ 超大屏幕 (>= 1200dp)',
                  '左侧完整导航栏，显示图标、标签和快捷键',
                ),
                const SizedBox(height: 16),
                Text(
                  '功能特性：\n'
                  '• Material 3 设计规范\n'
                  '• 支持动画过渡\n'
                  '• 徽章通知显示\n'
                  '• 用户菜单集成\n'
                  '• 快捷键提示\n'
                  '• 暗色模式支持',
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('关闭'),
            ),
          ],
        );
      },
    );
  }

  Widget _buildInfoSection(String title, String description) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: const TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: 14,
            ),
          ),
          Text(
            description,
            style: TextStyle(
              fontSize: 13,
              color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.7),
            ),
          ),
        ],
      ),
    );
  }
}

/// 独立使用自定义自适应菜单的示例页面
class CustomAdaptiveMenuPage extends StatefulWidget {
  const CustomAdaptiveMenuPage({super.key});

  @override
  State<CustomAdaptiveMenuPage> createState() => _CustomAdaptiveMenuPageState();
}

class _CustomAdaptiveMenuPageState extends State<CustomAdaptiveMenuPage> {
  int _selectedIndex = 0;

  final List<MenuItem> _menuItems = [
    const MenuItem(
      icon: Icons.dashboard_outlined,
      selectedIcon: Icons.dashboard,
      label: '仪表板',
      shortcut: 'Ctrl+1',
    ),
    const MenuItem(
      icon: Icons.people_outline,
      selectedIcon: Icons.people,
      label: '用户管理',
      shortcut: 'Ctrl+2',
    ),
    const MenuItem(
      icon: Icons.bar_chart_outlined,
      selectedIcon: Icons.bar_chart,
      label: '数据分析',
      shortcut: 'Ctrl+3',
      badgeCount: 5,
    ),
    const MenuDivider(),
    const MenuItem(
      icon: Icons.settings_outlined,
      selectedIcon: Icons.settings,
      label: '系统设置',
      shortcut: 'Ctrl+,',
    ),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(
        children: [
          // 自适应菜单
          AdaptiveMenu(
            config: AdaptiveMenuConfig(
              items: _menuItems,
              selectedIndex: _selectedIndex,
              onSelected: (index) {
                setState(() {
                  _selectedIndex = index;
                });
              },
              title: 'MyApp',
              subtitle: 'v1.0.0',
              expandedWidth: 280,
              collapsedWidth: 72,
              showShortcuts: true,
              showUserInfo: true,
            ),
          ),

          // 主体内容
          Expanded(
            child: Container(
              color: Theme.of(context).colorScheme.surface,
              child: Center(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(
                      _menuItems.where((item) => item is! MenuDivider).toList()[_selectedIndex].selectedIcon,
                      size: 80,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                    const SizedBox(height: 24),
                    Text(
                      _menuItems.where((item) => item is! MenuDivider).toList()[_selectedIndex].label,
                      style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                            fontWeight: FontWeight.bold,
                          ),
                    ),
                    const SizedBox(height: 16),
                    Text(
                      '使用自定义 AdaptiveMenu 组件',
                      style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                            color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.7),
                          ),
                    ),
                    const SizedBox(height: 32),
                    ElevatedButton.icon(
                      onPressed: () {
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                            content: Text('这是一个独立的自适应菜单页面示例'),
                            duration: Duration(seconds: 2),
                          ),
                        );
                      },
                      icon: const Icon(Icons.info_outline),
                      label: const Text('显示提示'),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// 独立使用自定义 AdaptiveScaffoldMenu 的示例页面
class ScaffoldAdaptiveMenuPage extends StatefulWidget {
  const ScaffoldAdaptiveMenuPage({super.key});

  @override
  State<ScaffoldAdaptiveMenuPage> createState() => _ScaffoldAdaptiveMenuPageState();
}

class _ScaffoldAdaptiveMenuPageState extends State<ScaffoldAdaptiveMenuPage> {
  int _selectedIndex = 0;

  final List<NavigationDestination> _destinations = [
    const NavigationDestination(
      icon: Icon(Icons.home_outlined),
      selectedIcon: Icon(Icons.home),
      label: '首页',
    ),
    const NavigationDestination(
      icon: Icon(Icons.explore_outlined),
      selectedIcon: Icon(Icons.explore),
      label: '探索',
    ),
    const NavigationDestination(
      icon: Icon(Icons.favorite_border),
      selectedIcon: Icon(Icons.favorite),
      label: '收藏',
    ),
    const NavigationDestination(
      icon: Icon(Icons.person_outline),
      selectedIcon: Icon(Icons.person),
      label: '我的',
    ),
  ];

  @override
  Widget build(BuildContext context) {
    return AdaptiveScaffoldMenu(
      body: Container(
        color: Theme.of(context).colorScheme.surface,
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                Icons.circle,
                size: 80,
                color: Theme.of(context).colorScheme.primary,
              ),
              const SizedBox(height: 24),
              Text(
                _destinations[_selectedIndex].label,
                style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
              ),
              const SizedBox(height: 16),
              Text(
                '使用 AdaptiveScaffoldMenu 组件',
                style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                      color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.7),
                    ),
              ),
              const SizedBox(height: 32),
              ElevatedButton.icon(
                onPressed: () {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text('这是一个使用自定义 AdaptiveScaffoldMenu 的页面示例'),
                      duration: Duration(seconds: 2),
                    ),
                  );
                },
                icon: const Icon(Icons.info_outline),
                label: const Text('显示提示'),
              ),
            ],
          ),
        ),
      ),
      destinations: _destinations,
      selectedIndex: _selectedIndex,
      onDestinationSelected: (index) {
        setState(() {
          _selectedIndex = index;
        });
      },
      title: 'Adaptive App',
      subtitle: '自适应应用',
      floatingActionButton: FloatingActionButton(
        onPressed: () {},
        child: const Icon(Icons.add),
      ),
    );
  }
}
