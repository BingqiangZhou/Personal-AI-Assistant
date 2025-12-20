import 'package:flutter/material.dart';
import 'material3_menu.dart';

/// Material 3 自适应菜单演示页面
class M3MenuDemoPage extends StatefulWidget {
  const M3MenuDemoPage({super.key});

  @override
  State<M3MenuDemoPage> createState() => _M3MenuDemoPageState();
}

class _M3MenuDemoPageState extends State<M3MenuDemoPage> {
  String _selectedId = 'dashboard';

  // 菜单项定义
  late final List<M3MenuItem> _menuItems;

  @override
  void initState() {
    super.initState();
    _menuItems = [
      M3MenuItem(
        id: 'dashboard',
        icon: Icons.dashboard_outlined,
        selectedIcon: Icons.dashboard,
        label: '仪表板',
        description: '查看概览数据',
        shortcut: 'Ctrl+1',
      ),
      M3MenuItem(
        id: 'knowledge',
        icon: Icons.library_books_outlined,
        selectedIcon: Icons.library_books,
        label: '知识库',
        description: '管理文档和笔记',
        shortcut: 'Ctrl+2',
        badgeCount: 5,
        badgeColor: Colors.blue,
      ),
      M3MenuItem(
        id: 'subscriptions',
        icon: Icons.rss_feed_outlined,
        selectedIcon: Icons.rss_feed,
        label: '订阅源',
        description: 'RSS 和 API 订阅',
        shortcut: 'Ctrl+3',
        badgeCount: 12,
      ),
      M3MenuDivider(),
      M3MenuItem(
        id: 'analytics',
        icon: Icons.analytics_outlined,
        selectedIcon: Icons.analytics,
        label: '分析',
        description: '数据统计和图表',
        shortcut: 'Ctrl+4',
      ),
      M3MenuItem(
        id: 'history',
        icon: Icons.history_outlined,
        selectedIcon: Icons.history,
        label: '历史记录',
        description: '查看操作历史',
        shortcut: 'Ctrl+5',
      ),
      M3MenuDivider(),
      M3MenuItem(
        id: 'settings',
        icon: Icons.settings_outlined,
        selectedIcon: Icons.settings,
        label: '系统设置',
        description: '应用配置',
        shortcut: 'Ctrl+,',
      ),
      M3MenuItem(
        id: 'help',
        icon: Icons.help_outline,
        selectedIcon: Icons.help,
        label: '帮助中心',
        description: '使用指南和文档',
      ),
    ];
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Material 3 自适应菜单演示'),
        actions: [
          IconButton(
            icon: const Icon(Icons.info_outline),
            onPressed: _showInfoDialog,
            tooltip: '使用说明',
          ),
        ],
      ),
      body: Column(
        children: [
          // 演示说明
          _buildDemoHeader(),

          // 演示区域
          Expanded(
            child: _buildDemoArea(),
          ),
        ],
      ),
    );
  }

  Widget _buildDemoHeader() {
    return Container(
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
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  '调整窗口大小查看自适应效果',
                  style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.onPrimaryContainer,
                  ),
                ),
                Text(
                  '小屏幕(<600dp): 底部导航 + 抽屉 | 中等屏幕(600-840dp): 折叠侧边栏 | 大屏幕(≥840dp): 完整侧边栏',
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.onPrimaryContainer.withValues(alpha: 0.8),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDemoArea() {
    return Row(
      children: [
        // 左侧：M3AdaptiveMenu 演示
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
            child: M3AdaptiveMenu(
              config: M3MenuConfig(
                items: _menuItems,
                selectedId: _selectedId,
                onSelected: (id) {
                  setState(() {
                    _selectedId = id;
                  });
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('选择了: $id'),
                      duration: const Duration(seconds: 1),
                    ),
                  );
                },
                title: 'M3 Menu',
                subtitle: 'v2.0.0',
                expandedWidth: 280,
                collapsedWidth: 72,
                showShortcuts: true,
                showUserInfo: true,
                autoAdapt: true,
                floatingActionButton: FloatingActionButton(
                  mini: true,
                  onPressed: () {},
                  child: const Icon(Icons.add),
                ),
              ),
            ),
          ),
        ),

        // 右侧：内容预览
        Expanded(
          flex: 1,
          child: _buildContentPreview(),
        ),
      ],
    );
  }

  Widget _buildContentPreview() {
    final selectedItem = _menuItems.where((item) => item is! M3MenuDivider).firstWhere(
      (item) => item.id == _selectedId,
      orElse: () => _menuItems.first,
    );

    return Container(
      color: Theme.of(context).colorScheme.surface,
      child: Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                selectedItem.selectedIcon ?? selectedItem.icon,
                size: 80,
                color: Theme.of(context).colorScheme.primary,
              ),
              const SizedBox(height: 24),
              Text(
                selectedItem.label,
                style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 8),
              if (selectedItem.description != null)
                Text(
                  selectedItem.description!,
                  style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.7),
                  ),
                ),
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.3),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  'ID: ${selectedItem.id}',
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.onPrimaryContainer,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              const SizedBox(height: 24),
              Text(
                '特性展示：\n'
                '• 响应式布局自适应\n'
                '• Material 3 设计规范\n'
                '• 徽章通知系统\n'
                '• 快捷键支持\n'
                '• 动画过渡效果\n'
                '• 无障碍访问支持',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.8),
                  height: 1.6,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showInfoDialog() {
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: const Text('Material 3 自适应菜单使用说明'),
          content: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                _buildInfoSection('📱 小屏幕 (< 600dp)', '底部导航栏 + 顶部应用栏 + 抽屉菜单'),
                _buildInfoSection('🖥️ 中等屏幕 (600-840dp)', '左侧折叠导航栏（仅图标）+ 完整应用栏'),
                _buildInfoSection('💻 大屏幕 (≥ 840dp)', '左侧完整导航栏（图标 + 标签）+ 应用栏'),
                const SizedBox(height: 16),
                _buildFeatureList(),
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

  Widget _buildFeatureList() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            '核心特性：',
            style: Theme.of(context).textTheme.bodyLarge?.copyWith(
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 8),
          for (final text in [
            '✓ Material 3 设计规范',
            '✓ 响应式断点自适应',
            '✓ 可折叠/展开侧边栏',
            '✓ 图标-only 模式（桌面端）',
            '✓ 徽章通知系统',
            '✓ 模态抽屉（移动端）',
            '✓ 悬浮操作按钮集成',
            '✓ 动画过渡效果',
            '✓ 键盘快捷键支持',
            '✓ 无障碍访问',
          ])
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 2),
              child: Text(
                text,
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ),
        ],
      ),
    );
  }
}

/// 独立使用示例页面
class M3MenuStandalonePage extends StatefulWidget {
  const M3MenuStandalonePage({super.key});

  @override
  State<M3MenuStandalonePage> createState() => _M3MenuStandalonePageState();
}

class _M3MenuStandalonePageState extends State<M3MenuStandalonePage> {
  String _selectedId = 'home';

  late final List<M3MenuItem> _items;

  @override
  void initState() {
    super.initState();
    _items = [
      M3MenuItem(
        id: 'home',
        icon: Icons.home_outlined,
        selectedIcon: Icons.home,
        label: '首页',
        shortcut: 'Ctrl+1',
      ),
      M3MenuItem(
        id: 'explore',
        icon: Icons.explore_outlined,
        selectedIcon: Icons.explore,
        label: '探索',
        shortcut: 'Ctrl+2',
      ),
      M3MenuItem(
        id: 'favorites',
        icon: Icons.favorite_border,
        selectedIcon: Icons.favorite,
        label: '收藏',
        badgeCount: 3,
        shortcut: 'Ctrl+3',
      ),
      M3MenuDivider(),
      M3MenuItem(
        id: 'profile',
        icon: Icons.person_outline,
        selectedIcon: Icons.person,
        label: '个人',
        shortcut: 'Ctrl+4',
      ),
    ];
  }

  @override
  Widget build(BuildContext context) {
    return M3AdaptiveMenu(
      config: M3MenuConfig(
        items: _items,
        selectedId: _selectedId,
        onSelected: (id) {
          setState(() {
            _selectedId = id;
          });
        },
        title: 'Standalone App',
        subtitle: '独立应用示例',
        expandedWidth: 280,
        collapsedWidth: 72,
        showShortcuts: true,
        showUserInfo: true,
        autoAdapt: true,
        floatingActionButton: FloatingActionButton(
          onPressed: () {},
          child: const Icon(Icons.add),
        ),
      ),
    );
  }
}
