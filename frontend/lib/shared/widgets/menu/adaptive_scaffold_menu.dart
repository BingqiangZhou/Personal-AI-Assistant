import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../../core/constants/breakpoints.dart';
import 'adaptive_menu.dart';

/// 使用 flutter_adaptive_scaffold 的自适应菜单布局
class AdaptiveScaffoldMenu extends StatefulWidget {
  final Widget body;
  final List<NavigationDestination> destinations;
  final int selectedIndex;
  final ValueChanged<int>? onDestinationSelected;
  final Widget? floatingActionButton;
  final PreferredSizeWidget? appBar;
  final String? title;
  final String? subtitle;
  final bool showShortcuts;

  const AdaptiveScaffoldMenu({
    super.key,
    required this.body,
    required this.destinations,
    required this.selectedIndex,
    this.onDestinationSelected,
    this.floatingActionButton,
    this.appBar,
    this.title,
    this.subtitle,
    this.showShortcuts = true,
  });

  @override
  State<AdaptiveScaffoldMenu> createState() => _AdaptiveScaffoldMenuState();
}

class _AdaptiveScaffoldMenuState extends State<AdaptiveScaffoldMenu> {
  // 响应式断点配置（使用 flutter_adaptive_scaffold 内置断点）

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final screenWidth = constraints.maxWidth;
        
        // 小屏幕 (<600dp) - 使用底部导航栏
        if (screenWidth < Breakpoints.medium) {
          return Scaffold(
            appBar: widget.appBar ?? _buildAppBar(),
            body: _buildBodyWithAppBar(),
            floatingActionButton: widget.floatingActionButton,
            bottomNavigationBar: _buildBottomNavigation(),
          );
        }
        
        // 中等屏幕 (600-840dp) - 折叠的 NavigationRail（仅图标）
        else if (screenWidth < Breakpoints.mediumLarge) {
          return Scaffold(
            appBar: widget.appBar ?? _buildAppBar(),
            body: Row(
              children: [
                _buildNavigationRail(
                  extended: false,
                  showLabels: false,
                ),
                const VerticalDivider(thickness: 1, width: 1),
                Expanded(child: _buildBodyWithAppBar()),
              ],
            ),
            floatingActionButton: widget.floatingActionButton,
          );
        }
        
        // 大屏幕 (840-1200dp) - 折叠的 NavigationRail（图标 + 简短标签）
        else if (screenWidth < Breakpoints.large) {
          return Scaffold(
            appBar: widget.appBar ?? _buildAppBar(),
            body: Row(
              children: [
                _buildNavigationRail(
                  extended: false,
                  showLabels: true,
                ),
                const VerticalDivider(thickness: 1, width: 1),
                Expanded(child: _buildBodyWithAppBar()),
              ],
            ),
            floatingActionButton: widget.floatingActionButton,
          );
        }
        
        // 超大屏幕 (>=1200dp) - 完全展开的 NavigationRail
        else {
          return Scaffold(
            appBar: widget.appBar ?? _buildAppBar(),
            body: Row(
              children: [
                _buildNavigationRail(
                  extended: true,
                  showLabels: true,
                ),
                const VerticalDivider(thickness: 1, width: 1),
                Expanded(child: _buildBodyWithAppBar()),
              ],
            ),
            floatingActionButton: widget.floatingActionButton,
          );
        }
      },
    );
  }

  /// 构建 NavigationRail
  Widget _buildNavigationRail({
    required bool extended,
    required bool showLabels,
  }) {
    return Container(
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border(
          right: BorderSide(
            color: Theme.of(context).dividerColor.withValues(alpha: 0.2),
            width: 1,
          ),
        ),
      ),
      child: Column(
        children: [
          // 头部
          _buildNavHeader(extended),

          // 导航项
          Expanded(
            child: NavigationRail(
              extended: extended,
              selectedIndex: widget.selectedIndex,
              onDestinationSelected: widget.onDestinationSelected,
              backgroundColor: Colors.transparent,
              leading: const SizedBox.shrink(),
              trailing: Expanded(
                child: Align(
                  alignment: Alignment.bottomCenter,
                  child: _buildUserMenu(extended),
                ),
              ),
              destinations: widget.destinations.map((destination) {
                return NavigationRailDestination(
                  icon: destination.icon,
                  selectedIcon: destination.selectedIcon,
                  label: showLabels ? Text(destination.label) : const SizedBox.shrink(),
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                );
              }).toList(),
              labelType: showLabels && !extended
                  ? NavigationRailLabelType.selected
                  : (showLabels ? NavigationRailLabelType.all : NavigationRailLabelType.none),
              selectedIconTheme: IconThemeData(
                color: Theme.of(context).colorScheme.primary,
                size: 24,
              ),
              unselectedIconTheme: IconThemeData(
                color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.8),
                size: 24,
              ),
              selectedLabelTextStyle: TextStyle(
                color: Theme.of(context).colorScheme.primary,
                fontWeight: FontWeight.w700,
              ),
              unselectedLabelTextStyle: TextStyle(
                color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.9),
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ],
      ),
    );
  }

  /// 构建导航头部
  Widget _buildNavHeader(bool extended) {
    return Container(
      padding: EdgeInsets.all(extended ? 20 : 12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.4),
        border: Border(
          bottom: BorderSide(
            color: Theme.of(context).dividerColor.withValues(alpha: 0.3),
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          // Logo
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surface,
              borderRadius: BorderRadius.circular(12),
              boxShadow: [
                BoxShadow(
                  color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
                  blurRadius: 8,
                  offset: const Offset(0, 2),
                ),
              ],
            ),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(12),
              child: Image.asset(
                'assets/icons/Logo3.png',
                width: 40,
                height: 40,
                fit: BoxFit.cover,
              ),
            ),
          ),

          // 文字（仅在展开时显示）
          if (extended) ...[
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (widget.title != null)
                    Text(
                      widget.title!,
                      style: Theme.of(context).textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.bold,
                        color: Theme.of(context)
                            .colorScheme
                            .onPrimaryContainer
                            .withValues(alpha: 0.9),
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  if (widget.subtitle != null)
                    Text(
                      widget.subtitle!,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context)
                            .colorScheme
                            .onPrimaryContainer
                            .withValues(alpha: 0.8),
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }

  /// 构建用户菜单
  Widget _buildUserMenu(bool extended) {
    return Container(
      padding: EdgeInsets.all(extended ? 16 : 8),
      child: extended
          ? Row(
              children: [
                CircleAvatar(
                  radius: 18,
                  backgroundColor: Theme.of(context).colorScheme.primary,
                  child: Icon(
                    Icons.person,
                    color: Theme.of(context).colorScheme.onPrimary,
                    size: 18,
                  ),
                ),
                if (extended) ...[
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'John Doe',
                          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                                fontWeight: FontWeight.w600,
                              ),
                          overflow: TextOverflow.ellipsis,
                        ),
                        Text(
                          'Online',
                          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                color: Colors.green,
                              ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                ],
                PopupMenuButton<String>(
                  icon: Icon(
                    Icons.more_vert,
                    color: Theme.of(context).colorScheme.onSurface,
                    size: 20,
                  ),
                  itemBuilder: (context) => [
                    const PopupMenuItem(
                      value: 'profile',
                      child: Row(
                        children: [
                          Icon(Icons.person_outline),
                          SizedBox(width: 8),
                          Text('Profile'),
                        ],
                      ),
                    ),
                    const PopupMenuItem(
                      value: 'settings',
                      child: Row(
                        children: [
                          Icon(Icons.settings_outlined),
                          SizedBox(width: 8),
                          Text('Settings'),
                        ],
                      ),
                    ),
                    const PopupMenuDivider(),
                    const PopupMenuItem(
                      value: 'logout',
                      child: Row(
                        children: [
                          Icon(Icons.logout_outlined, color: Colors.red),
                          SizedBox(width: 8),
                          Text('Logout', style: TextStyle(color: Colors.red)),
                        ],
                      ),
                    ),
                  ],
                  onSelected: (value) => _handleUserMenuSelection(value),
                ),
              ],
            )
          : Center(
              child: PopupMenuButton<String>(
                tooltip: '用户菜单',
                child: CircleAvatar(
                  radius: 16,
                  backgroundColor: Theme.of(context).colorScheme.primary,
                  child: Icon(
                    Icons.person,
                    color: Theme.of(context).colorScheme.onPrimary,
                    size: 16,
                  ),
                ),
                itemBuilder: (context) => [
                  const PopupMenuItem(
                    value: 'profile',
                    child: Row(
                      children: [
                        Icon(Icons.person_outline),
                        SizedBox(width: 8),
                        Text('Profile'),
                      ],
                    ),
                  ),
                  const PopupMenuItem(
                    value: 'settings',
                    child: Row(
                      children: [
                        Icon(Icons.settings_outlined),
                        SizedBox(width: 8),
                        Text('Settings'),
                      ],
                    ),
                  ),
                  const PopupMenuDivider(),
                  const PopupMenuItem(
                    value: 'logout',
                    child: Row(
                      children: [
                        Icon(Icons.logout_outlined, color: Colors.red),
                        SizedBox(width: 8),
                        Text('Logout', style: TextStyle(color: Colors.red)),
                      ],
                    ),
                  ),
                ],
                onSelected: (value) => _handleUserMenuSelection(value),
              ),
            ),
    );
  }

  /// 构建底部导航
  Widget _buildBottomNavigation() {
    return Container(
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.1),
            blurRadius: 10,
            offset: const Offset(0, -2),
          ),
        ],
      ),
      child: BottomNavigationBar(
        currentIndex: widget.selectedIndex,
        onTap: widget.onDestinationSelected,
        type: BottomNavigationBarType.fixed,
        backgroundColor: Theme.of(context).colorScheme.surface,
        selectedItemColor: Theme.of(context).colorScheme.primary,
        unselectedItemColor: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.6),
        elevation: 8,
        items: widget.destinations.map((destination) {
          return BottomNavigationBarItem(
            icon: destination.icon,
            activeIcon: destination.selectedIcon,
            label: destination.label,
          );
        }).toList(),
      ),
    );
  }

  /// 构建应用栏
  Widget _buildAppBar() {
    return AppBar(
      title: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (widget.title != null)
            Text(widget.title!),
          if (widget.subtitle != null)
            Text(
              widget.subtitle!,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.7),
                  ),
            ),
        ],
      ),
      centerTitle: false,
      elevation: 1,
      actions: [
        IconButton(
          icon: const Icon(Icons.search),
          onPressed: () {},
          tooltip: '搜索',
        ),
        IconButton(
          icon: const Icon(Icons.notifications_outlined),
          onPressed: () {},
          tooltip: '通知',
        ),
        const SizedBox(width: 8),
      ],
    );
  }

  /// 构建带应用栏的主体内容
  Widget _buildBodyWithAppBar() {
    return widget.body;
  }

  /// 处理用户菜单选择
  void _handleUserMenuSelection(String value) {
    switch (value) {
      case 'profile':
        // 导航到个人资料
        if (context.mounted) {
          context.go('/profile');
        }
        break;
      case 'settings':
        // 导航到设置
        if (context.mounted) {
          context.go('/settings');
        }
        break;
      case 'logout':
        // 处理登出
        if (context.mounted) {
          context.go('/login');
        }
        break;
    }
  }
}

/// 扩展的 NavigationDestination 辅助类
class NavigationDestinationHelper {
  static List<NavigationDestination> fromMenuItems(List<MenuItem> items) {
    return items
        .where((item) => item is! MenuDivider)
        .map((item) => NavigationDestination(
              icon: Icon(item.icon),
              selectedIcon: Icon(item.selectedIcon ?? item.icon),
              label: item.label,
            ))
        .toList();
  }
}
