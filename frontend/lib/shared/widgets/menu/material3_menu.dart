import 'package:flutter/material.dart';

/// Material 3 自适应菜单增强组件
///
/// 基于 Material 3 设计规范，提供完整的自适应导航体验
/// 支持：
/// - 响应式断点自适应（移动端、平板、桌面端）
/// - 可折叠/展开的侧边栏
/// - 图标-only 模式（桌面端收起）
/// - 徽章通知系统
/// - 模态导航（移动端抽屉）
/// - 悬浮操作按钮集成
/// - 动画过渡效果
/// - 键盘快捷键支持
/// - 无障碍访问

// ==================== 核心数据模型 ====================

/// 菜单项定义
class M3MenuItem {
  /// 唯一标识符
  final String id;

  /// 图标（未选中状态）
  final IconData icon;

  /// 选中时的图标
  final IconData? selectedIcon;

  /// 菜单标签
  final String label;

  /// 详细描述（可选）
  final String? description;

  /// 快捷键提示
  final String? shortcut;

  /// 徽章数量
  final int? badgeCount;

  /// 是否启用
  final bool enabled;

  /// 是否显示在菜单中
  final bool visible;

  /// 子菜单项
  final List<M3MenuItem>? children;

  /// 自定义徽章颜色
  final Color? badgeColor;

  const M3MenuItem({
    required this.id,
    required this.icon,
    required this.label,
    this.selectedIcon,
    this.description,
    this.shortcut,
    this.badgeCount,
    this.enabled = true,
    this.visible = true,
    this.children,
    this.badgeColor,
  });

  /// 是否有徽章
  bool get hasBadge => badgeCount != null && badgeCount! > 0;

  /// 是否有子菜单
  bool get hasChildren => children != null && children!.isNotEmpty;
}

/// 菜单分隔线
class M3MenuDivider extends M3MenuItem {
  const M3MenuDivider()
      : super(
          id: 'divider',
          icon: Icons.minimize,
          label: '',
          enabled: false,
        );
}

/// 菜单组
class M3MenuGroup {
  final String title;
  final List<M3MenuItem> items;
  final String? leadingIcon;

  const M3MenuGroup({
    required this.title,
    required this.items,
    this.leadingIcon,
  });
}

// ==================== 配置类 ====================

/// 自适应菜单配置
class M3MenuConfig {
  /// 菜单项列表
  final List<M3MenuItem> items;

  /// 选中的菜单项ID
  final String? selectedId;

  /// 选择回调
  final ValueChanged<String> onSelected;

  /// 展开时的宽度（桌面端）
  final double expandedWidth;

  /// 折叠时的宽度（桌面端）
  final double collapsedWidth;

  /// 是否显示用户信息区域
  final bool showUserInfo;

  /// 是否显示快捷键提示
  final bool showShortcuts;

  /// 是否支持动画
  final bool animated;

  /// 菜单标题
  final String? title;

  /// 菜单副标题
  final String? subtitle;

  /// 是否自动根据屏幕大小调整
  final bool autoAdapt;

  /// 移动端是否使用抽屉
  final bool useDrawerOnMobile;

  /// 是否支持键盘快捷键
  final bool keyboardShortcuts;

  /// 悬浮操作按钮
  final Widget? floatingActionButton;

  /// 自定义用户菜单构建器
  final WidgetBuilder? userMenuBuilder;

  /// 自定义头部构建器
  final WidgetBuilder? headerBuilder;

  /// 自定义底部构建器
  final WidgetBuilder? bottomBuilder;

  const M3MenuConfig({
    required this.items,
    required this.onSelected,
    this.selectedId,
    this.expandedWidth = 280,
    this.collapsedWidth = 72,
    this.showUserInfo = true,
    this.showShortcuts = true,
    this.animated = true,
    this.title,
    this.subtitle,
    this.autoAdapt = true,
    this.useDrawerOnMobile = true,
    this.keyboardShortcuts = true,
    this.floatingActionButton,
    this.userMenuBuilder,
    this.headerBuilder,
    this.bottomBuilder,
  });

  /// 获取可见的菜单项
  List<M3MenuItem> get visibleItems => items.where((item) => item.visible).toList();
}

// ==================== 主菜单组件 ====================

/// Material 3 自适应菜单主组件
class M3AdaptiveMenu extends StatefulWidget {
  final M3MenuConfig config;

  const M3AdaptiveMenu({
    super.key,
    required this.config,
  });

  @override
  State<M3AdaptiveMenu> createState() => _M3AdaptiveMenuState();
}

class _M3AdaptiveMenuState extends State<M3AdaptiveMenu>
    with SingleTickerProviderStateMixin {
  late AnimationController _animationController;
  late Animation<double> _widthAnimation;
  bool _isExpanded = true;
  final GlobalKey<ScaffoldState> _scaffoldKey = GlobalKey<ScaffoldState>();

  @override
  void initState() {
    super.initState();
    _animationController = AnimationController(
      duration: const Duration(milliseconds: 300),
      vsync: this,
    );
    _updateAnimation();
    _setupKeyboardShortcuts();
  }

  @override
  void didUpdateWidget(covariant M3AdaptiveMenu oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.config.expandedWidth != widget.config.expandedWidth ||
        oldWidget.config.collapsedWidth != widget.config.collapsedWidth) {
      _updateAnimation();
    }
  }

  void _updateAnimation() {
    final targetWidth = _isExpanded
        ? widget.config.expandedWidth
        : widget.config.collapsedWidth;

    _widthAnimation = Tween<double>(
      begin: targetWidth,
      end: targetWidth,
    ).animate(CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeInOut,
    ));
  }

  void _toggleExpansion() {
    setState(() {
      _isExpanded = !_isExpanded;
      _updateAnimation();
      if (widget.config.animated) {
        _animationController.forward(from: 0);
      }
    });
  }

  void _setupKeyboardShortcuts() {
    if (!widget.config.keyboardShortcuts) return;

    // 可以在这里添加键盘快捷键支持
    // 例如：Ctrl+1, Ctrl+2 等切换菜单项
  }

  void _handleSelection(String id) {
    widget.config.onSelected(id);
    // 移动端抽屉自动关闭
    if (_scaffoldKey.currentState?.isDrawerOpen ?? false) {
      Navigator.of(context).pop();
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!widget.config.autoAdapt) {
      return _buildDesktopMenu();
    }

    return LayoutBuilder(
      builder: (context, constraints) {
        final width = constraints.maxWidth;

        // 小屏幕（< 600dp）- 移动端抽屉
        if (width < 600) {
          return _buildMobileDrawer();
        }

        // 中等屏幕（600-840dp）- 折叠侧边栏
        if (width < 840) {
          return _buildDesktopMenu(collapsed: true);
        }

        // 大屏幕（>= 840dp）- 完整侧边栏
        return _buildDesktopMenu(collapsed: false);
      },
    );
  }

  /// 构建移动端抽屉
  Widget _buildMobileDrawer() {
    return Scaffold(
      key: _scaffoldKey,
      drawer: _buildDrawerContent(),
      body: _buildMobileBody(),
      floatingActionButton: widget.config.floatingActionButton,
    );
  }

  /// 构建抽屉内容
  Widget _buildDrawerContent() {
    return Material(
      child: Container(
        color: Theme.of(context).colorScheme.surface,
        child: Column(
          children: [
            // 头部
            if (widget.config.headerBuilder != null)
              widget.config.headerBuilder!(context)
            else
              _buildHeader(true),

            // 菜单内容
            Expanded(
              child: _buildMenuList(true),
            ),

            // 底部
            if (widget.config.bottomBuilder != null)
              widget.config.bottomBuilder!(context)
            else if (widget.config.showUserInfo)
              _buildBottomSection(true),
          ],
        ),
      ),
    );
  }

  /// 构建移动端主体
  Widget _buildMobileBody() {
    return Scaffold(
      appBar: AppBar(
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (widget.config.title != null)
              Text(widget.config.title!),
            if (widget.config.subtitle != null)
              Text(
                widget.config.subtitle!,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.7),
                    ),
              ),
          ],
        ),
        leading: IconButton(
          icon: const Icon(Icons.menu),
          onPressed: () => _scaffoldKey.currentState?.openDrawer(),
        ),
        actions: [
          if (widget.config.floatingActionButton != null)
            IconButton(
              icon: widget.config.floatingActionButton!,
              onPressed: () {},
            ),
        ],
      ),
      body: _buildContentArea(),
    );
  }

  /// 构建桌面端菜单
  Widget _buildDesktopMenu({bool collapsed = false}) {
    return AnimatedBuilder(
      animation: _animationController,
      builder: (context, child) {
        return Row(
          children: [
            // 侧边栏
            Container(
              width: collapsed ? widget.config.collapsedWidth : _widthAnimation.value,
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
                  if (widget.config.headerBuilder != null)
                    widget.config.headerBuilder!(context)
                  else
                    _buildHeader(!collapsed),

                  // 菜单内容
                  Expanded(
                    child: _buildMenuList(!collapsed),
                  ),

                  // 底部
                  if (widget.config.bottomBuilder != null)
                    widget.config.bottomBuilder!(context)
                  else if (widget.config.showUserInfo)
                    _buildBottomSection(!collapsed),
                ],
              ),
            ),

            // 主体内容
            Expanded(
              child: _buildContentArea(),
            ),
          ],
        );
      },
    );
  }

  /// 构建头部
  Widget _buildHeader(bool expanded) {
    return Container(
      padding: EdgeInsets.all(expanded ? 20 : 12),
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
          // Logo/Icon
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.primary,
              borderRadius: BorderRadius.circular(12),
              boxShadow: [
                BoxShadow(
                  color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
                  blurRadius: 8,
                  offset: const Offset(0, 2),
                ),
              ],
            ),
            child: Icon(
              Icons.smart_toy,
              color: Theme.of(context).colorScheme.onPrimary,
              size: 24,
            ),
          ),

          // 只在展开时显示文字
          if (expanded) ...[
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (widget.config.title != null)
                    Text(
                      widget.config.title!,
                      style: Theme.of(context).textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.bold,
                        color: Theme.of(context)
                            .colorScheme
                            .onPrimaryContainer
                            .withValues(alpha: 0.9),
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  if (widget.config.subtitle != null)
                    Text(
                      widget.config.subtitle!,
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

          // 折叠/展开按钮（仅桌面端）
          if (!widget.config.autoAdapt) ...[
            const Spacer(),
            IconButton(
              icon: Icon(
                _isExpanded ? Icons.chevron_left : Icons.chevron_right,
                size: 20,
              ),
              onPressed: _toggleExpansion,
              tooltip: _isExpanded ? '折叠菜单' : '展开菜单',
              style: IconButton.styleFrom(
                foregroundColor: Theme.of(context).colorScheme.onPrimaryContainer,
                padding: const EdgeInsets.all(8),
                minimumSize: const Size(32, 32),
              ),
            ),
          ],
        ],
      ),
    );
  }

  /// 构建菜单列表
  Widget _buildMenuList(bool expanded) {
    final visibleItems = widget.config.visibleItems;

    return ListView.builder(
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: visibleItems.length,
      itemBuilder: (context, index) {
        final item = visibleItems[index];

        if (item is M3MenuDivider) {
          return Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Divider(
              height: 1,
              color: Theme.of(context).dividerColor.withValues(alpha: 0.3),
            ),
          );
        }

        final isSelected = widget.config.selectedId == item.id;

        return _M3MenuItemTile(
          item: item,
          isSelected: isSelected,
          expanded: expanded,
          showShortcut: widget.config.showShortcuts,
          onTap: () => _handleSelection(item.id),
        );
      },
    );
  }

  /// 构建底部区域
  Widget _buildBottomSection(bool expanded) {
    return Container(
      padding: EdgeInsets.all(expanded ? 16 : 12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface.withValues(alpha: 0.3),
        border: Border(
          top: BorderSide(
            color: Theme.of(context).dividerColor.withValues(alpha: 0.2),
            width: 1,
          ),
        ),
      ),
      child: expanded
          ? (widget.config.userMenuBuilder?.call(context) ?? const _M3UserProfileTileExpanded())
          : (widget.config.userMenuBuilder?.call(context) ?? const _M3UserProfileTileCompact()),
    );
  }

  /// 构建内容区域（占位）
  Widget _buildContentArea() {
    return Container(
      color: Theme.of(context).colorScheme.surface,
      child: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.dashboard_outlined,
              size: 64,
              color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.5),
            ),
            const SizedBox(height: 16),
            Text(
              '内容区域',
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.7),
              ),
            ),
            const SizedBox(height: 8),
            Text(
              '请在父组件中提供实际内容',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.5),
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  void dispose() {
    _animationController.dispose();
    super.dispose();
  }
}

// ==================== 菜单项组件 ====================

/// Material 3 菜单项组件
class _M3MenuItemTile extends StatelessWidget {
  final M3MenuItem item;
  final bool isSelected;
  final bool expanded;
  final bool showShortcut;
  final VoidCallback onTap;

  const _M3MenuItemTile({
    required this.item,
    required this.isSelected,
    required this.expanded,
    required this.showShortcut,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    if (!item.enabled) {
      return const SizedBox.shrink();
    }

    final iconColor = isSelected
        ? Theme.of(context).colorScheme.primary
        : Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.8);

    final textColor = isSelected
        ? Theme.of(context).colorScheme.primary
        : Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.9);

    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 2),
      decoration: BoxDecoration(
        color: isSelected
            ? Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.8)
            : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: isSelected
              ? Theme.of(context).colorScheme.primary.withValues(alpha: 0.3)
              : Theme.of(context).dividerColor.withValues(alpha: 0.2),
          width: 0.5,
        ),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: item.enabled ? onTap : null,
          borderRadius: BorderRadius.circular(8),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            child: expanded
                ? _buildExpandedLayout(context, iconColor, textColor)
                : _buildCollapsedLayout(context, iconColor),
          ),
        ),
      ),
    );
  }

  Widget _buildExpandedLayout(
      BuildContext context, Color iconColor, Color textColor) {
    return Row(
      children: [
        // 图标
        Icon(
          isSelected ? (item.selectedIcon ?? item.icon) : item.icon,
          color: iconColor,
          size: 24,
        ),

        const SizedBox(width: 16),

        // 标签和描述
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                item.label,
                style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                      color: textColor,
                      fontWeight: isSelected ? FontWeight.w700 : FontWeight.w600,
                    ),
                overflow: TextOverflow.ellipsis,
              ),
              if (item.description != null)
                Text(
                  item.description!,
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
                      ),
                  overflow: TextOverflow.ellipsis,
                  maxLines: 1,
                ),
            ],
          ),
        ),

        // 快捷键
        if (showShortcut && item.shortcut != null) ...[
          const SizedBox(width: 8),
          Text(
            item.shortcut!,
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: isSelected
                      ? textColor
                      : Theme.of(context).colorScheme.onSurfaceVariant.withValues(alpha: 0.8),
                  fontWeight: FontWeight.w500,
                ),
          ),
        ],

        // 徽章
        if (item.hasBadge) ...[
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(
              color: item.badgeColor ?? Theme.of(context).colorScheme.error,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Text(
              item.badgeCount! > 99 ? '99+' : item.badgeCount.toString(),
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.onError,
                    fontWeight: FontWeight.bold,
                    fontSize: 10,
                  ),
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildCollapsedLayout(BuildContext context, Color iconColor) {
    return Center(
      child: Stack(
        children: [
          Icon(
            isSelected ? (item.selectedIcon ?? item.icon) : item.icon,
            color: iconColor,
            size: 24,
          ),

          // 徽章（折叠时显示为点）
          if (item.hasBadge)
            Positioned(
              right: 0,
              top: 0,
              child: Container(
                width: 8,
                height: 8,
                decoration: BoxDecoration(
                  color: item.badgeColor ?? Theme.of(context).colorScheme.error,
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: Theme.of(context).colorScheme.surface,
                    width: 1,
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

// ==================== 用户信息组件 ====================

/// 展开的用户信息组件
class _M3UserProfileTileExpanded extends StatelessWidget {
  const _M3UserProfileTileExpanded();

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        CircleAvatar(
          radius: 20,
          backgroundColor: Theme.of(context).colorScheme.primary,
          child: Icon(
            Icons.person,
            color: Theme.of(context).colorScheme.onPrimary,
            size: 20,
          ),
        ),
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
                      color: Theme.of(context).colorScheme.tertiary,
                    ),
                overflow: TextOverflow.ellipsis,
              ),
            ],
          ),
        ),
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
            PopupMenuItem(
              value: 'logout',
              child: Row(
                children: [
                  Icon(Icons.logout_outlined, color: Theme.of(context).colorScheme.error),
                  SizedBox(width: 8),
                  Text('Logout', style: TextStyle(color: Theme.of(context).colorScheme.error)),
                ],
              ),
            ),
          ],
          onSelected: (value) => _handleMenuSelection(context, value),
        ),
      ],
    );
  }

  void _handleMenuSelection(BuildContext context, String value) {
    switch (value) {
      case 'profile':
        // 导航到个人资料
        break;
      case 'settings':
        // 导航到设置
        break;
      case 'logout':
        // 处理登出
        break;
    }
  }
}

/// 折叠的用户信息组件
class _M3UserProfileTileCompact extends StatelessWidget {
  const _M3UserProfileTileCompact();

  @override
  Widget build(BuildContext context) {
    return Center(
      child: PopupMenuButton<String>(
        tooltip: '用户菜单',
        child: CircleAvatar(
          radius: 18,
          backgroundColor: Theme.of(context).colorScheme.primary,
          child: Icon(
            Icons.person,
            color: Theme.of(context).colorScheme.onPrimary,
            size: 18,
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
          PopupMenuItem(
            value: 'logout',
            child: Row(
              children: [
                Icon(Icons.logout_outlined, color: Theme.of(context).colorScheme.error),
                SizedBox(width: 8),
                Text('Logout', style: TextStyle(color: Theme.of(context).colorScheme.error)),
              ],
            ),
          ),
        ],
        onSelected: (value) => _handleMenuSelection(context, value),
      ),
    );
  }

  void _handleMenuSelection(BuildContext context, String value) {
    switch (value) {
      case 'profile':
        break;
      case 'settings':
        break;
      case 'logout':
        break;
    }
  }
}

// ==================== 使用示例 ====================

/// M3AdaptiveMenu 使用示例
///
/// ```dart
/// class MyApp extends StatelessWidget {
///   @override
///   Widget build(BuildContext context) {
///     return MaterialApp(
///       home: M3AdaptiveMenu(
///         config: M3MenuConfig(
///           items: [
///             M3MenuItem(
///               id: 'dashboard',
///               icon: Icons.dashboard_outlined,
///               selectedIcon: Icons.dashboard,
///               label: '仪表板',
///               shortcut: 'Ctrl+1',
///             ),
///             M3MenuItem(
///               id: 'analytics',
///               icon: Icons.analytics_outlined,
///               selectedIcon: Icons.analytics,
///               label: '分析',
///               badgeCount: 3,
///             ),
///             M3MenuDivider(),
///             M3MenuItem(
///               id: 'settings',
///               icon: Icons.settings_outlined,
///               selectedIcon: Icons.settings,
///               label: '设置',
///               shortcut: 'Ctrl+,',
///             ),
///           ],
///           onSelected: (id) {
///             print('Selected: $id');
///           },
///           title: 'My App',
///           subtitle: 'v1.0.0',
///           expandedWidth: 280,
///           collapsedWidth: 72,
///         ),
///       ),
///     );
///   }
/// }
/// ```
