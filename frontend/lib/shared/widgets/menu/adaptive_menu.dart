import 'package:flutter/material.dart';

/// 自适应菜单配置
class AdaptiveMenuConfig {
  /// 菜单项列表
  final List<MenuItem> items;

  /// 选中的索引
  final int selectedIndex;

  /// 选择回调
  final ValueChanged<int> onSelected;

  /// 菜单宽度（展开时）
  final double expandedWidth;

  /// 菜单宽度（折叠时）
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

  const AdaptiveMenuConfig({
    required this.items,
    required this.selectedIndex,
    required this.onSelected,
    this.expandedWidth = 280,
    this.collapsedWidth = 72,
    this.showUserInfo = true,
    this.showShortcuts = true,
    this.animated = true,
    this.title,
    this.subtitle,
  });
}

/// 菜单项
class MenuItem {
  /// 图标（未选中状态）
  final IconData icon;

  /// 选中时的图标
  final IconData? selectedIcon;

  /// 菜单标签
  final String label;

  /// 快捷键提示
  final String? shortcut;

  /// 徽章数量
  final int? badgeCount;

  /// 是否启用
  final bool enabled;

  const MenuItem({
    required this.icon,
    required this.label,
    this.selectedIcon,
    this.shortcut,
    this.badgeCount,
    this.enabled = true,
  });
}

/// 分隔线项目
class MenuDivider extends MenuItem {
  const MenuDivider()
      : super(
          icon: Icons.minimize,
          label: '',
          enabled: false,
        );
}

/// 自适应菜单组件
class AdaptiveMenu extends StatefulWidget {
  final AdaptiveMenuConfig config;

  const AdaptiveMenu({
    super.key,
    required this.config,
  });

  @override
  State<AdaptiveMenu> createState() => _AdaptiveMenuState();
}

class _AdaptiveMenuState extends State<AdaptiveMenu>
    with SingleTickerProviderStateMixin {
  late AnimationController _animationController;
  late Animation<double> _widthAnimation;
  bool _isExpanded = true;

  @override
  void initState() {
    super.initState();
    _animationController = AnimationController(
      duration: const Duration(milliseconds: 300),
      vsync: this,
    );

    _updateAnimation();
  }

  @override
  void didUpdateWidget(covariant AdaptiveMenu oldWidget) {
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
      _animationController.forward(from: 0);
    });
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _animationController,
      builder: (context, child) {
        return Container(
          width: _widthAnimation.value,
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
              // 头部区域
              _buildHeader(context),

              // 菜单内容
              Expanded(
                child: _buildMenuContent(context),
              ),

              // 底部区域
              if (widget.config.showUserInfo) _buildBottomSection(context),
            ],
          ),
        );
      },
    );
  }

  Widget _buildHeader(BuildContext context) {
    return Container(
      padding: EdgeInsets.all(_isExpanded ? 20 : 12),
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
          if (_isExpanded) ...[
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

          // 折叠/展开按钮
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
      ),
    );
  }

  Widget _buildMenuContent(BuildContext context) {
    return ListView.builder(
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: widget.config.items.length,
      itemBuilder: (context, index) {
        final item = widget.config.items[index];

        if (item is MenuDivider) {
          return Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Divider(
              height: 1,
              color: Theme.of(context).dividerColor.withValues(alpha: 0.3),
            ),
          );
        }

        final isSelected = widget.config.selectedIndex == index;

        return _MenuItemTile(
          item: item,
          isSelected: isSelected,
          expanded: _isExpanded,
          showShortcut: widget.config.showShortcuts,
          onTap: () => widget.config.onSelected(index),
        );
      },
    );
  }

  Widget _buildBottomSection(BuildContext context) {
    return Container(
      padding: EdgeInsets.all(_isExpanded ? 16 : 12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface.withValues(alpha: 0.3),
        border: Border(
          top: BorderSide(
            color: Theme.of(context).dividerColor.withValues(alpha: 0.2),
            width: 1,
          ),
        ),
      ),
      child: _isExpanded
          ? const _UserProfileTileExpanded()
          : const _UserProfileTileCompact(),
    );
  }

  @override
  void dispose() {
    _animationController.dispose();
    super.dispose();
  }
}

/// 菜单项组件
class _MenuItemTile extends StatelessWidget {
  final MenuItem item;
  final bool isSelected;
  final bool expanded;
  final bool showShortcut;
  final VoidCallback onTap;

  const _MenuItemTile({
    required this.item,
    required this.isSelected,
    required this.expanded,
    required this.showShortcut,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
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

        // 标签
        Expanded(
          child: Text(
            item.label,
            style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                  color: textColor,
                  fontWeight: isSelected ? FontWeight.w700 : FontWeight.w600,
                ),
            overflow: TextOverflow.ellipsis,
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
        if (item.badgeCount != null && item.badgeCount! > 0) ...[
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.error,
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
          if (item.badgeCount != null && item.badgeCount! > 0)
            Positioned(
              right: 0,
              top: 0,
              child: Container(
                width: 8,
                height: 8,
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.error,
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

/// 展开的用户信息组件
class _UserProfileTileExpanded extends StatelessWidget {
  const _UserProfileTileExpanded();

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
                'John Doe', // 应从用户状态获取
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                overflow: TextOverflow.ellipsis,
              ),
              Text(
                'Online', // 应从用户状态获取
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Colors.green,
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
class _UserProfileTileCompact extends StatelessWidget {
  const _UserProfileTileCompact();

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
