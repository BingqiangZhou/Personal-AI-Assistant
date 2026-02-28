import 'package:flutter/material.dart';

import '../../core/localization/app_localizations.dart';

const Duration _kBottomAccessoryPaddingTransition = Duration(milliseconds: 180);

/// Material Design 3自定义自适应导航组件
///
/// 完全绕过NavigationRail，使用自定义的Drawer和Column组合
/// 确保在所有平台上都不会出现断言错误
class CustomAdaptiveNavigation extends StatelessWidget {
  const CustomAdaptiveNavigation({
    super.key,
    required this.destinations,
    required this.selectedIndex,
    this.onDestinationSelected,
    this.body,
    this.floatingActionButton,
    this.appBar,
    this.bottomAccessory,
    this.bottomAccessoryBodyPadding = 60.0,
    this.desktopNavExpanded = true,
    this.onDesktopNavToggle,
  });

  final List<NavigationDestination> destinations;
  final int selectedIndex;
  final ValueChanged<int>? onDestinationSelected;
  final Widget? body;
  final Widget? floatingActionButton;
  final PreferredSizeWidget? appBar;
  final Widget? bottomAccessory;
  final double bottomAccessoryBodyPadding;
  final bool desktopNavExpanded;
  final VoidCallback? onDesktopNavToggle;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final screenWidth = constraints.maxWidth;

        if (screenWidth < 600) {
          // 移动端 - 使用底部导航栏
          return _buildMobileLayout(context);
        } else if (screenWidth < 840) {
          // 平板端 - 使用紧凑的抽屉导航
          return _buildTabletLayout(context);
        } else {
          // 桌面端 - 使用永久的侧边栏导航
          return _buildDesktopLayout(context, expanded: desktopNavExpanded);
        }
      },
    );
  }

  /// 移动端布局
  Widget _buildMobileLayout(BuildContext context) {
    final navigationBar = NavigationBar(
      selectedIndex: selectedIndex,
      onDestinationSelected: onDestinationSelected,
      destinations: destinations,
      height: 65,
    );

    return Scaffold(
      appBar: appBar,
      body: Stack(
        children: [
          // Body content with padding for bottom accessory (Mini Player height approx)
          AnimatedPadding(
            duration: _kBottomAccessoryPaddingTransition,
            curve: Curves.easeOutCubic,
            padding: EdgeInsets.only(
              bottom: bottomAccessory != null ? bottomAccessoryBodyPadding : 0,
            ),
            child: body ?? const SizedBox.shrink(),
          ),
          // Floating Action Button
          if (floatingActionButton != null)
            Positioned(
              right: 16,
              bottom: (bottomAccessory != null ? 76.0 : 16.0),
              child: floatingActionButton!,
            ),
          // Bottom Accessory (Player) Overlay
          if (bottomAccessory != null)
            Positioned(left: 0, right: 0, bottom: 0, child: bottomAccessory!),
        ],
      ),
      bottomNavigationBar: navigationBar,
    );
  }

  /// 平板端布局 - 使用抽屉导航
  Widget _buildTabletLayout(BuildContext context) {
    return Scaffold(
      appBar: appBar,
      body: Row(
        children: [
          // 紧凑的抽屉式导航
          SizedBox(
            width: 80,
            child: Container(
              decoration: BoxDecoration(
                color: Theme.of(
                  context,
                ).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
                border: Border(
                  right: BorderSide(
                    color: Theme.of(
                      context,
                    ).colorScheme.outline.withValues(alpha: 0.2),
                    width: 1,
                  ),
                ),
              ),
              child: Column(
                children: [
                  const SizedBox(height: 16),
                  // 应用标题或图标
                  Container(
                    padding: const EdgeInsets.all(8),
                    child: _buildBrandLogoBadge(context),
                  ),
                  const SizedBox(height: 16),
                  const Divider(),
                  const SizedBox(height: 8),
                  ..._buildNavigationItems(context, compact: true),
                  const Spacer(),
                  // Profile按钮单独在底部
                  if (destinations.isNotEmpty)
                    _buildProfileNavigationItem(context, compact: true),
                  const SizedBox(height: 8),
                ],
              ),
            ),
          ),
          const VerticalDivider(thickness: 1, width: 1),
          Expanded(
            child: _buildRightPaneNavigator(
              pageKey: const ValueKey('right_pane_root_tablet'),
            ),
          ),
        ],
      ),
    );
  }

  /// 桌面端布局 - 使用永久的侧边栏
  Widget _buildDesktopLayout(BuildContext context, {required bool expanded}) {
    return Scaffold(
      appBar: appBar,
      body: Row(
        children: [
          // 永久的侧边栏导航
          TweenAnimationBuilder<double>(
            tween: Tween<double>(end: expanded ? 280 : 80),
            duration: const Duration(milliseconds: 180),
            curve: Curves.easeOutCubic,
            builder: (context, width, child) {
              final showCompact = width < 200;
              return SizedBox(
                key: const ValueKey('desktop_navigation_sidebar'),
                width: width,
                child: Container(
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceContainerHighest
                        .withValues(alpha: 0.3),
                    border: Border(
                      right: BorderSide(
                        color: Theme.of(
                          context,
                        ).colorScheme.outline.withValues(alpha: 0.2),
                        width: 1,
                      ),
                    ),
                  ),
                  child: showCompact
                      ? _buildDesktopCollapsedSidebar(context)
                      : _buildDesktopExpandedSidebar(context),
                ),
              );
            },
          ),
          const VerticalDivider(thickness: 1, width: 1),
          Expanded(
            child: _buildRightPaneNavigator(
              pageKey: const ValueKey('right_pane_root_desktop'),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRightPaneNavigator({required ValueKey<String> pageKey}) {
    return ClipRect(
      child: Navigator(
        pages: [MaterialPage(key: pageKey, child: _buildRightPaneContent())],
        onDidRemovePage: (page) {},
      ),
    );
  }

  Widget _buildRightPaneContent() {
    return Stack(
      children: [
        RepaintBoundary(
          child: AnimatedPadding(
            duration: _kBottomAccessoryPaddingTransition,
            curve: Curves.easeOutCubic,
            padding: EdgeInsets.only(
              bottom: bottomAccessory != null ? bottomAccessoryBodyPadding : 0,
            ),
            child: body ?? const SizedBox.shrink(),
          ),
        ),
        if (floatingActionButton != null)
          Positioned(
            right: 24,
            bottom: (bottomAccessory != null ? 84.0 : 24.0),
            child: floatingActionButton!,
          ),
        if (bottomAccessory != null)
          Positioned(
            left: 0,
            right: 0,
            bottom: 0,
            child: RepaintBoundary(child: bottomAccessory!),
          ),
      ],
    );
  }

  Widget _buildDesktopExpandedSidebar(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          height: 56,
          padding: const EdgeInsets.symmetric(horizontal: 24.0),
          child: Row(
            children: [
              _buildBrandLogoBadge(context),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  AppLocalizations.of(context)!.sidebarAppTitle,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: Theme.of(context).textTheme.titleLarge?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              IconButton(
                onPressed: onDesktopNavToggle,
                tooltip: AppLocalizations.of(context)!.sidebarCollapseMenu,
                style: IconButton.styleFrom(
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  minimumSize: const Size(32, 32),
                  padding: EdgeInsets.zero,
                ),
                icon: const Icon(Icons.chevron_left),
              ),
            ],
          ),
        ),
        const Divider(),
        const SizedBox(height: 8),
        ..._buildNavigationItems(context, compact: false),
        const Spacer(),
        if (destinations.isNotEmpty)
          _buildProfileNavigationItem(context, compact: false),
        const SizedBox(height: 8),
      ],
    );
  }

  Widget _buildDesktopCollapsedSidebar(BuildContext context) {
    return Column(
      children: [
        Container(
          height: 56,
          padding: const EdgeInsets.symmetric(horizontal: 8.0),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              _buildBrandLogoBadge(context),
              IconButton(
                onPressed: onDesktopNavToggle,
                tooltip: AppLocalizations.of(context)!.sidebarExpandMenu,
                style: IconButton.styleFrom(
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  minimumSize: const Size(28, 28),
                  padding: EdgeInsets.zero,
                ),
                iconSize: 20,
                icon: const Icon(Icons.chevron_right),
              ),
            ],
          ),
        ),
        const Divider(),
        const SizedBox(height: 8),
        ..._buildNavigationItems(context, compact: true),
        const Spacer(),
        if (destinations.isNotEmpty)
          _buildProfileNavigationItem(context, compact: true),
        const SizedBox(height: 8),
      ],
    );
  }

  Widget _buildBrandLogoBadge(BuildContext context) {
    return Container(
      width: 32,
      height: 32,
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(8),
        boxShadow: [
          BoxShadow(
            color: Theme.of(
              context,
            ).colorScheme.secondary.withValues(alpha: 0.3),
            blurRadius: 6,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(8),
        child: Image.asset(
          'assets/icons/Logo3.png',
          width: 32,
          height: 32,
          fit: BoxFit.cover,
        ),
      ),
    );
  }

  List<Widget> _buildNavigationItems(
    BuildContext context, {
    required bool compact,
  }) {
    if (destinations.length <= 1) {
      return const <Widget>[];
    }

    final items = <Widget>[];
    for (var index = 0; index < destinations.length - 1; index++) {
      final destination = destinations[index];
      final isSelected = index == selectedIndex;
      items.add(
        compact
            ? _buildCompactNavItem(
                context,
                destination,
                isSelected,
                () => onDestinationSelected?.call(index),
              )
            : _buildExpandedNavItem(
                context,
                destination,
                isSelected,
                () => onDestinationSelected?.call(index),
              ),
      );
    }
    return items;
  }

  Widget _buildProfileNavigationItem(
    BuildContext context, {
    required bool compact,
  }) {
    final profileIndex = destinations.length - 1;
    final destination = destinations[profileIndex];
    final isSelected = profileIndex == selectedIndex;
    return compact
        ? _buildCompactNavItem(
            context,
            destination,
            isSelected,
            () => onDestinationSelected?.call(profileIndex),
          )
        : _buildExpandedNavItem(
            context,
            destination,
            isSelected,
            () => onDestinationSelected?.call(profileIndex),
          );
  }

  /// 构建紧凑的导航项（平板端）
  Widget _buildCompactNavItem(
    BuildContext context,
    NavigationDestination destination,
    bool isSelected,
    VoidCallback onTap,
  ) {
    return Tooltip(
      message: destination.label,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Container(
          width: 56,
          height: 56,
          margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          decoration: BoxDecoration(
            color: isSelected
                ? Theme.of(context).colorScheme.secondaryContainer
                : Colors.transparent,
            borderRadius: BorderRadius.circular(12),
          ),
          child: isSelected
              ? (destination.selectedIcon ?? destination.icon)
              : destination.icon,
        ),
      ),
    );
  }

  /// 构建展开的导航项（桌面端）
  Widget _buildExpandedNavItem(
    BuildContext context,
    NavigationDestination destination,
    bool isSelected,
    VoidCallback onTap,
  ) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: Container(
        width: double.infinity,
        height: 56,
        margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
        decoration: BoxDecoration(
          color: isSelected
              ? Theme.of(context).colorScheme.secondaryContainer
              : Colors.transparent,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          children: [
            const SizedBox(width: 16),
            SizedBox(
              width: 24,
              height: 24,
              child: isSelected
                  ? (destination.selectedIcon ?? destination.icon)
                  : destination.icon,
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Text(
                destination.label,
                style: Theme.of(context).textTheme.titleSmall?.copyWith(
                  color: isSelected
                      ? Theme.of(context).colorScheme.onSecondaryContainer
                      : Theme.of(context).colorScheme.onSurfaceVariant,
                  fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                ),
              ),
            ),
            if (isSelected)
              Container(
                width: 3,
                height: 24,
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.secondary,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            const SizedBox(width: 8),
          ],
        ),
      ),
    );
  }
}

/// 简化的响应式容器组件
class ResponsiveContainer extends StatelessWidget {
  const ResponsiveContainer({
    super.key,
    required this.child,
    this.maxWidth,
    this.padding,
    this.alignment,
  });

  final Widget child;
  final double? maxWidth;
  final EdgeInsetsGeometry? padding;
  final AlignmentGeometry? alignment;

  @override
  Widget build(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;

    // 计算安全的最大宽度
    final safeMaxWidth =
        maxWidth ??
        (screenWidth < 600
            ? screenWidth
            : screenWidth < 1200
            ? 1000
            : 1200);

    // 计算安全的内边距
    final safePadding =
        padding ??
        EdgeInsets.only(
          left: screenWidth < 600 ? 16.0 : 24.0,
          right: screenWidth < 600 ? 16.0 : 24.0,
          top: 0.0, // 移除顶部padding,让页面标题与"Personal AI"对齐
          bottom: 0.0,
        );

    // 移动端添加SafeArea，解决顶部标题栏被状态栏遮挡的问题
    Widget content = ConstrainedBox(
      constraints: BoxConstraints(maxWidth: safeMaxWidth, minHeight: 0),
      child: child,
    );

    if (screenWidth < 600) {
      content = SafeArea(top: true, bottom: false, child: content);
    }

    return Container(
      alignment: alignment,
      padding: safePadding,
      child: content,
    );
  }
}

/// 安全的响应式网格组件
class ResponsiveGrid extends StatelessWidget {
  const ResponsiveGrid({
    super.key,
    required this.children,
    this.crossAxisSpacing = 16.0,
    this.mainAxisSpacing = 16.0,
    this.childAspectRatio = 1.0,
  });

  final List<Widget> children;
  final double crossAxisSpacing;
  final double mainAxisSpacing;
  final double childAspectRatio;

  @override
  Widget build(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;

    // 简化的列数计算
    int crossAxisCount;
    if (screenWidth < 600) {
      crossAxisCount = 1;
    } else if (screenWidth < 900) {
      crossAxisCount = 2;
    } else if (screenWidth < 1200) {
      crossAxisCount = 3;
    } else {
      crossAxisCount = 4;
    }

    return GridView.builder(
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: crossAxisCount,
        crossAxisSpacing: crossAxisSpacing,
        mainAxisSpacing: mainAxisSpacing,
        childAspectRatio: childAspectRatio,
      ),
      itemCount: children.length,
      itemBuilder: (context, index) => children[index],
    );
  }
}
