import 'package:flutter/material.dart';

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
  });

  final List<NavigationDestination> destinations;
  final int selectedIndex;
  final ValueChanged<int>? onDestinationSelected;
  final Widget? body;
  final Widget? floatingActionButton;
  final PreferredSizeWidget? appBar;

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
          return _buildDesktopLayout(context);
        }
      },
    );
  }

  /// 移动端布局
  Widget _buildMobileLayout(BuildContext context) {
    return Scaffold(
      appBar: appBar,
      body: body,
      floatingActionButton: floatingActionButton,
      bottomNavigationBar: NavigationBar(
        selectedIndex: selectedIndex,
        onDestinationSelected: onDestinationSelected,
        destinations: destinations,
        height: 65,
      ),
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
                color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
                border: Border(
                  right: BorderSide(
                    color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.2),
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
                    child: Icon(
                      Icons.psychology,
                      size: 32,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                  ),
                  const SizedBox(height: 16),
                  const Divider(),
                  const SizedBox(height: 8),
                  // 导航项目
                  ...destinations.asMap().entries.map((entry) {
                    final index = entry.key;
                    final destination = entry.value;
                    return _buildCompactNavItem(
                      context,
                      destination,
                      index == selectedIndex,
                      () => onDestinationSelected?.call(index),
                    );
                  }),
                  const Spacer(),
                ],
              ),
            ),
          ),
          const VerticalDivider(thickness: 1, width: 1),
          Expanded(child: body!),
        ],
      ),
      floatingActionButton: floatingActionButton,
    );
  }

  /// 桌面端布局 - 使用永久的侧边栏
  Widget _buildDesktopLayout(BuildContext context) {
    return Scaffold(
      appBar: appBar,
      body: Row(
        children: [
          // 永久的侧边栏导航
          SizedBox(
            width: 280,
            child: Container(
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
                border: Border(
                  right: BorderSide(
                    color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.2),
                    width: 1,
                  ),
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // 应用标题区域
                  Padding(
                    padding: const EdgeInsets.all(24.0),
                    child: Row(
                      children: [
                        Icon(
                          Icons.psychology,
                          size: 32,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                        const SizedBox(width: 12),
                        Text(
                          'Personal AI',
                          style: Theme.of(context).textTheme.titleLarge?.copyWith(
                                color: Theme.of(context).colorScheme.onSurfaceVariant,
                                fontWeight: FontWeight.bold,
                              ),
                        ),
                      ],
                    ),
                  ),
                  const Divider(),
                  const SizedBox(height: 8),
                  // 导航项目
                  ...destinations.asMap().entries.map((entry) {
                    final index = entry.key;
                    final destination = entry.value;
                    return _buildExpandedNavItem(
                      context,
                      destination,
                      index == selectedIndex,
                      () => onDestinationSelected?.call(index),
                    );
                  }),
                  const Spacer(),
                ],
              ),
            ),
          ),
          const VerticalDivider(thickness: 1, width: 1),
          Expanded(child: body!),
        ],
      ),
      floatingActionButton: floatingActionButton,
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
    final safeMaxWidth = maxWidth ?? (screenWidth < 600
        ? screenWidth
        : screenWidth < 1200
        ? 1000
        : 1200);

    // 计算安全的内边距
    final safePadding = padding ?? EdgeInsets.symmetric(
      horizontal: screenWidth < 600 ? 16.0 : 24.0,
      vertical: 16.0,
    );

    return Container(
      alignment: alignment,
      padding: safePadding,
      child: ConstrainedBox(
        constraints: BoxConstraints(
          maxWidth: safeMaxWidth,
          minHeight: 0,
        ),
        child: child,
      ),
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