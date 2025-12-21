import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../constants/breakpoints.dart';

/// 平台安全的自适应导航组件
///
/// 修复了NavigationRail在Windows上的断言错误
/// 提供跨平台兼容的响应式导航
class AdaptiveNavigation extends ConsumerWidget {
  const AdaptiveNavigation({
    super.key,
    required this.destinations,
    required this.selectedIndex,
    required this.onDestinationSelected,
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
  Widget build(BuildContext context, WidgetRef ref) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final screenWidth = constraints.maxWidth;
        final isTablet = screenWidth >= AppBreakpoints.medium && screenWidth < AppBreakpoints.large;
        final isMobile = screenWidth < AppBreakpoints.medium;

        if (isMobile) {
          return _buildMobileLayout(context, body!, floatingActionButton);
        } else if (isTablet) {
          return _buildTabletLayout(context, body!, floatingActionButton);
        } else {
          return _buildDesktopLayout(context, body!, floatingActionButton);
        }
      },
    );
  }

  /// 移动端布局：底部导航栏
  Widget _buildMobileLayout(BuildContext context, Widget body, Widget? floatingActionButton) {
    return Scaffold(
      appBar: appBar,
      body: body,
      floatingActionButton: floatingActionButton,
      bottomNavigationBar: NavigationBar(
        selectedIndex: selectedIndex,
        onDestinationSelected: onDestinationSelected,
        destinations: destinations,
        height: 65, // 确保适当的触摸目标大小
      ),
    );
  }

  /// 平板端布局：紧凑的侧边导航栏
  Widget _buildTabletLayout(BuildContext context, Widget body, Widget? floatingActionButton) {
    return Scaffold(
      appBar: appBar,
      body: Row(
        children: [
          // 紧凑的导航栏，明确设置所有属性以避免断言错误
          NavigationRail(
            selectedIndex: selectedIndex,
            onDestinationSelected: onDestinationSelected,
            extended: false, // 明确设置不展开
            labelType: NavigationRailLabelType.all, // 当extended=false时，可以使用all
            destinations: destinations
                .map((dest) => NavigationRailDestination(
                      icon: dest.icon,
                      selectedIcon: dest.selectedIcon,
                      label: Text(dest.label),
                    ))
                .toList(),
            useIndicator: true,
            backgroundColor: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
            minWidth: 56, // 最小宽度
            minExtendedWidth: 56, // 即使展开时的最小宽度
          ),
          const VerticalDivider(thickness: 1, width: 1),
          Expanded(child: body),
        ],
      ),
      floatingActionButton: floatingActionButton,
    );
  }

  /// 桌面端布局：展开的侧边导航栏
  Widget _buildDesktopLayout(BuildContext context, Widget body, Widget? floatingActionButton) {
    return Scaffold(
      appBar: appBar,
      body: Row(
        children: [
          // 展开的导航栏
          NavigationRail(
            selectedIndex: selectedIndex,
            onDestinationSelected: onDestinationSelected,
            extended: true, // 桌面端展开
            labelType: NavigationRailLabelType.all, // 展开时显示所有标签
            destinations: destinations
                .map((dest) => NavigationRailDestination(
                      icon: dest.icon,
                      selectedIcon: dest.selectedIcon,
                      label: Text(dest.label),
                    ))
                .toList(),
            useIndicator: true,
            backgroundColor: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
            minWidth: 300, // 展开时的最小宽度
            leading: Padding(
              padding: const EdgeInsets.all(16.0),
              child: Text(
                'Personal AI',
                style: Theme.of(context).textTheme.titleLarge?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                      fontWeight: FontWeight.bold,
                    ),
              ),
            ),
          ),
          const VerticalDivider(thickness: 1, width: 1),
          Expanded(child: body),
        ],
      ),
      floatingActionButton: floatingActionButton,
    );
  }
}

/// 安全的响应式容器
///
/// 提供跨平台兼容的响应式布局容器
class SafeResponsiveContainer extends StatelessWidget {
  const SafeResponsiveContainer({
    super.key,
    required this.child,
    this.maxWidth,
    this.padding,
    this.alignment,
    this.constraints,
  });

  final Widget child;
  final double? maxWidth;
  final EdgeInsetsGeometry? padding;
  final AlignmentGeometry? alignment;
  final BoxConstraints? constraints;

  @override
  Widget build(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    final screenHeight = MediaQuery.of(context).size.height;

    // 平台特定的调整
    final isWindows = Theme.of(context).platform == TargetPlatform.windows;

    // 计算安全的内边距
    EdgeInsetsGeometry safePadding = padding ?? EdgeInsets.symmetric(
      horizontal: _getResponsiveHorizontalPadding(screenWidth, isWindows),
      vertical: _getResponsiveVerticalPadding(screenHeight, isWindows),
    );

    // 计算最大宽度
    final safeMaxWidth = maxWidth ?? _getSafeMaxWidth(screenWidth, isWindows);

    return Container(
      alignment: alignment,
      padding: safePadding,
      constraints: constraints ?? BoxConstraints(
        maxWidth: safeMaxWidth,
        minHeight: 0,
      ),
      child: child,
    );
  }

  double _getResponsiveHorizontalPadding(double width, bool isWindows) {
    if (isWindows) {
      // Windows平台需要更大的边距以适应窗口边框
      if (width >= AppBreakpoints.large) return 32.0;
      if (width >= AppBreakpoints.medium) return 24.0;
      return 16.0;
    } else {
      // 其他平台的标准边距
      if (width >= AppBreakpoints.large) return 24.0;
      if (width >= AppBreakpoints.medium) return 20.0;
      return 16.0;
    }
  }

  double _getResponsiveVerticalPadding(double height, bool isWindows) {
    if (isWindows) {
      // Windows平台可能需要考虑标题栏高度
      return 16.0;
    } else {
      return 12.0;
    }
  }

  double _getSafeMaxWidth(double width, bool isWindows) {
    if (isWindows) {
      // Windows平台通常有更大的显示器，可以使用更大的最大宽度
      if (width >= AppBreakpoints.large) return 1400.0;
      if (width >= AppBreakpoints.medium) return AppBreakpoints.large;
      return width;
    } else {
      // 其他平台的限制
      if (width >= AppBreakpoints.large) return 1200.0;
      if (width >= AppBreakpoints.medium) return AppBreakpoints.mediumLarge;
      return width;
    }
  }
}

/// 平台感知的响应式网格
///
/// 提供跨平台兼容的响应式网格布局
class PlatformResponsiveGrid extends StatelessWidget {
  const PlatformResponsiveGrid({
    super.key,
    required this.children,
    this.crossAxisSpacing = 16.0,
    this.mainAxisSpacing = 16.0,
    this.childAspectRatio = 1.0,
    this.maxCrossAxisExtent,
  });

  final List<Widget> children;
  final double crossAxisSpacing;
  final double mainAxisSpacing;
  final double childAspectRatio;
  final double? maxCrossAxisExtent;

  @override
  Widget build(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    final isWindows = Theme.of(context).platform == TargetPlatform.windows;

    // 根据平台调整网格列数
    int crossAxisCount = _calculateCrossAxisCount(screenWidth, isWindows);

    // 调整间距以适应平台
    final adjustedCrossAxisSpacing = _getAdjustedSpacing(crossAxisSpacing, isWindows);
    final adjustedMainAxisSpacing = _getAdjustedSpacing(mainAxisSpacing, isWindows);

    return SafeResponsiveContainer(
      child: GridView.builder(
        gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
          crossAxisCount: crossAxisCount,
          crossAxisSpacing: adjustedCrossAxisSpacing,
          mainAxisSpacing: adjustedMainAxisSpacing,
          childAspectRatio: childAspectRatio,
        ),
        itemCount: children.length,
        itemBuilder: (context, index) => children[index],
      ),
    );
  }

  int _calculateCrossAxisCount(double width, bool isWindows) {
    if (isWindows) {
      // Windows平台通常有更大的显示器，可以显示更多列
      if (width >= 1600) return 4; // 超大屏幕
      if (width >= AppBreakpoints.large) return 3; // 大屏幕
      if (width >= AppBreakpoints.medium) return 2; // 中等屏幕
      return 1; // 小屏幕
    } else {
      // 其他平台的标准网格
      if (width >= AppBreakpoints.large) return 3;
      if (width >= AppBreakpoints.medium) return 2;
      return 1;
    }
  }

  double _getAdjustedSpacing(double baseSpacing, bool isWindows) {
    if (isWindows) {
      // Windows平台可能需要稍微大的间距
      return baseSpacing * 1.2;
    }
    return baseSpacing;
  }
}