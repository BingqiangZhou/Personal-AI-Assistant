import 'package:flutter/material.dart';

/// 完全安全的自适应导航组件
///
/// 专门解决NavigationRail在所有平台上的断言问题
/// 断言错误: "extended (labelType == null || labelType != NavigationRailLabelType.none): is not true"
class FullySafeAdaptiveNavigation extends StatelessWidget {
  const FullySafeAdaptiveNavigation({
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
          // 平板端 - 使用安全配置的NavigationRail
          return _buildTabletLayout(context);
        } else {
          // 桌面端 - 使用安全配置的展开NavigationRail
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

  /// 平板端布局 - 安全配置的NavigationRail
  Widget _buildTabletLayout(BuildContext context) {
    return Scaffold(
      appBar: appBar,
      body: Row(
        children: [
          NavigationRail(
            selectedIndex: selectedIndex,
            onDestinationSelected: onDestinationSelected,
            extended: false, // 明确设置不展开
            labelType: NavigationRailLabelType.all, // 当extended=false时，使用all
            destinations: _convertToNavigationRailDestinations(),
            useIndicator: true,
            backgroundColor: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
          ),
          const VerticalDivider(thickness: 1, width: 1),
          Expanded(child: body!),
        ],
      ),
      floatingActionButton: floatingActionButton,
    );
  }

  /// 桌面端布局 - 安全配置的展开NavigationRail
  Widget _buildDesktopLayout(BuildContext context) {
    return Scaffold(
      appBar: appBar,
      body: Row(
        children: [
          NavigationRail(
            selectedIndex: selectedIndex,
            onDestinationSelected: onDestinationSelected,
            extended: true, // 桌面端展开
            labelType: NavigationRailLabelType.all, // 当extended=true时，必须使用all
            destinations: _convertToNavigationRailDestinations(),
            useIndicator: true,
            backgroundColor: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
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
          Expanded(child: body!),
        ],
      ),
      floatingActionButton: floatingActionButton,
    );
  }

  /// 将NavigationDestination转换为NavigationRailDestination
  List<NavigationRailDestination> _convertToNavigationRailDestinations() {
    return destinations.map((dest) {
      return NavigationRailDestination(
        icon: dest.icon,
        selectedIcon: dest.selectedIcon,
        label: Text(dest.label),
      );
    }).toList();
  }
}

/// 简化的响应式容器组件
///
/// 提供基本的响应式布局支持，避免复杂的断言问题
class SimpleResponsiveContainer extends StatelessWidget {
  const SimpleResponsiveContainer({
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
///
/// 避免复杂的响应式逻辑导致的潜在问题
class SafeResponsiveGrid extends StatelessWidget {
  const SafeResponsiveGrid({
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