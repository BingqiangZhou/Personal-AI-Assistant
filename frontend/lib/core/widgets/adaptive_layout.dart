import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../constants/breakpoints.dart';

/// 自适应页面基类
///
/// 提供统一的响应式布局接口，子类需要实现不同屏幕尺寸下的布局构建方法
abstract class AdaptivePage extends ConsumerWidget {
  const AdaptivePage({super.key});

  /// 构建移动端布局（< 600dp）
  Widget buildMobileLayout(BuildContext context, WidgetRef ref);

  /// 构建平板端布局（600-840dp）
  Widget buildTabletLayout(BuildContext context, WidgetRef ref);

  /// 构建桌面端布局（> 840dp）
  Widget buildDesktopLayout(BuildContext context, WidgetRef ref);

  /// 默认使用移动端布局
  Widget buildDefaultLayout(BuildContext context, WidgetRef ref) {
    return buildMobileLayout(context, ref);
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final screenWidth = MediaQuery.of(context).size.width;

    if (screenWidth < AppBreakpoints.medium) {
      return buildMobileLayout(context, ref);
    } else if (screenWidth < AppBreakpoints.mediumLarge) {
      return buildTabletLayout(context, ref);
    } else {
      return buildDesktopLayout(context, ref);
    }
  }
}

/// 自适应脚手架包装器
///
/// 提供Material Design 3自适应导航和布局功能
class AdaptiveScaffoldWrapper extends StatelessWidget {
  const AdaptiveScaffoldWrapper({
    super.key,
    required this.destinations,
    required this.body,
    this.selectedIndex = 0,
    this.onDestinationSelected,
    this.floatingActionButton,
    this.appBar,
    this.animationDuration = const Duration(milliseconds: 300),
  });

  /// 导航目的地列表
  final List<NavigationDestination> destinations;

  /// 页面主体内容
  final Widget Function(BuildContext context, int index) body;

  /// 当前选中的导航索引
  final int selectedIndex;

  /// 导航选择回调
  final ValueChanged<int>? onDestinationSelected;

  /// 浮动操作按钮
  final Widget? floatingActionButton;

  /// 应用栏
  final PreferredSizeWidget? appBar;

  /// 动画时长
  final Duration animationDuration;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final width = constraints.maxWidth;

        // 根据屏幕宽度返回不同的布局
        if (width < AppBreakpoints.medium) {
          // 移动端 - 底部导航栏
          return Scaffold(
            appBar: appBar,
            body: body(context, selectedIndex),
            floatingActionButton: floatingActionButton,
            bottomNavigationBar: NavigationBar(
              selectedIndex: selectedIndex,
              onDestinationSelected: onDestinationSelected,
              destinations: destinations,
            ),
          );
        } else {
          // 桌面端 - 侧边导航栏
          return Scaffold(
            appBar: appBar,
            body: Row(
              children: [
                NavigationRail(
                  selectedIndex: selectedIndex,
                  onDestinationSelected: onDestinationSelected,
                  extended: width >= AppBreakpoints.large,
                  destinations: destinations
                      .map((dest) => NavigationRailDestination(
                            icon: dest.icon,
                            selectedIcon: dest.selectedIcon,
                            label: Text(dest.label),
                          ))
                      .toList(),
                  // 修复NavigationRail断言错误：当extended=true时，labelType不能是none
                  // 根据Flutter文档，extended=true时必须显示标签
                  labelType: width >= AppBreakpoints.large
                      ? NavigationRailLabelType.all
                      : NavigationRailLabelType.selected,
                ),
                const VerticalDivider(thickness: 1, width: 1),
                Expanded(child: body(context, selectedIndex)),
              ],
            ),
            floatingActionButton: floatingActionButton,
          );
        }
      },
    );
  }
}

/// 自适应容器组件
///
/// 根据屏幕尺寸提供不同的布局约束和边距
class AdaptiveContainer extends StatelessWidget {
  const AdaptiveContainer({
    super.key,
    required this.child,
    this.maxWidth,
    this.padding,
    this.margin,
    this.alignment,
    this.color,
    this.decoration,
    this.foregroundDecoration,
    this.clipBehavior = Clip.none,
  });

  final Widget child;
  final double? maxWidth;
  final EdgeInsetsGeometry? padding;
  final EdgeInsetsGeometry? margin;
  final AlignmentGeometry? alignment;
  final Color? color;
  final Decoration? decoration;
  final Decoration? foregroundDecoration;
  final Clip clipBehavior;

  @override
  Widget build(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;

    // 默认最大宽度约束
    final effectiveMaxWidth = maxWidth ?? (screenWidth < AppBreakpoints.medium
        ? screenWidth
        : AppBreakpoints.large);

    // 默认内边距
    final effectivePadding = padding ?? EdgeInsets.symmetric(
      horizontal: screenWidth < AppBreakpoints.medium ? 16.0 : 24.0,
      vertical: screenWidth < AppBreakpoints.medium ? 8.0 : 16.0,
    );

    return Container(
      alignment: alignment,
      color: color,
      decoration: decoration,
      foregroundDecoration: foregroundDecoration,
      clipBehavior: clipBehavior,
      margin: margin,
      child: ConstrainedBox(
        constraints: BoxConstraints(
          maxWidth: effectiveMaxWidth,
          minHeight: 0,
        ),
        child: Padding(
          padding: effectivePadding,
          child: child,
        ),
      ),
    );
  }
}

/// 响应式网格组件
///
/// 根据屏幕尺寸自动调整列数
class ResponsiveGrid extends StatelessWidget {
  const ResponsiveGrid({
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

    // 根据屏幕尺寸确定网格列数
    int crossAxisCount;
    if (screenWidth < AppBreakpoints.medium) {
      crossAxisCount = 1; // 移动端单列
    } else if (screenWidth < AppBreakpoints.mediumLarge) {
      crossAxisCount = 2; // 平板端双列
    } else if (screenWidth < AppBreakpoints.large) {
      crossAxisCount = 3; // 小桌面三列
    } else {
      crossAxisCount = 4; // 大桌面四列
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