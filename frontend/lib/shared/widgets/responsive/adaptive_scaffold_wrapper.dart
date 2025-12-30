import 'package:flutter/material.dart';

/// AdaptiveScaffoldWrapper - 自适应脚手架包装器
/// 由于 flutter_adaptive_scaffold 已废弃，使用原生 Flutter 实现自适应布局
class AdaptiveScaffoldWrapper extends StatelessWidget {
  final Widget body;
  final List<NavigationDestination>? destinations;
  final int selectedIndex;
  final ValueChanged<int>? onDestinationSelected;
  final Widget? floatingActionButton;
  final PreferredSizeWidget? appBar;

  const AdaptiveScaffoldWrapper({
    super.key,
    required this.body,
    this.destinations,
    this.selectedIndex = 0,
    this.onDestinationSelected,
    this.floatingActionButton,
    this.appBar,
  });

  @override
  Widget build(BuildContext context) {
    // 如果没有导航目标，返回简单 Scaffold
    if (destinations == null) {
      return Scaffold(
        appBar: appBar,
        body: body,
        floatingActionButton: floatingActionButton,
      );
    }

    // 检查屏幕宽度以决定使用哪种布局
    final screenWidth = MediaQuery.of(context).size.width;
    final isWideScreen = screenWidth > 800;

    if (isWideScreen) {
      // 宽屏：使用 NavigationRail
      return Scaffold(
        appBar: appBar,
        body: Row(
          children: [
            NavigationRail(
              selectedIndex: selectedIndex,
              onDestinationSelected: onDestinationSelected,
              labelType: NavigationRailLabelType.all,
              destinations: destinations!
                  .map((dest) => NavigationRailDestination(
                        icon: dest.icon,
                        selectedIcon: dest.selectedIcon,
                        label: Text(dest.label),
                      ))
                  .toList(),
            ),
            const VerticalDivider(width: 1, thickness: 1),
            Expanded(child: body),
          ],
        ),
        floatingActionButton: floatingActionButton,
      );
    } else {
      // 窄屏：使用 BottomNavigationBar
      return Scaffold(
        appBar: appBar,
        body: body,
        floatingActionButton: floatingActionButton,
        bottomNavigationBar: BottomNavigationBar(
          currentIndex: selectedIndex,
          onTap: onDestinationSelected,
          type: BottomNavigationBarType.fixed,
          items: destinations!
              .map((dest) => BottomNavigationBarItem(
                    icon: dest.icon,
                    activeIcon: dest.selectedIcon,
                    label: dest.label,
                  ))
              .toList(),
        ),
      );
    }
  }
}
