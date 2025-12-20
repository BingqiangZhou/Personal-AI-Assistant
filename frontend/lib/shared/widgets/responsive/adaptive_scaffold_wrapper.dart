import 'package:flutter/material.dart';
import 'package:flutter_adaptive_scaffold/flutter_adaptive_scaffold.dart';

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
    if (destinations == null) {
      return Scaffold(
        appBar: appBar,
        body: body,
        floatingActionButton: floatingActionButton,
      );
    }

    return AdaptiveScaffold(
      selectedIndex: selectedIndex,
      onSelectedIndexChange: onDestinationSelected,
      destinations: destinations!
          .map((dest) => NavigationDestination(
                icon: dest.icon,
                selectedIcon: dest.selectedIcon,
                label: dest.label,
              ))
          .toList(),
      body: (_) => body,
      smallBody: (_) => Scaffold(
        appBar: appBar,
        body: body,
        floatingActionButton: floatingActionButton,
      ),
    );
  }
}
