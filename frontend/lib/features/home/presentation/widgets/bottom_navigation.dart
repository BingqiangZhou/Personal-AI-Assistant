import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Navigation item data model for bottom navigation bar
class NavigationItem {
  final IconData icon;
  final IconData? activeIcon;
  final String label;

  const NavigationItem({
    required this.icon,
    this.activeIcon,
    required this.label,
  });
}

class BottomNavigation extends ConsumerWidget {
  final List<NavigationItem> items;
  final int currentIndex;
  final Function(int) onTap;

  const BottomNavigation({
    super.key,
    required this.items,
    required this.currentIndex,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Container(
      decoration: BoxDecoration(
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.1),
            blurRadius: 10,
            offset: const Offset(0, -2),
          ),
        ],
      ),
      child: BottomNavigationBar(
        currentIndex: currentIndex,
        onTap: onTap,
        type: BottomNavigationBarType.fixed,
        backgroundColor: Theme.of(context).colorScheme.surface,
        selectedItemColor: Theme.of(context).colorScheme.primary,
        unselectedItemColor: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.6),
        elevation: 8,
        items: items.map((item) {
          return BottomNavigationBarItem(
            icon: Icon(
              item.icon,
              size: 24,
            ),
            activeIcon: Icon(
              item.activeIcon,
              size: 24,
            ),
            label: item.label,
          );
        }).toList(),
      ),
    );
  }
}