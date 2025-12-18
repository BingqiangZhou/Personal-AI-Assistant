import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/constants/app_constants.dart';

class DesktopSideNavigation extends ConsumerWidget {
  const DesktopSideNavigation({
    super.key,
    this.width = 280,
    this.currentRoute,
  });

  final double width;
  final String? currentRoute;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Container(
      width: width,
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border(
          right: BorderSide(
            color: Theme.of(context).dividerColor.withOpacity(0.2),
            width: 1,
          ),
        ),
      ),
      child: Column(
        children: [
          // App header
          _buildAppHeader(context),

          // Navigation items
          Expanded(
            child: _buildNavigationItems(context),
          ),

          // Bottom section with user info
          _buildBottomSection(context),
        ],
      ),
    );
  }

  Widget _buildAppHeader(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.primaryContainer.withOpacity(0.3),
        border: Border(
          bottom: BorderSide(
            color: Theme.of(context).dividerColor.withOpacity(0.2),
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.primary,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(
              Icons.smart_toy,
              color: Theme.of(context).colorScheme.onPrimary,
              size: 24,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  AppConstants.appName,
                  style: Theme.of(context).textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.onPrimaryContainer,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
                Text(
                  'Desktop Version',
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.onPrimaryContainer.withOpacity(0.7),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildNavigationItems(BuildContext context) {
    final navigationItems = [
      NavigationItem(
        icon: Icons.chat_outlined,
        selectedIcon: Icons.chat,
        label: 'AI Assistant',
        route: '/chat',
        shortcut: 'Ctrl+1',
      ),
      NavigationItem(
        icon: Icons.library_books_outlined,
        selectedIcon: Icons.library_books,
        label: 'Knowledge Base',
        route: '/knowledge',
        shortcut: 'Ctrl+2',
      ),
      NavigationItem(
        icon: Icons.rss_feed_outlined,
        selectedIcon: Icons.rss_feed,
        label: 'Subscriptions',
        route: '/subscriptions',
        shortcut: 'Ctrl+3',
      ),
      const NavigationItemDivider(),
      NavigationItem(
        icon: Icons.analytics_outlined,
        selectedIcon: Icons.analytics,
        label: 'Analytics',
        route: '/analytics',
        shortcut: 'Ctrl+4',
      ),
      NavigationItem(
        icon: Icons.history_outlined,
        selectedIcon: Icons.history,
        label: 'History',
        route: '/history',
        shortcut: 'Ctrl+5',
      ),
      const NavigationItemDivider(),
      NavigationItem(
        icon: Icons.settings_outlined,
        selectedIcon: Icons.settings,
        label: 'Settings',
        route: '/settings',
        shortcut: 'Ctrl+,',
      ),
    ];

    return ListView(
      padding: const EdgeInsets.symmetric(vertical: 8),
      children: navigationItems.map((item) {
        if (item is NavigationItemDivider) {
          return const Divider(
            height: 1,
            indent: 16,
            endIndent: 16,
          );
        }

        final isSelected = currentRoute == item.route;

        return NavigationTile(
          icon: item.icon,
          selectedIcon: item.selectedIcon,
          label: item.label,
          route: item.route,
          shortcut: item.shortcut,
          isSelected: isSelected,
        );
      }).toList(),
    );
  }

  Widget _buildBottomSection(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceVariant.withOpacity(0.3),
        border: Border(
          top: BorderSide(
            color: Theme.of(context).dividerColor.withOpacity(0.2),
            width: 1,
          ),
        ),
      ),
      child: const UserProfileTile(),
    );
  }
}

class NavigationItem {
  final IconData icon;
  final IconData selectedIcon;
  final String label;
  final String route;
  final String shortcut;

  const NavigationItem({
    required this.icon,
    required this.selectedIcon,
    required this.label,
    required this.route,
    required this.shortcut,
  });
}

class NavigationItemDivider extends NavigationItem {
  const NavigationItemDivider()
      : super(
          icon: Icons.minimize,
          selectedIcon: Icons.minimize,
          label: '',
          route: '',
          shortcut: '',
        );
}

class NavigationTile extends StatelessWidget {
  const NavigationTile({
    super.key,
    required this.icon,
    required this.selectedIcon,
    required this.label,
    required this.route,
    required this.shortcut,
    this.isSelected = false,
  });

  final IconData icon;
  final IconData selectedIcon;
  final String label;
  final String route;
  final String shortcut;
  final bool isSelected;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 2),
      decoration: BoxDecoration(
        color: isSelected
            ? Theme.of(context).colorScheme.primaryContainer
            : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: () {
            if (context.mounted) {
              context.go(route);
            }
          },
          borderRadius: BorderRadius.circular(8),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            child: Row(
              children: [
                Icon(
                  isSelected ? selectedIcon : icon,
                  color: isSelected
                      ? Theme.of(context).colorScheme.onPrimaryContainer
                      : Theme.of(context).colorScheme.onSurface,
                  size: 24,
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Text(
                    label,
                    style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                      color: isSelected
                          ? Theme.of(context).colorScheme.onPrimaryContainer
                          : Theme.of(context).colorScheme.onSurface,
                      fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                    ),
                  ),
                ),
                Text(
                  shortcut,
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class UserProfileTile extends ConsumerWidget {
  const UserProfileTile({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Row(
      children: [
        CircleAvatar(
          radius: 20,
          backgroundColor: Theme.of(context).colorScheme.primary,
          child: const Icon(
            Icons.person,
            color: Colors.white,
            size: 24,
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'John Doe', // This should come from user state
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
                overflow: TextOverflow.ellipsis,
              ),
              Text(
                'Online', // This should come from user state
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
              value: 'status',
              child: Row(
                children: [
                  Icon(Icons.circle, color: Colors.green, size: 12),
                  SizedBox(width: 8),
                  Text('Online'),
                ],
              ),
            ),
            const PopupMenuItem(
              value: 'away',
              child: Row(
                children: [
                  Icon(Icons.circle, color: Colors.orange, size: 12),
                  SizedBox(width: 8),
                  Text('Away'),
                ],
              ),
            ),
            const PopupMenuItem(
              value: 'busy',
              child: Row(
                children: [
                  Icon(Icons.circle, color: Colors.red, size: 12),
                  SizedBox(width: 8),
                  Text('Busy'),
                ],
              ),
            ),
            const PopupMenuDivider(),
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
              value: 'logout',
              child: Row(
                children: [
                  Icon(Icons.logout_outlined),
                  SizedBox(width: 8),
                  Text('Logout'),
                ],
              ),
            ),
          ],
          onSelected: (value) {
            _handleMenuSelection(context, value);
          },
        ),
      ],
    );
  }

  void _handleMenuSelection(BuildContext context, String value) {
    switch (value) {
      case 'status':
      case 'away':
      case 'busy':
        // Update user status
        break;
      case 'profile':
        context.go('/profile');
        break;
      case 'logout':
        // Handle logout
        context.go('/login');
        break;
    }
  }
}