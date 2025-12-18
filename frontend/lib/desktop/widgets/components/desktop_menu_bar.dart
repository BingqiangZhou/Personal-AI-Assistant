import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/constants/app_constants.dart';

class DesktopMenuBar extends ConsumerWidget implements PreferredSizeWidget {
  const DesktopMenuBar({
    super.key,
    this.title,
    this.currentRoute,
    this.actions,
    this.onMenuPressed,
  });

  final String? title;
  final String? currentRoute;
  final List<Widget>? actions;
  final VoidCallback? onMenuPressed;

  @override
  Size get preferredSize => const Size.fromHeight(64);

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return AppBar(
      title: Row(
        children: [
          // Menu button for smaller screens
          if (MediaQuery.of(context).size.width <= 1200)
            IconButton(
              onPressed: onMenuPressed,
              icon: const Icon(Icons.menu),
              tooltip: 'Menu',
            ),

          if (title != null) ...[
            if (MediaQuery.of(context).size.width <= 1200)
              const SizedBox(width: 16),
            Text(
              title!,
              style: Theme.of(context).textTheme.titleLarge?.copyWith(
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ],
      ),
      centerTitle: false,
      elevation: 1,
      backgroundColor: Theme.of(context).colorScheme.surface,
      surfaceTintColor: Theme.of(context).colorScheme.primary,
      actions: [
        ...?actions,
        _buildSearchButton(context),
        _buildNotificationButton(context),
        _buildUserMenu(context),
        const SizedBox(width: 8),
      ],
      titleSpacing: 16,
      toolbarHeight: 64,
    );
  }

  Widget _buildSearchButton(BuildContext context) {
    return IconButton(
      onPressed: () {
        _showSearchDialog(context);
      },
      icon: const Icon(Icons.search_outlined),
      tooltip: 'Search (Ctrl+K)',
    );
  }

  Widget _buildNotificationButton(BuildContext context) {
    return Stack(
      children: [
        IconButton(
          onPressed: () {
            _showNotifications(context);
          },
          icon: const Icon(Icons.notifications_outlined),
          tooltip: 'Notifications',
        ),
        // Notification badge
        Positioned(
          right: 8,
          top: 8,
          child: Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.error,
              shape: BoxShape.circle,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildUserMenu(BuildContext context) {
    return PopupMenuButton<String>(
      icon: CircleAvatar(
        radius: 16,
        backgroundColor: Theme.of(context).colorScheme.primary,
        child: const Icon(
          Icons.person,
          color: Colors.white,
          size: 20,
        ),
      ),
      itemBuilder: (context) => [
        PopupMenuItem(
          enabled: false,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'John Doe', // Should come from user state
                style: Theme.of(context).textTheme.titleSmall?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
              ),
              Text(
                'john.doe@example.com', // Should come from user state
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ),
        ),
        const PopupMenuDivider(),
        const PopupMenuItem(
          value: 'profile',
          child: Row(
            children: [
              Icon(Icons.person_outline),
              SizedBox(width: 12),
              Text('Profile'),
            ],
          ),
        ),
        const PopupMenuItem(
          value: 'settings',
          child: Row(
            children: [
              Icon(Icons.settings_outlined),
              SizedBox(width: 12),
              Text('Settings'),
            ],
          ),
        ),
        const PopupMenuItem(
          value: 'help',
          child: Row(
            children: [
              Icon(Icons.help_outline),
              SizedBox(width: 12),
              Text('Help & Support'),
            ],
          ),
        ),
        const PopupMenuDivider(),
        const PopupMenuItem(
          value: 'about',
          child: Row(
            children: [
              Icon(Icons.info_outline),
              SizedBox(width: 12),
              Text('About'),
            ],
          ),
        ),
        const PopupMenuItem(
          value: 'logout',
          child: Row(
            children: [
              Icon(Icons.logout_outlined),
              SizedBox(width: 12),
              Text('Logout'),
            ],
          ),
        ),
      ],
      onSelected: (value) {
        _handleUserMenuSelection(context, value);
      },
    );
  }

  void _showSearchDialog(BuildContext context) {
    showSearch(
      context: context,
      delegate: CustomSearchDelegate(),
    );
  }

  void _showNotifications(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => const NotificationsDialog(),
    );
  }

  void _handleUserMenuSelection(BuildContext context, String value) {
    switch (value) {
      case 'profile':
        context.go('/profile');
        break;
      case 'settings':
        context.go('/settings');
        break;
      case 'help':
        _showHelpDialog(context);
        break;
      case 'about':
        _showAboutDialog(context);
        break;
      case 'logout':
        _handleLogout(context);
        break;
    }
  }

  void _showHelpDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Help & Support'),
        content: const Text(
          'For help and support, please contact our support team at support@example.com',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  void _showAboutDialog(BuildContext context) {
    showAboutDialog(
      context: context,
      applicationName: AppConstants.appName,
      applicationVersion: AppConstants.appVersion,
      applicationIcon: const Icon(Icons.smart_toy, size: 48),
      children: [
        const Text('Personal AI Assistant - Your intelligent companion for knowledge management and AI-powered assistance.'),
      ],
    );
  }

  void _handleLogout(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Logout'),
        content: const Text('Are you sure you want to logout?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () {
              Navigator.of(context).pop();
              // Handle logout
              context.go('/login');
            },
            child: const Text('Logout'),
          ),
        ],
      ),
    );
  }
}

class CustomSearchDelegate extends SearchDelegate<String> {
  @override
  List<Widget>? buildActions(BuildContext context) {
    return [
      IconButton(
        onPressed: () {
          query = '';
        },
        icon: const Icon(Icons.clear),
      ),
    ];
  }

  @override
  Widget? buildLeading(BuildContext context) {
    return IconButton(
      onPressed: () {
        close(context, '');
      },
      icon: const Icon(Icons.arrow_back),
    );
  }

  @override
  Widget buildResults(BuildContext context) {
    // Implement search results
    return const Center(
      child: Text('Search results will appear here'),
    );
  }

  @override
  Widget buildSuggestions(BuildContext context) {
    // Implement search suggestions
    final suggestions = [
      'AI Assistant',
      'Knowledge Base',
      'Recent conversations',
      'Settings',
    ];

    return ListView.builder(
      itemCount: suggestions.length,
      itemBuilder: (context, index) {
        final suggestion = suggestions[index];
        return ListTile(
          leading: const Icon(Icons.search),
          title: Text(suggestion),
          onTap: () {
            query = suggestion;
            showResults(context);
          },
        );
      },
    );
  }
}

class NotificationsDialog extends StatelessWidget {
  const NotificationsDialog({super.key});

  @override
  Widget build(BuildContext context) {
    return Dialog(
      child: Container(
        width: 400,
        height: 500,
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  'Notifications',
                  style: Theme.of(context).textTheme.titleLarge,
                ),
                IconButton(
                  onPressed: () => Navigator.of(context).pop(),
                  icon: const Icon(Icons.close),
                ),
              ],
            ),
            const Divider(),
            const Expanded(
              child: Center(
                child: Text('No new notifications'),
              ),
            ),
          ],
        ),
      ),
    );
  }
}