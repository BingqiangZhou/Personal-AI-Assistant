import 'package:flutter/material.dart';

class DesktopLayout extends StatelessWidget {
  const DesktopLayout({
    super.key,
    required this.child,
    required this.screenWidth,
  });

  final Widget child;
  final double screenWidth;

  @override
  Widget build(BuildContext context) {
    // Desktop-specific layout configurations
    return LayoutBuilder(
      builder: (context, constraints) {
        return Scaffold(
          body: _buildResponsiveLayout(context, constraints),
        );
      },
    );
  }

  Widget _buildResponsiveLayout(BuildContext context, BoxConstraints constraints) {
    // Define breakpoints for desktop
    const desktopBreakpoint = 1200.0;
    const tabletBreakpoint = 800.0;

    if (constraints.maxWidth >= desktopBreakpoint) {
      return _buildDesktopLayout(context);
    } else if (constraints.maxWidth >= tabletBreakpoint) {
      return _buildTabletLayout(context);
    } else {
      return _buildCompactLayout(context);
    }
  }

  Widget _buildDesktopLayout(BuildContext context) {
    return Row(
      children: [
        // Fixed sidebar for desktop
        const SizedBox(
          width: 280,
          child: _DesktopSideBar(),
        ),

        // Main content with scrollbar
        Expanded(
          child: Scrollbar(
            thumbVisibility: true,
            thickness: 8,
            radius: const Radius.circular(4),
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: ConstrainedBox(
                constraints: const BoxConstraints(
                  minHeight: 1000, // Minimum height for desktop
                ),
                child: child,
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildTabletLayout(BuildContext context) {
    return child;
  }

  Widget _buildCompactLayout(BuildContext context) {
    return child;
  }
}

class _DesktopSideBar extends StatelessWidget {
  const _DesktopSideBar();

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border(
          right: BorderSide(
            color: Theme.of(context).dividerColor,
            width: 1,
          ),
        ),
      ),
      child: Column(
        children: [
          // App header
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.primaryContainer,
            ),
            child: Row(
              children: [
                Icon(
                  Icons.smart_toy,
                  color: Theme.of(context).colorScheme.onPrimaryContainer,
                  size: 32,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'Personal AI Assistant',
                    style: Theme.of(context).textTheme.titleLarge?.copyWith(
                      color: Theme.of(context).colorScheme.onPrimaryContainer,
                      fontWeight: FontWeight.bold,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
          ),

          // Navigation items
          const Expanded(
            child: _NavigationItems(),
          ),

          // User profile section
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              border: Border(
                top: BorderSide(
                  color: Theme.of(context).dividerColor,
                  width: 1,
                ),
              ),
            ),
            child: const _UserProfileSection(),
          ),
        ],
      ),
    );
  }
}

class _NavigationItems extends StatelessWidget {
  const _NavigationItems();

  @override
  Widget build(BuildContext context) {
    final navigationItems = [
      {'icon': Icons.chat, 'label': 'AI Assistant', 'route': '/chat'},
      {'icon': Icons.library_books, 'label': 'Knowledge Base', 'route': '/knowledge'},
      {'icon': Icons.rss_feed, 'label': 'Subscriptions', 'route': '/subscriptions'},
      {'icon': Icons.settings, 'label': 'Settings', 'route': '/settings'},
    ];

    return ListView.builder(
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: navigationItems.length,
      itemBuilder: (context, index) {
        final item = navigationItems[index];
        final isSelected = false; // This should be managed by state

        return _NavigationTile(
          icon: item['icon'] as IconData,
          label: item['label'] as String,
          route: item['route'] as String,
          isSelected: isSelected,
        );
      },
    );
  }
}

class _NavigationTile extends StatelessWidget {
  const _NavigationTile({
    required this.icon,
    required this.label,
    required this.route,
    this.isSelected = false,
  });

  final IconData icon;
  final String label;
  final String route;
  final bool isSelected;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      child: Material(
        color: isSelected
            ? Theme.of(context).colorScheme.primaryContainer
            : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
        child: InkWell(
          onTap: () {
            // Navigate to route
          },
          borderRadius: BorderRadius.circular(8),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            child: Row(
              children: [
                Icon(
                  icon,
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
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _UserProfileSection extends StatelessWidget {
  const _UserProfileSection();

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        CircleAvatar(
          backgroundColor: Theme.of(context).colorScheme.primary,
          child: const Icon(
            Icons.person,
            color: Colors.white,
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'User Name', // This should come from user state
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
                overflow: TextOverflow.ellipsis,
              ),
              Text(
                'user@example.com', // This should come from user state
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
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
          ),
          itemBuilder: (context) => [
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
              value: 'settings',
              child: Row(
                children: [
                  Icon(Icons.settings_outlined),
                  SizedBox(width: 8),
                  Text('Settings'),
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
            // Handle menu selection
          },
        ),
      ],
    );
  }
}