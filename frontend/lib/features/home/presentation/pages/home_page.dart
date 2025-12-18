import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/theme/app_theme.dart';
import '../widgets/bottom_navigation.dart';
import '../../../auth/presentation/providers/auth_provider.dart';

class HomePage extends ConsumerStatefulWidget {
  final Widget? child;

  const HomePage({super.key, this.child});

  @override
  ConsumerState<HomePage> createState() => _HomePageState();
}

class _HomePageState extends ConsumerState<HomePage> {
  int _currentIndex = 0;

  final List<NavigationItem> _navigationItems = [
    NavigationItem(
      icon: Icons.home_outlined,
      activeIcon: Icons.home,
      label: 'Home',
      route: '/home',
    ),
    NavigationItem(
      icon: Icons.feed_outlined,
      activeIcon: Icons.feed,
      label: 'Podcast',
      route: '/podcast',
    ),
    NavigationItem(
      icon: Icons.psychology_outlined,
      activeIcon: Icons.psychology,
      label: 'AI Assistant',
      route: '/home/assistant',
    ),
    NavigationItem(
      icon: Icons.folder_outlined,
      activeIcon: Icons.folder,
      label: 'Knowledge',
      route: '/knowledge',
    ),
    NavigationItem(
      icon: Icons.person_outline,
      activeIcon: Icons.person,
      label: 'Profile',
      route: '/profile',
    ),
  ];

  void _onItemTapped(int index) {
    setState(() {
      _currentIndex = index;
    });

    final item = _navigationItems[index];
    if (widget.child == null) {
      context.go(item.route);
    }
  }

  @override
  Widget build(BuildContext context) {
    final authState = ref.watch(authProvider);
    final user = authState.user;

    return Scaffold(
      appBar: AppBar(
        title: Text(
          _navigationItems[_currentIndex].label,
          style: Theme.of(context).textTheme.titleLarge?.copyWith(
            fontWeight: FontWeight.w600,
          ),
        ),
        actions: [
          if (user != null) ...[
            IconButton(
              icon: const Icon(Icons.notifications_outlined),
              onPressed: () {
                // TODO: Show notifications
              },
            ),
            PopupMenuButton<String>(
              icon: CircleAvatar(
                backgroundImage: user.avatarUrl != null ? NetworkImage(user.avatarUrl!) : null,
                child: user.avatarUrl == null ? Text(user.displayName[0].toUpperCase()) : null,
              ),
              itemBuilder: (context) => [
                PopupMenuItem(
                  value: 'profile',
                  child: Row(
                    children: [
                      const Icon(Icons.person),
                      const SizedBox(width: 8),
                      Text(user.displayName),
                    ],
                  ),
                ),
                const PopupMenuDivider(),
                PopupMenuItem(
                  value: 'settings',
                  child: Row(
                    children: const [
                      Icon(Icons.settings),
                      SizedBox(width: 8),
                      Text('Settings'),
                    ],
                  ),
                ),
                PopupMenuItem(
                  value: 'logout',
                  child: Row(
                    children: const [
                      Icon(Icons.logout),
                      SizedBox(width: 8),
                      Text('Logout'),
                    ],
                  ),
                ),
              ],
              onSelected: (value) {
                switch (value) {
                  case 'profile':
                    context.go('/profile');
                    break;
                  case 'settings':
                    context.go('/profile/settings');
                    break;
                  case 'logout':
                    ref.read(authProvider.notifier).logout();
                    break;
                }
              },
            ),
          ],
        ],
      ),

      body: widget.child ??
          IndexedStack(
            index: _currentIndex,
            children: _navigationItems.map((item) {
              return Navigator(
                onGenerateRoute: (settings) {
                  return MaterialPageRoute(
                    builder: (context) => _buildPage(item.route),
                  );
                },
              );
            }).toList(),
          ),

      bottomNavigationBar: widget.child == null
          ? BottomNavigation(
              items: _navigationItems,
              currentIndex: _currentIndex,
              onTap: _onItemTapped,
            )
          : null,
    );
  }

  Widget _buildPage(String route) {
    // This is a placeholder for actual page content
    // In a real app, you would use a proper navigation setup
    switch (route) {
      case '/home':
        return const Center(
          child: Text('Home Page'),
        );
      case '/home/assistant':
        return const Center(
          child: Text('AI Assistant Page'),
        );
      default:
        return const Center(
          child: Text('Page'),
        );
    }
  }
}

class NavigationItem {
  final IconData icon;
  final IconData activeIcon;
  final String label;
  final String route;

  NavigationItem({
    required this.icon,
    required this.activeIcon,
    required this.label,
    required this.route,
  });
}