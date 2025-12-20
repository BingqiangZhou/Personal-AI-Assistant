import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../widgets/bottom_navigation.dart';
import '../../../auth/presentation/providers/auth_provider.dart';
import '../../../podcast/presentation/pages/podcast_feed_page.dart';
import '../../../podcast/presentation/pages/podcast_list_page.dart';
import '../../../assistant/presentation/pages/assistant_chat_page.dart';
import '../../../knowledge/presentation/pages/knowledge_base_page.dart';
import '../../../profile/presentation/pages/profile_page.dart';

class HomePage extends ConsumerStatefulWidget {
  final Widget? child;
  final int? initialTab;

  const HomePage({super.key, this.child, this.initialTab});

  @override
  ConsumerState<HomePage> createState() => _HomePageState();
}

class _HomePageState extends ConsumerState<HomePage> {
  late int _currentIndex;

  final List<NavigationItem> _navigationItems = [
    NavigationItem(
      icon: Icons.home_outlined,
      activeIcon: Icons.home,
      label: 'Feed',
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

  @override
  void initState() {
    super.initState();
    _currentIndex = widget.initialTab ?? 0;
  }

  void _onItemTapped(int index) {
    setState(() {
      _currentIndex = index;
    });
    // 现在我们使用_buildCurrentTabContent()来显示内容，不需要Go Router导航
  }

  @override
  Widget build(BuildContext context) {
    final authState = ref.watch(authProvider);
    final user = authState.user;

    // 如果使用ShellRoute（有child），则不显示底部导航
    // 如果使用Tab导航（无child），则显示底部导航
    if (widget.child != null) {
      return Scaffold(body: widget.child);
    }

    return Scaffold(
      body: _buildCurrentTabContent(),
      bottomNavigationBar: BottomNavigation(
        items: _navigationItems,
        currentIndex: _currentIndex,
        onTap: _onItemTapped,
      ),
    );
  }

  Widget _buildCurrentTabContent() {
    switch (_currentIndex) {
      case 0: // Feed
        return const PodcastFeedPage();
      case 1: // Podcast
        return const PodcastListPage();
      case 2: // AI Assistant
        return const AssistantChatPage();
      case 3: // Knowledge Base
        return const KnowledgeBasePage();
      case 4: // Profile
        return const ProfilePage();
      default:
        return const Center(child: Text('Page Not Found'));
    }
  }

  Widget _buildPage(String route) {
    switch (route) {
      case '/home':
        return const PodcastFeedPage(); // Feed
      case '/podcast':
        return const PodcastListPage(); // Podcast List
      case '/home/assistant':
        return const AssistantChatPage(); // AI Assistant
      case '/knowledge':
        return const KnowledgeBasePage(); // Knowledge Base
      case '/profile':
        return const ProfilePage(); // Profile
      default:
        return const Center(
          child: Text('Page Not Found'),
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