import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../podcast/presentation/pages/podcast_feed_page.dart';
import '../../../podcast/presentation/pages/podcast_list_page.dart';
import '../../../podcast/presentation/widgets/audio_player_widget.dart';
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
  bool _isRailExtended = false;

  final List<NavigationDestination> _destinations = const [
    NavigationDestination(
      icon: Icon(Icons.home_outlined),
      selectedIcon: Icon(Icons.home),
      label: 'Feed',
    ),
    NavigationDestination(
      icon: Icon(Icons.feed_outlined),
      selectedIcon: Icon(Icons.feed),
      label: 'Podcast',
    ),
    NavigationDestination(
      icon: Icon(Icons.psychology_outlined),
      selectedIcon: Icon(Icons.psychology),
      label: 'AI Assistant',
    ),
    NavigationDestination(
      icon: Icon(Icons.folder_outlined),
      selectedIcon: Icon(Icons.folder),
      label: 'Knowledge',
    ),
    NavigationDestination(
      icon: Icon(Icons.person_outline),
      selectedIcon: Icon(Icons.person),
      label: 'Profile',
    ),
  ];

  @override
  void initState() {
    super.initState();
    _currentIndex = widget.initialTab ?? 0;
  }

  @override
  Widget build(BuildContext context) {
    if (widget.child != null) {
      return Scaffold(body: widget.child);
    }

    return Scaffold(
      body: Row(
        children: [
          NavigationRail(
            extended: _isRailExtended,
            selectedIndex: _currentIndex,
            onDestinationSelected: (index) => setState(() => _currentIndex = index),
            leading: IconButton(
              icon: Icon(_isRailExtended ? Icons.menu_open : Icons.menu),
              onPressed: () => setState(() => _isRailExtended = !_isRailExtended),
              tooltip: _isRailExtended ? 'Collapse menu' : 'Expand menu',
            ),
            destinations: _destinations.map((dest) {
              return NavigationRailDestination(
                icon: dest.icon,
                selectedIcon: dest.selectedIcon,
                label: Text(dest.label),
              );
            }).toList(),
          ),
          const VerticalDivider(thickness: 1, width: 1),
          Expanded(
            child: _buildCurrentTabContent(),
          ),
        ],
      ),
    );
  }

  Widget _buildCurrentTabContent() {
    switch (_currentIndex) {
      case 0:
        return const PodcastFeedPage();
      case 1:
        return const PodcastListPage();
      case 2:
        return const AssistantChatPage();
      case 3:
        return const KnowledgeBasePage();
      case 4:
        return const ProfilePage();
      default:
        return const Center(child: Text('Page Not Found'));
    }
  }
}