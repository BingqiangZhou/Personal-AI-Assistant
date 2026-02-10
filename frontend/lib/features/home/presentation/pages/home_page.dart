import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../../podcast/presentation/pages/podcast_feed_page.dart';
import '../../../podcast/presentation/pages/podcast_list_page.dart';
import '../../../podcast/presentation/providers/podcast_providers.dart';
import '../../../podcast/presentation/widgets/podcast_bottom_player_widget.dart';
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

  @override
  void initState() {
    super.initState();
    _currentIndex = widget.initialTab ?? 0;
  }

  List<NavigationDestination> _buildDestinations(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return [
      NavigationDestination(
        icon: const Icon(Icons.home_outlined),
        selectedIcon: const Icon(Icons.home),
        label: l10n.nav_feed,
      ),
      NavigationDestination(
        icon: const Icon(Icons.podcasts_outlined),
        selectedIcon: const Icon(Icons.podcasts),
        label: l10n.nav_podcast,
      ),
      NavigationDestination(
        icon: const Icon(Icons.person_outline),
        selectedIcon: const Icon(Icons.person),
        label: l10n.nav_profile,
      ),
    ];
  }

  @override
  Widget build(BuildContext context) {
    if (widget.child != null) {
      return Scaffold(body: widget.child!);
    }

    return CustomAdaptiveNavigation(
      key: const ValueKey('home_custom_adaptive_navigation'),
      destinations: _buildDestinations(context),
      selectedIndex: _currentIndex,
      onDestinationSelected: _handleNavigation,
      appBar: null,
      floatingActionButton: _buildFloatingActionButton(),
      bottomAccessory: _buildBottomAccessory(),
      body: _buildTabContent(_currentIndex),
    );
  }

  Widget? _buildFloatingActionButton() {
    return null;
  }

  Widget? _buildBottomAccessory() {
    final isPodcastTab = _currentIndex == 0 || _currentIndex == 1;
    if (!isPodcastTab) {
      return null;
    }
    return const PodcastBottomPlayerWidget(applySafeArea: false);
  }

  void _handleNavigation(int index) {
    if (_currentIndex != index) {
      setState(() {
        _currentIndex = index;
      });
    }
  }

  Widget _buildTabContent(int index) {
    final content = _buildPageContent(index);

    // Watch global audio player state for expansion only
    final isExpanded = ref.watch(audioPlayerProvider.select((s) => s.isExpanded));

    // If expanded, wrap content with a barrier to detect outside taps
    if (isExpanded) {
      return Stack(
        children: [
          content,
          // Transparent barrier that covers the content behind the player
          Positioned.fill(
            child: GestureDetector(
              onTap: () {
                ref.read(audioPlayerProvider.notifier).setExpanded(false);
              },
              behavior: HitTestBehavior.opaque, // Opaque to catch all touches
              child: Container(
                color: Colors.black.withValues(alpha: 0.01), // Almost transparent but touchable
              ),
            ),
          ),
        ],
      );
    }

    return content;
  }

  Widget _buildPageContent(int index) {
    switch (index) {
      case 0:
        return const PodcastFeedPage();
      case 1:
        return const PodcastListPage();
      case 2:
        return const ProfilePage();
      default:
        return Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(Icons.error_outline, size: 64, color: Colors.grey),
              SizedBox(height: 16),
              Text(
                AppLocalizations.of(context)!.page_not_found,
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.w500,
                  color: Colors.grey,
                ),
              ),
              SizedBox(height: 8),
              Text(
                AppLocalizations.of(context)!.page_not_found_subtitle,
                style: TextStyle(fontSize: 14, color: Colors.grey),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        );
    }
  }
}
