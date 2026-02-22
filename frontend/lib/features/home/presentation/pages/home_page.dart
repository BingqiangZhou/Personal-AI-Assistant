import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../../auth/presentation/providers/auth_provider.dart';
import '../../../podcast/presentation/pages/podcast_feed_page.dart';
import '../../../podcast/presentation/pages/podcast_list_page.dart';
import '../../../podcast/presentation/constants/podcast_ui_constants.dart';
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
  static const int _tabCount = 3;

  late int _currentIndex;
  bool _hasAttemptedPlaybackRestore = false;
  bool _desktopNavExpanded = true;
  bool _hasPrefetchedLibraryFeed = false;
  final Set<int> _visitedTabs = <int>{};

  @override
  void initState() {
    super.initState();
    _currentIndex = (widget.initialTab ?? 0).clamp(0, _tabCount - 1) as int;
    _visitedTabs.add(_currentIndex);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;

      _restoreMiniPlayerOnHomeEnter();
      _prefetchLibraryFeedOnHomeEnter();

      final audioState = ref.read(audioPlayerProvider);
      if (!_isPodcastTab(_currentIndex) && audioState.isExpanded) {
        ref.read(audioPlayerProvider.notifier).setExpanded(false);
      }
    });
  }

  void _restoreMiniPlayerOnHomeEnter() {
    if (_hasAttemptedPlaybackRestore) {
      return;
    }

    _hasAttemptedPlaybackRestore = true;
    unawaited(
      ref.read(audioPlayerProvider.notifier).restoreLastPlayedEpisodeIfNeeded(),
    );
  }

  void _prefetchLibraryFeedOnHomeEnter() {
    if (_hasPrefetchedLibraryFeed) {
      return;
    }
    _hasPrefetchedLibraryFeed = true;

    final authState = ref.read(authProvider);
    if (!authState.isAuthenticated) {
      return;
    }

    final feedState = ref.read(podcastFeedProvider);
    if (feedState.episodes.isNotEmpty && feedState.isDataFresh()) {
      return;
    }

    unawaited(
      ref.read(podcastFeedProvider.notifier).loadInitialFeed(background: true),
    );
  }

  bool _isPodcastTab(int index) => index == 0 || index == 1;

  List<NavigationDestination> _buildDestinations(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return [
      NavigationDestination(
        icon: const Icon(Icons.travel_explore_outlined),
        selectedIcon: const Icon(Icons.travel_explore),
        label: l10n.nav_podcast,
      ),
      NavigationDestination(
        icon: const Icon(Icons.library_books_outlined),
        selectedIcon: const Icon(Icons.library_books),
        label: l10n.nav_feed,
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

    final hasCurrentEpisode = ref.watch(
      audioPlayerProvider.select((s) => s.currentEpisode != null),
    );
    final isExpanded = ref.watch(
      audioPlayerProvider.select((s) => s.isExpanded),
    );

    return CustomAdaptiveNavigation(
      key: const ValueKey('home_custom_adaptive_navigation'),
      destinations: _buildDestinations(context),
      selectedIndex: _currentIndex,
      onDestinationSelected: _handleNavigation,
      appBar: null,
      floatingActionButton: _buildFloatingActionButton(),
      bottomAccessory: _buildBottomAccessory(hasCurrentEpisode),
      bottomAccessoryBodyPadding: _bottomAccessoryBodyPadding(
        hasCurrentEpisode: hasCurrentEpisode,
      ),
      desktopNavExpanded: _desktopNavExpanded,
      onDesktopNavToggle: () {
        setState(() {
          _desktopNavExpanded = !_desktopNavExpanded;
        });
      },
      body: _buildTabContent(isExpanded),
    );
  }

  Widget? _buildFloatingActionButton() {
    return null;
  }

  Widget? _buildBottomAccessory(bool hasCurrentEpisode) {
    final isPodcastTab = _isPodcastTab(_currentIndex);
    if (!isPodcastTab) {
      return null;
    }

    if (!hasCurrentEpisode) {
      return null;
    }

    return const PodcastBottomPlayerWidget(applySafeArea: false);
  }

  double _bottomAccessoryBodyPadding({required bool hasCurrentEpisode}) {
    final isPodcastTab = _isPodcastTab(_currentIndex);
    if (!isPodcastTab || !hasCurrentEpisode) {
      return 0;
    }

    return kPodcastMiniPlayerBodyReserve;
  }

  void _handleNavigation(int index) {
    if (_currentIndex != index) {
      _visitedTabs.add(index);
    }

    if (!_isPodcastTab(index) && ref.read(audioPlayerProvider).isExpanded) {
      ref.read(audioPlayerProvider.notifier).setExpanded(false);
    }

    if (_currentIndex != index) {
      setState(() {
        _currentIndex = index;
      });
    }
  }

  Widget _buildTabContent(bool isExpanded) {
    final content = _buildIndexedTabContent();

    // If expanded, wrap content with a barrier to detect outside taps
    if (isExpanded && _isPodcastTab(_currentIndex)) {
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
                color: Colors.black.withValues(
                  alpha: 0.01,
                ), // Almost transparent but touchable
              ),
            ),
          ),
        ],
      );
    }

    return content;
  }

  Widget _buildIndexedTabContent() {
    return IndexedStack(
      index: _currentIndex,
      children: List<Widget>.generate(_tabCount, (index) {
        if (!_visitedTabs.contains(index)) {
          return const SizedBox.shrink();
        }
        return _buildPageContent(index);
      }),
    );
  }

  Widget _buildPageContent(int index) {
    switch (index) {
      case 0:
        return const PodcastListPage();
      case 1:
        return const PodcastFeedPage();
      case 2:
        return const ProfilePage();
      default:
        return Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                Icons.error_outline,
                size: 64,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
              SizedBox(height: 16),
              Text(
                AppLocalizations.of(context)!.page_not_found,
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.w500,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
              ),
              SizedBox(height: 8),
              Text(
                AppLocalizations.of(context)!.page_not_found_subtitle,
                style: TextStyle(
                  fontSize: 14,
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        );
    }
  }
}
