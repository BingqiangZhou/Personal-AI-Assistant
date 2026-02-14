import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../data/models/podcast_discover_chart_model.dart';
import '../../data/models/podcast_search_model.dart';
import '../../data/services/apple_podcast_rss_service.dart';
import 'country_selector_provider.dart';

enum PodcastDiscoverTab { podcasts, episodes }

class PodcastDiscoverState {
  final PodcastCountry country;
  final bool isLoading;
  final bool isRefreshing;
  final String? error;
  final PodcastDiscoverTab selectedTab;
  final String selectedCategory;
  final bool showsExpanded;
  final bool episodesExpanded;
  final List<PodcastDiscoverItem> topShows;
  final List<PodcastDiscoverItem> topEpisodes;

  const PodcastDiscoverState({
    required this.country,
    this.isLoading = false,
    this.isRefreshing = false,
    this.error,
    this.selectedTab = PodcastDiscoverTab.podcasts,
    this.selectedCategory = allCategoryValue,
    this.showsExpanded = false,
    this.episodesExpanded = false,
    this.topShows = const [],
    this.topEpisodes = const [],
  });

  static const String allCategoryValue = '__all__';

  PodcastDiscoverState copyWith({
    PodcastCountry? country,
    bool? isLoading,
    bool? isRefreshing,
    String? error,
    bool clearError = false,
    PodcastDiscoverTab? selectedTab,
    String? selectedCategory,
    bool? showsExpanded,
    bool? episodesExpanded,
    List<PodcastDiscoverItem>? topShows,
    List<PodcastDiscoverItem>? topEpisodes,
  }) {
    return PodcastDiscoverState(
      country: country ?? this.country,
      isLoading: isLoading ?? this.isLoading,
      isRefreshing: isRefreshing ?? this.isRefreshing,
      error: clearError ? null : (error ?? this.error),
      selectedTab: selectedTab ?? this.selectedTab,
      selectedCategory: selectedCategory ?? this.selectedCategory,
      showsExpanded: showsExpanded ?? this.showsExpanded,
      episodesExpanded: episodesExpanded ?? this.episodesExpanded,
      topShows: topShows ?? this.topShows,
      topEpisodes: topEpisodes ?? this.topEpisodes,
    );
  }

  List<PodcastDiscoverItem> get activeItems =>
      selectedTab == PodcastDiscoverTab.podcasts ? topShows : topEpisodes;

  bool get isCurrentTabExpanded => selectedTab == PodcastDiscoverTab.podcasts
      ? showsExpanded
      : episodesExpanded;

  List<String> get categories {
    final counts = <String, int>{};
    for (final item in activeItems) {
      for (final genre in item.genres) {
        final trimmed = genre.trim();
        if (trimmed.isEmpty) continue;
        counts[trimmed] = (counts[trimmed] ?? 0) + 1;
      }
    }

    final sorted = counts.entries.toList()
      ..sort((a, b) {
        final countCompare = b.value.compareTo(a.value);
        if (countCompare != 0) return countCompare;
        return a.key.toLowerCase().compareTo(b.key.toLowerCase());
      });
    return sorted.map((entry) => entry.key).toList();
  }

  List<PodcastDiscoverItem> get filteredActiveItems {
    if (selectedCategory == allCategoryValue) {
      return activeItems;
    }
    return activeItems
        .where((item) => item.hasGenre(selectedCategory))
        .toList();
  }

  List<PodcastDiscoverItem> get visibleItems {
    final source = filteredActiveItems;
    final limit = isCurrentTabExpanded ? 25 : 5;
    return source.take(limit).toList();
  }

  bool get canSeeAll => filteredActiveItems.length > 5;
}

final applePodcastRssServiceProvider = Provider<ApplePodcastRssService>((ref) {
  return ApplePodcastRssService.ref(ref);
});

final podcastDiscoverProvider =
    NotifierProvider<PodcastDiscoverNotifier, PodcastDiscoverState>(
      PodcastDiscoverNotifier.new,
    );

class PodcastDiscoverNotifier extends Notifier<PodcastDiscoverState> {
  late final ApplePodcastRssService _rssService;

  @override
  PodcastDiscoverState build() {
    _rssService = ref.read(applePodcastRssServiceProvider);
    final selectedCountry = ref.read(countrySelectorProvider).selectedCountry;

    ref.listen<CountrySelectorState>(countrySelectorProvider, (previous, next) {
      final previousCountry = previous?.selectedCountry;
      if (previousCountry != next.selectedCountry) {
        unawaited(onCountryChanged(next.selectedCountry));
      }
    });

    return PodcastDiscoverState(country: selectedCountry);
  }

  Future<void> loadInitialData() async {
    await _loadCharts(country: state.country, isRefresh: false);
  }

  Future<void> refresh() async {
    await _loadCharts(country: state.country, isRefresh: true);
  }

  Future<void> onCountryChanged(PodcastCountry country) async {
    if (country == state.country &&
        (state.topShows.isNotEmpty || state.topEpisodes.isNotEmpty)) {
      return;
    }
    state = state.copyWith(
      country: country,
      selectedCategory: PodcastDiscoverState.allCategoryValue,
      showsExpanded: false,
      episodesExpanded: false,
      clearError: true,
    );
    await _loadCharts(country: country, isRefresh: false);
  }

  void setTab(PodcastDiscoverTab tab) {
    if (tab == state.selectedTab) return;
    state = state.copyWith(
      selectedTab: tab,
      selectedCategory: PodcastDiscoverState.allCategoryValue,
    );
  }

  void selectCategory(String category) {
    final normalized = category.trim();
    if (normalized.isEmpty) {
      return;
    }
    state = state.copyWith(selectedCategory: normalized);
  }

  void toggleSeeAll() {
    if (state.selectedTab == PodcastDiscoverTab.podcasts) {
      state = state.copyWith(showsExpanded: !state.showsExpanded);
      return;
    }
    state = state.copyWith(episodesExpanded: !state.episodesExpanded);
  }

  Future<void> _loadCharts({
    required PodcastCountry country,
    required bool isRefresh,
  }) async {
    state = state.copyWith(
      isLoading: !isRefresh,
      isRefreshing: isRefresh,
      clearError: true,
    );

    try {
      final responses = await Future.wait([
        _rssService.fetchTopShows(
          country: country,
          limit: 25,
          format: ApplePodcastRssFormat.json,
        ),
        _rssService.fetchTopEpisodes(
          country: country,
          limit: 25,
          format: ApplePodcastRssFormat.json,
        ),
      ]);

      final shows = responses[0].feed.results
          .map(
            (entry) => PodcastDiscoverItem.fromChartEntry(
              entry,
              defaultKind: PodcastDiscoverKind.podcasts,
            ),
          )
          .toList();
      final episodes = responses[1].feed.results
          .map(
            (entry) => PodcastDiscoverItem.fromChartEntry(
              entry,
              defaultKind: PodcastDiscoverKind.podcastEpisodes,
            ),
          )
          .toList();

      state = state.copyWith(
        country: country,
        isLoading: false,
        isRefreshing: false,
        topShows: shows,
        topEpisodes: episodes,
        selectedCategory: PodcastDiscoverState.allCategoryValue,
        showsExpanded: false,
        episodesExpanded: false,
        clearError: true,
      );
    } catch (error) {
      state = state.copyWith(
        isLoading: false,
        isRefreshing: false,
        error: error.toString(),
      );
    }
  }
}
