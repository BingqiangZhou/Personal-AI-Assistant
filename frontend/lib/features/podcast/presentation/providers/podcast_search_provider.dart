import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../../../../core/utils/debounce.dart' as utils;
import '../../data/models/itunes_episode_lookup_model.dart';
import '../../data/models/podcast_search_model.dart';
import '../../data/services/itunes_search_service.dart';
import '../providers/country_selector_provider.dart';

part 'podcast_search_provider.g.dart';

enum PodcastSearchMode { podcasts, episodes }

/// 播客搜索状态
class PodcastSearchState {
  final List<PodcastSearchResult> podcastResults;
  final List<ITunesPodcastEpisodeResult> episodeResults;
  final bool isLoading;
  final bool hasSearched;
  final String? error;
  final String currentQuery;
  final PodcastCountry searchCountry;
  final PodcastSearchMode searchMode;

  const PodcastSearchState({
    this.podcastResults = const [],
    this.episodeResults = const [],
    this.isLoading = false,
    this.hasSearched = false,
    this.error,
    this.currentQuery = '',
    this.searchCountry = PodcastCountry.china,
    this.searchMode = PodcastSearchMode.episodes,
  });

  PodcastSearchState copyWith({
    List<PodcastSearchResult>? podcastResults,
    List<ITunesPodcastEpisodeResult>? episodeResults,
    bool? isLoading,
    bool? hasSearched,
    String? error,
    String? currentQuery,
    PodcastCountry? searchCountry,
    PodcastSearchMode? searchMode,
  }) {
    return PodcastSearchState(
      podcastResults: podcastResults ?? this.podcastResults,
      episodeResults: episodeResults ?? this.episodeResults,
      isLoading: isLoading ?? this.isLoading,
      hasSearched: hasSearched ?? this.hasSearched,
      error: error,
      currentQuery: currentQuery ?? this.currentQuery,
      searchCountry: searchCountry ?? this.searchCountry,
      searchMode: searchMode ?? this.searchMode,
    );
  }
}

/// iTunes Search Service Provider (manual provider)
final iTunesSearchServiceProvider = Provider<ITunesSearchService>((ref) {
  return ITunesSearchService();
});

/// 播客搜索 Notifier
@riverpod
class PodcastSearchNotifier extends _$PodcastSearchNotifier {
  utils.DebounceTimer? _debounce;

  @override
  PodcastSearchState build() {
    ref.onDispose(() {
      _debounce?.cancel();
    });

    return const PodcastSearchState();
  }

  /// 搜索播客（带防抖）
  void searchPodcasts(String query) {
    _scheduleSearch(query, PodcastSearchMode.podcasts);
  }

  /// 搜索分集（带防抖）
  void searchEpisodes(String query) {
    _scheduleSearch(query, PodcastSearchMode.episodes);
  }

  void setSearchMode(PodcastSearchMode mode) {
    if (state.searchMode == mode) {
      return;
    }
    state = state.copyWith(
      searchMode: mode,
      error: null,
      isLoading: state.currentQuery.trim().isNotEmpty,
      hasSearched: state.currentQuery.trim().isNotEmpty,
      podcastResults: mode == PodcastSearchMode.podcasts ? state.podcastResults : const [],
      episodeResults: mode == PodcastSearchMode.episodes ? state.episodeResults : const [],
    );
    if (state.currentQuery.trim().isNotEmpty) {
      _scheduleSearch(state.currentQuery, mode, bypassDebounce: true);
    }
  }

  void _scheduleSearch(
    String query,
    PodcastSearchMode mode, {
    bool bypassDebounce = false,
  }) {
    _debounce?.cancel();

    if (query.trim().isEmpty) {
      state = PodcastSearchState(searchMode: mode);
      return;
    }

    state = state.copyWith(
      isLoading: true,
      hasSearched: true,
      error: null,
      currentQuery: query,
      searchMode: mode,
    );

    final delay = bypassDebounce ? Duration.zero : const Duration(milliseconds: 500);
    _debounce = utils.DebounceTimer(delay, () async {
      await _performSearch(query, mode);
    });
  }

  /// 执行搜索
  Future<void> _performSearch(String query, PodcastSearchMode mode) async {
    final country = ref.read(countrySelectorProvider).selectedCountry;
    final searchService = ref.read(iTunesSearchServiceProvider);

    try {
      if (mode == PodcastSearchMode.podcasts) {
        final response = await searchService.searchPodcasts(
          term: query,
          country: country,
          limit: 25,
        );
        state = state.copyWith(
          podcastResults: response.results,
          episodeResults: const [],
          isLoading: false,
          searchCountry: country,
          error: null,
          searchMode: mode,
        );
        return;
      }

      final episodes = await searchService.searchPodcastEpisodes(
        term: query,
        country: country,
        limit: 25,
      );
      state = state.copyWith(
        podcastResults: const [],
        episodeResults: episodes,
        isLoading: false,
        searchCountry: country,
        error: null,
        searchMode: mode,
      );
    } catch (error) {
      state = state.copyWith(
        podcastResults: const [],
        episodeResults: const [],
        isLoading: false,
        searchCountry: country,
        error: error.toString(),
        searchMode: mode,
      );
    }
  }

  /// 清除搜索结果
  void clearSearch() {
    _debounce?.cancel();
    state = PodcastSearchState(searchMode: state.searchMode);
  }

  /// 重新搜索（使用当前查询）
  Future<void> retrySearch() async {
    if (state.currentQuery.isNotEmpty) {
      state = state.copyWith(isLoading: true, error: null);
      await _performSearch(state.currentQuery, state.searchMode);
    }
  }
}
