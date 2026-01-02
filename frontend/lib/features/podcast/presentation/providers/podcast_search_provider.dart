import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../../../../core/utils/debounce.dart' as utils;
import '../../data/models/podcast_search_model.dart';
import '../../data/services/itunes_search_service.dart';
import '../providers/country_selector_provider.dart';

part 'podcast_search_provider.g.dart';

/// 播客搜索状态
class PodcastSearchState {
  final List<PodcastSearchResult> results;
  final bool isLoading;
  final bool hasSearched;
  final String? error;
  final String currentQuery;

  const PodcastSearchState({
    this.results = const [],
    this.isLoading = false,
    this.hasSearched = false,
    this.error,
    this.currentQuery = '',
  });

  PodcastSearchState copyWith({
    List<PodcastSearchResult>? results,
    bool? isLoading,
    bool? hasSearched,
    String? error,
    String? currentQuery,
  }) {
    return PodcastSearchState(
      results: results ?? this.results,
      isLoading: isLoading ?? this.isLoading,
      hasSearched: hasSearched ?? this.hasSearched,
      error: error,
      currentQuery: currentQuery ?? this.currentQuery,
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
    // 取消之前的防抖
    _debounce?.cancel();

    if (query.trim().isEmpty) {
      state = const PodcastSearchState();
      return;
    }

    state = state.copyWith(
      isLoading: true,
      hasSearched: true,
      error: null,
      currentQuery: query,
    );

    // 设置新的防抖（500ms）
    _debounce = utils.DebounceTimer(Duration(milliseconds: 500), () async {
      await _performSearch(query);
    });
  }

  /// 执行搜索
  Future<void> _performSearch(String query) async {
    final country = ref.read(countrySelectorProvider).selectedCountry;
    final searchService = ref.read(iTunesSearchServiceProvider);

    try {
      final response = await searchService.searchPodcasts(
        term: query,
        country: country,
        limit: 25,
      );

      state = state.copyWith(
        results: response.results,
        isLoading: false,
      );
    } catch (error) {
      state = state.copyWith(
        isLoading: false,
        error: error.toString(),
      );
    }
  }

  /// 清除搜索结果
  void clearSearch() {
    _debounce?.cancel();
    state = const PodcastSearchState();
  }

  /// 重新搜索（使用当前查询）
  Future<void> retrySearch() async {
    if (state.currentQuery.isNotEmpty) {
      state = state.copyWith(isLoading: true, error: null);
      await _performSearch(state.currentQuery);
    }
  }
}
