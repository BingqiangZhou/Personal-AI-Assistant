import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:personal_ai_assistant/core/storage/local_storage_service.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_discover_chart_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_search_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/services/apple_podcast_rss_service.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_discover_provider.dart';

void main() {
  group('podcastDiscoverProvider', () {
    test('loads initial top shows and episodes', () async {
      final fakeService = _FakeApplePodcastRssService();
      final container = ProviderContainer(
        overrides: [
          localStorageServiceProvider.overrideWithValue(
            _MockLocalStorageService(),
          ),
          applePodcastRssServiceProvider.overrideWithValue(fakeService),
        ],
      );
      addTearDown(container.dispose);

      await container.read(podcastDiscoverProvider.notifier).loadInitialData();
      final state = container.read(podcastDiscoverProvider);

      expect(state.topShows, isNotEmpty);
      expect(state.topEpisodes, isNotEmpty);
      expect(state.selectedTab, PodcastDiscoverTab.podcasts);
      expect(state.selectedCategory, PodcastDiscoverState.allCategoryValue);
    });

    test(
      'supports tab switching, category filtering, and see-all toggle',
      () async {
        final fakeService = _FakeApplePodcastRssService();
        final container = ProviderContainer(
          overrides: [
            localStorageServiceProvider.overrideWithValue(
              _MockLocalStorageService(),
            ),
            applePodcastRssServiceProvider.overrideWithValue(fakeService),
          ],
        );
        addTearDown(container.dispose);

        await container
            .read(podcastDiscoverProvider.notifier)
            .loadInitialData();
        final notifier = container.read(podcastDiscoverProvider.notifier);

        notifier.setTab(PodcastDiscoverTab.episodes);
        notifier.selectCategory('News');
        var state = container.read(podcastDiscoverProvider);

        expect(state.selectedTab, PodcastDiscoverTab.episodes);
        expect(state.selectedCategory, 'News');
        expect(
          state.filteredActiveItems.every((item) => item.hasGenre('News')),
          isTrue,
        );

        expect(state.isCurrentTabExpanded, isFalse);
        notifier.toggleSeeAll();
        state = container.read(podcastDiscoverProvider);
        expect(state.isCurrentTabExpanded, isTrue);
      },
    );

    test('reloads on country change', () async {
      final fakeService = _FakeApplePodcastRssService();
      final container = ProviderContainer(
        overrides: [
          localStorageServiceProvider.overrideWithValue(
            _MockLocalStorageService(),
          ),
          applePodcastRssServiceProvider.overrideWithValue(fakeService),
        ],
      );
      addTearDown(container.dispose);

      await container.read(podcastDiscoverProvider.notifier).loadInitialData();
      final initialCalls = fakeService.showsCalls;

      await container
          .read(podcastDiscoverProvider.notifier)
          .onCountryChanged(PodcastCountry.japan);

      final state = container.read(podcastDiscoverProvider);
      expect(state.country, PodcastCountry.japan);
      expect(fakeService.showsCalls, greaterThan(initialCalls));
    });

    test('skips repeated load when discover data is fresh', () async {
      final fakeService = _FakeApplePodcastRssService();
      final container = ProviderContainer(
        overrides: [
          localStorageServiceProvider.overrideWithValue(
            _MockLocalStorageService(),
          ),
          applePodcastRssServiceProvider.overrideWithValue(fakeService),
        ],
      );
      addTearDown(container.dispose);

      await container.read(podcastDiscoverProvider.notifier).loadInitialData();
      final showsCallsAfterFirstLoad = fakeService.showsCalls;
      final episodesCallsAfterFirstLoad = fakeService.episodeCalls;

      await container.read(podcastDiscoverProvider.notifier).loadInitialData();

      expect(fakeService.showsCalls, showsCallsAfterFirstLoad);
      expect(fakeService.episodeCalls, episodesCallsAfterFirstLoad);
    });

    test('loads selected tab results first before the other tab', () async {
      final fakeService = _DelayedApplePodcastRssService();
      final container = ProviderContainer(
        overrides: [
          localStorageServiceProvider.overrideWithValue(
            _MockLocalStorageService(),
          ),
          applePodcastRssServiceProvider.overrideWithValue(fakeService),
        ],
      );
      addTearDown(container.dispose);

      container
          .read(podcastDiscoverProvider.notifier)
          .setTab(PodcastDiscoverTab.episodes);

      final future = container
          .read(podcastDiscoverProvider.notifier)
          .loadInitialData();

      await Future<void>.delayed(const Duration(milliseconds: 50));
      final midState = container.read(podcastDiscoverProvider);
      expect(midState.topEpisodes, isNotEmpty);
      expect(midState.topShows, isEmpty);

      await future;

      final finalState = container.read(podcastDiscoverProvider);
      expect(finalState.topEpisodes, isNotEmpty);
      expect(finalState.topShows, isNotEmpty);
    });
  });
}

class _FakeApplePodcastRssService extends ApplePodcastRssService {
  _FakeApplePodcastRssService() : super();

  int showsCalls = 0;
  int episodeCalls = 0;

  @override
  Future<ApplePodcastChartResponse> fetchTopShows({
    required PodcastCountry country,
    int limit = 25,
    ApplePodcastRssFormat format = ApplePodcastRssFormat.json,
  }) async {
    showsCalls += 1;
    return _responseFor(kind: 'podcasts', country: country.code);
  }

  @override
  Future<ApplePodcastChartResponse> fetchTopEpisodes({
    required PodcastCountry country,
    int limit = 25,
    ApplePodcastRssFormat format = ApplePodcastRssFormat.json,
  }) async {
    episodeCalls += 1;
    return _responseFor(kind: 'podcast-episodes', country: country.code);
  }

  ApplePodcastChartResponse _responseFor({
    required String kind,
    required String country,
  }) {
    final items = List.generate(
      8,
      (index) => ApplePodcastChartEntry.fromJson({
        'artistName': 'Artist $index',
        'id': '${1000 + index}',
        'name': 'Item $index',
        'kind': kind,
        'artworkUrl100': 'https://example.com/$index.png',
        'genres': [
          {'name': index.isEven ? 'Technology' : 'News'},
        ],
        'url': 'https://podcasts.apple.com/$country/podcast/id${1000 + index}',
      }),
    );

    return ApplePodcastChartResponse(
      feed: ApplePodcastChartFeed(
        title: kind,
        country: country,
        updated: '2026-02-14T00:00:00Z',
        results: items,
      ),
    );
  }
}

class _DelayedApplePodcastRssService extends _FakeApplePodcastRssService {
  @override
  Future<ApplePodcastChartResponse> fetchTopShows({
    required PodcastCountry country,
    int limit = 25,
    ApplePodcastRssFormat format = ApplePodcastRssFormat.json,
  }) async {
    showsCalls += 1;
    await Future<void>.delayed(const Duration(milliseconds: 120));
    return _responseFor(kind: 'podcasts', country: country.code);
  }

  @override
  Future<ApplePodcastChartResponse> fetchTopEpisodes({
    required PodcastCountry country,
    int limit = 25,
    ApplePodcastRssFormat format = ApplePodcastRssFormat.json,
  }) async {
    episodeCalls += 1;
    await Future<void>.delayed(const Duration(milliseconds: 20));
    return _responseFor(kind: 'podcast-episodes', country: country.code);
  }
}

class _MockLocalStorageService implements LocalStorageService {
  final Map<String, dynamic> _storage = {};

  @override
  Future<void> clear() async => _storage.clear();

  @override
  Future<void> clearExpiredCache() async {}

  @override
  Future<bool> containsKey(String key) async => _storage.containsKey(key);

  @override
  Future<void> cacheData(String key, data, {Duration? expiration}) async {
    _storage[key] = data;
  }

  @override
  Future<T?> get<T>(String key) async => _storage[key] as T?;

  @override
  Future<String?> getApiBaseUrl() async => _storage['api_base_url'] as String?;

  @override
  Future<bool?> getBool(String key) async => _storage[key] as bool?;

  @override
  Future<T?> getCachedData<T>(String key) async => _storage[key] as T?;

  @override
  Future<double?> getDouble(String key) async => _storage[key] as double?;

  @override
  Future<int?> getInt(String key) async => _storage[key] as int?;

  @override
  Future<String?> getServerBaseUrl() async =>
      _storage['server_base_url'] as String?;

  @override
  Future<String?> getString(String key) async => _storage[key] as String?;

  @override
  Future<List<String>?> getStringList(String key) async =>
      _storage[key] as List<String>?;

  @override
  Future<void> remove(String key) async => _storage.remove(key);

  @override
  Future<void> save<T>(String key, T value) async => _storage[key] = value;

  @override
  Future<void> saveApiBaseUrl(String url) async =>
      _storage['api_base_url'] = url;

  @override
  Future<void> saveBool(String key, bool value) async => _storage[key] = value;

  @override
  Future<void> saveDouble(String key, double value) async =>
      _storage[key] = value;

  @override
  Future<void> saveInt(String key, int value) async => _storage[key] = value;

  @override
  Future<void> saveServerBaseUrl(String url) async =>
      _storage['server_base_url'] = url;

  @override
  Future<void> saveString(String key, String value) async =>
      _storage[key] = value;

  @override
  Future<void> saveStringList(String key, List<String> value) async =>
      _storage[key] = value;
}
