import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/storage/local_storage_service.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_discover_chart_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_search_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_state_models.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/services/apple_podcast_rss_service.dart';
import 'package:personal_ai_assistant/features/podcast/data/services/itunes_search_service.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_list_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_discover_provider.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_search_provider.dart'
    as search;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('PodcastListPage discover actions', () {
    testWidgets('show subscribe button uses lookup and subscribes', (
      tester,
    ) async {
      final fakeLookupService = _FakeITunesSearchService();
      final fakeSubscriptionNotifier = _FakePodcastSubscriptionNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            localStorageServiceProvider.overrideWithValue(
              _MockLocalStorageService(),
            ),
            applePodcastRssServiceProvider.overrideWithValue(
              _FakeApplePodcastRssService(),
            ),
            search.iTunesSearchServiceProvider.overrideWithValue(
              fakeLookupService,
            ),
            podcastSubscriptionProvider.overrideWith(
              () => fakeSubscriptionNotifier,
            ),
            search.podcastSearchProvider.overrideWithValue(
              const search.PodcastSearchState(),
            ),
          ],
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: const PodcastListPage(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('podcast_discover_subscribe_111')));
      await tester.pumpAndSettle();
      await tester.pump(const Duration(seconds: 4));

      expect(fakeLookupService.lookupCalled, isTrue);
      expect(
        fakeSubscriptionNotifier.lastAddedFeedUrl,
        'https://example.com/feed.xml',
      );
    });

    testWidgets('episode open action launches external url', (tester) async {
      const channel = MethodChannel('plugins.flutter.io/url_launcher');
      final calls = <MethodCall>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls.add(call);
            return true;
          });
      addTearDown(() {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null);
      });

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            localStorageServiceProvider.overrideWithValue(
              _MockLocalStorageService(),
            ),
            applePodcastRssServiceProvider.overrideWithValue(
              _FakeApplePodcastRssService(),
            ),
            podcastSubscriptionProvider.overrideWith(
              () => _FakePodcastSubscriptionNotifier(),
            ),
            search.podcastSearchProvider.overrideWithValue(
              const search.PodcastSearchState(),
            ),
          ],
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: const PodcastListPage(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      final l10n = AppLocalizations.of(
        tester.element(find.byType(PodcastListPage)),
      )!;
      await tester.tap(find.text(l10n.podcast_episodes));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('podcast_discover_open_222')));
      await tester.pumpAndSettle();

      expect(
        calls.any(
          (call) => call.method == 'launch' || call.method == 'launchUrl',
        ),
        isTrue,
      );
    });
  });
}

class _FakeApplePodcastRssService extends ApplePodcastRssService {
  _FakeApplePodcastRssService() : super();

  @override
  Future<ApplePodcastChartResponse> fetchTopShows({
    required PodcastCountry country,
    int limit = 25,
    ApplePodcastRssFormat format = ApplePodcastRssFormat.json,
  }) async {
    return ApplePodcastChartResponse(
      feed: ApplePodcastChartFeed(
        title: 'Top Shows',
        country: country.code,
        updated: '2026-02-14T00:00:00Z',
        results: [
          ApplePodcastChartEntry.fromJson({
            'artistName': 'Show Artist',
            'id': '111',
            'name': 'Show One',
            'kind': 'podcasts',
            'artworkUrl100': 'https://example.com/show.png',
            'genres': [
              {'name': 'Technology'},
            ],
            'url': 'https://podcasts.apple.com/us/podcast/id111',
          }),
        ],
      ),
    );
  }

  @override
  Future<ApplePodcastChartResponse> fetchTopEpisodes({
    required PodcastCountry country,
    int limit = 25,
    ApplePodcastRssFormat format = ApplePodcastRssFormat.json,
  }) async {
    return ApplePodcastChartResponse(
      feed: ApplePodcastChartFeed(
        title: 'Top Episodes',
        country: country.code,
        updated: '2026-02-14T00:00:00Z',
        results: [
          ApplePodcastChartEntry.fromJson({
            'artistName': 'Episode Artist',
            'id': '222',
            'name': 'Episode One',
            'kind': 'podcast-episodes',
            'artworkUrl100': 'https://example.com/ep.png',
            'genres': [
              {'name': 'News'},
            ],
            'url': 'https://podcasts.apple.com/us/podcast/id222',
          }),
        ],
      ),
    );
  }
}

class _FakeITunesSearchService extends ITunesSearchService {
  _FakeITunesSearchService() : super();

  bool lookupCalled = false;

  @override
  Future<PodcastSearchResult?> lookupPodcast({
    required int itunesId,
    PodcastCountry country = PodcastCountry.china,
  }) async {
    lookupCalled = true;
    return const PodcastSearchResult(
      collectionId: 111,
      collectionName: 'Show One',
      artistName: 'Show Artist',
      feedUrl: 'https://example.com/feed.xml',
    );
  }
}

class _FakePodcastSubscriptionNotifier extends PodcastSubscriptionNotifier {
  String? lastAddedFeedUrl;

  @override
  PodcastSubscriptionState build() => const PodcastSubscriptionState(
    subscriptions: [],
    hasMore: false,
    total: 0,
  );

  @override
  Future<void> loadSubscriptions({
    int page = 1,
    int size = 10,
    int? categoryId,
    String? status,
    bool forceRefresh = false,
  }) async {}

  @override
  Future<void> loadMoreSubscriptions({int? categoryId, String? status}) async {}

  @override
  Future<void> refreshSubscriptions({int? categoryId, String? status}) async {}

  @override
  Future<PodcastSubscriptionModel> addSubscription({
    required String feedUrl,
    List<int>? categoryIds,
  }) async {
    lastAddedFeedUrl = feedUrl;
    final now = DateTime.now();
    return PodcastSubscriptionModel(
      id: 1,
      userId: 1,
      title: 'Subscribed',
      sourceUrl: feedUrl,
      status: 'active',
      fetchInterval: 3600,
      episodeCount: 0,
      unplayedCount: 0,
      createdAt: now,
    );
  }
}

class _MockLocalStorageService implements LocalStorageService {
  final Map<String, dynamic> _storage = {};

  @override
  Future<void> saveString(String key, String value) async =>
      _storage[key] = value;

  @override
  Future<String?> getString(String key) async => _storage[key] as String?;

  @override
  Future<void> saveBool(String key, bool value) async => _storage[key] = value;

  @override
  Future<bool?> getBool(String key) async => _storage[key] as bool?;

  @override
  Future<void> saveInt(String key, int value) async => _storage[key] = value;

  @override
  Future<int?> getInt(String key) async => _storage[key] as int?;

  @override
  Future<void> saveDouble(String key, double value) async =>
      _storage[key] = value;

  @override
  Future<double?> getDouble(String key) async => _storage[key] as double?;

  @override
  Future<void> saveStringList(String key, List<String> value) async =>
      _storage[key] = value;

  @override
  Future<List<String>?> getStringList(String key) async =>
      _storage[key] as List<String>?;

  @override
  Future<void> save<T>(String key, T value) async => _storage[key] = value;

  @override
  Future<T?> get<T>(String key) async => _storage[key] as T?;

  @override
  Future<void> remove(String key) async => _storage.remove(key);

  @override
  Future<void> clear() async => _storage.clear();

  @override
  Future<bool> containsKey(String key) async => _storage.containsKey(key);

  @override
  Future<void> cacheData(
    String key,
    dynamic data, {
    Duration? expiration,
  }) async {
    _storage[key] = data;
  }

  @override
  Future<T?> getCachedData<T>(String key) async => _storage[key] as T?;

  @override
  Future<void> clearExpiredCache() async {}

  @override
  Future<void> saveApiBaseUrl(String url) async =>
      _storage['api_base_url'] = url;

  @override
  Future<String?> getApiBaseUrl() async => _storage['api_base_url'] as String?;

  @override
  Future<void> saveServerBaseUrl(String url) async =>
      _storage['server_base_url'] = url;

  @override
  Future<String?> getServerBaseUrl() async =>
      _storage['server_base_url'] as String?;
}
