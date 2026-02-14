import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/storage/local_storage_service.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_state_models.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_list_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_search_provider.dart'
    as search;

void main() {
  group('PodcastListPage desktop subscription layout', () {
    testWidgets('renders subscriptions shortcut and keeps navigation', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(1200, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      final notifier = TestPodcastSubscriptionNotifier(
        PodcastSubscriptionState(
          subscriptions: [_subscription()],
          hasMore: false,
          total: 1,
        ),
      );

      final router = GoRouter(
        routes: [
          GoRoute(
            path: '/',
            builder: (context, state) => ProviderScope(
              overrides: [
                podcastSubscriptionProvider.overrideWith(() => notifier),
                search.podcastSearchProvider.overrideWithValue(
                  const search.PodcastSearchState(),
                ),
                localStorageServiceProvider.overrideWithValue(
                  MockLocalStorageService(),
                ),
              ],
              child: const PodcastListPage(),
            ),
          ),
          GoRoute(
            path: '/profile/subscriptions',
            builder: (context, state) =>
                const Scaffold(body: Text('Subscriptions Page')),
          ),
        ],
      );

      await tester.pumpWidget(
        MaterialApp.router(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          routerConfig: router,
        ),
      );
      await tester.pumpAndSettle();

      final shortcutFinder = find.byKey(
        const Key('podcast_list_subscriptions_shortcut'),
      );
      expect(shortcutFinder, findsOneWidget);

      await tester.tap(shortcutFinder);
      await tester.pumpAndSettle();

      expect(find.text('Subscriptions Page'), findsOneWidget);
    });
  });
}

class MockLocalStorageService implements LocalStorageService {
  final Map<String, dynamic> _storage = {};

  @override
  Future<void> saveString(String key, String value) async {
    _storage[key] = value;
  }

  @override
  Future<String?> getString(String key) async {
    return _storage[key] as String?;
  }

  @override
  Future<void> saveBool(String key, bool value) async {
    _storage[key] = value;
  }

  @override
  Future<bool?> getBool(String key) async {
    return _storage[key] as bool?;
  }

  @override
  Future<void> saveInt(String key, int value) async {
    _storage[key] = value;
  }

  @override
  Future<int?> getInt(String key) async {
    return _storage[key] as int?;
  }

  @override
  Future<void> saveDouble(String key, double value) async {
    _storage[key] = value;
  }

  @override
  Future<double?> getDouble(String key) async {
    return _storage[key] as double?;
  }

  @override
  Future<void> saveStringList(String key, List<String> value) async {
    _storage[key] = value;
  }

  @override
  Future<List<String>?> getStringList(String key) async {
    return _storage[key] as List<String>?;
  }

  @override
  Future<void> save<T>(String key, T value) async {
    _storage[key] = value;
  }

  @override
  Future<T?> get<T>(String key) async {
    return _storage[key] as T?;
  }

  @override
  Future<void> remove(String key) async {
    _storage.remove(key);
  }

  @override
  Future<void> clear() async {
    _storage.clear();
  }

  @override
  Future<bool> containsKey(String key) async {
    return _storage.containsKey(key);
  }

  @override
  Future<void> cacheData(
    String key,
    dynamic data, {
    Duration? expiration,
  }) async {
    _storage[key] = data;
  }

  @override
  Future<T?> getCachedData<T>(String key) async {
    return _storage[key] as T?;
  }

  @override
  Future<void> clearExpiredCache() async {}

  @override
  Future<void> saveApiBaseUrl(String url) async {
    _storage['api_base_url'] = url;
  }

  @override
  Future<String?> getApiBaseUrl() async {
    return _storage['api_base_url'] as String?;
  }

  @override
  Future<void> saveServerBaseUrl(String url) async {
    _storage['server_base_url'] = url;
  }

  @override
  Future<String?> getServerBaseUrl() async {
    return _storage['server_base_url'] as String?;
  }
}

class TestPodcastSubscriptionNotifier extends PodcastSubscriptionNotifier {
  TestPodcastSubscriptionNotifier(this._initialState);

  final PodcastSubscriptionState _initialState;

  @override
  PodcastSubscriptionState build() {
    return _initialState;
  }

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
}

PodcastSubscriptionModel _subscription() {
  final now = DateTime.now();
  return PodcastSubscriptionModel(
    id: 1,
    userId: 1,
    title: 'Sample Podcast',
    description: 'Sample Description',
    sourceUrl: 'https://example.com/feed.xml',
    status: 'active',
    fetchInterval: 3600,
    episodeCount: 10,
    unplayedCount: 3,
    createdAt: now,
  );
}
