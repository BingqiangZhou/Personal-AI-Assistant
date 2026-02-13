import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/storage/local_storage_service.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_state_models.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_list_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_search_provider.dart'
    as search;

void main() {
  group('PodcastListPage mobile card layout', () {
    testWidgets('subscription card matches mini player inset and radius', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(390, 844);
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

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
            search.podcastSearchProvider.overrideWithValue(
              const search.PodcastSearchState(),
            ),
            localStorageServiceProvider.overrideWithValue(
              MockLocalStorageService(),
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

      final cardFinder = find.byKey(
        const Key('podcast_subscription_mobile_card_1'),
      );
      expect(cardFinder, findsOneWidget);

      final cardWidget = tester.widget<Card>(cardFinder);
      expect(
        cardWidget.margin,
        const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
      );
      expect(cardWidget.shape, isA<RoundedRectangleBorder>());

      final rounded = cardWidget.shape! as RoundedRectangleBorder;
      final radius = rounded.borderRadius.resolve(TextDirection.ltr);
      expect(radius.topLeft.x, 12);
      expect(radius.topRight.x, 12);
      expect(radius.bottomLeft.x, 12);
      expect(radius.bottomRight.x, 12);

      final cardMaterialFinder = find.descendant(
        of: cardFinder,
        matching: find.byType(Material),
      );
      expect(cardMaterialFinder, findsWidgets);
      final cardMaterialRect = tester.getRect(cardMaterialFinder.first);
      expect(cardMaterialRect.width, closeTo(350, 1));
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
