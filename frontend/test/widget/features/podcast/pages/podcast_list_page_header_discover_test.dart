import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/storage/local_storage_service.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_state_models.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/constants/podcast_ui_constants.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_list_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/bulk_selection_provider.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_search_provider.dart'
    as search;
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/add_podcast_dialog.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/bulk_import_dialog.dart';

void main() {
  group('PodcastListPage header and discover layout', () {
    testWidgets('renders header actions and discover/subscription sections', (
      tester,
    ) async {
      final container = ProviderContainer(
        overrides: [
          podcastSubscriptionProvider.overrideWith(
            () => _TestPodcastSubscriptionNotifier(
              PodcastSubscriptionState(
                subscriptions: [_subscription()],
                hasMore: false,
                total: 1,
              ),
            ),
          ),
          search.podcastSearchProvider.overrideWithValue(
            const search.PodcastSearchState(),
          ),
          localStorageServiceProvider.overrideWithValue(
            _MockLocalStorageService(),
          ),
        ],
      );
      addTearDown(container.dispose);

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
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
      );
      expect(l10n, isNotNull);

      expect(
        find.byKey(const Key('podcast_list_header_title')),
        findsOneWidget,
      );
      expect(find.byKey(const Key('podcast_list_action_add')), findsOneWidget);
      expect(
        find.byKey(const Key('podcast_list_action_bulk_import')),
        findsOneWidget,
      );
      expect(
        find.byKey(const Key('podcast_list_action_select_mode')),
        findsOneWidget,
      );
      expect(
        find.byKey(const Key('podcast_list_discover_title')),
        findsOneWidget,
      );
      expect(
        find.byKey(const Key('podcast_list_discover_hint_action')),
        findsOneWidget,
      );
      expect(
        find.byKey(const Key('podcast_list_discover_card')),
        findsOneWidget,
      );
      expect(
        find.byWidgetPredicate(
          (widget) =>
              widget is SearchBar &&
              widget.key == const Key('podcast_list_discover_card'),
        ),
        findsOneWidget,
      );
      expect(
        find.byKey(const Key('podcast_list_subscriptions_title')),
        findsOneWidget,
      );

      final subscriptionsTitle = tester.widget<RichText>(
        find.byKey(const Key('podcast_list_subscriptions_title')),
      );
      expect(subscriptionsTitle.text.toPlainText(), contains('(1)'));

      expect(find.text(l10n!.podcast_network_hint), findsNothing);

      final searchBar = tester.widget<SearchBar>(
        find.byKey(const Key('podcast_list_discover_card')),
      );
      final searchBarShape = searchBar.shape?.resolve(<WidgetState>{});
      expect(searchBarShape, isA<RoundedRectangleBorder>());
      final resolvedSearchBarRadius =
          (searchBarShape! as RoundedRectangleBorder).borderRadius.resolve(
            TextDirection.ltr,
          );
      expect(
        resolvedSearchBarRadius.topLeft.x,
        equals(kPodcastMiniCornerRadius),
      );
      expect(
        resolvedSearchBarRadius.topRight.x,
        equals(kPodcastMiniCornerRadius),
      );

      final countryButtonContainer = tester.widget<Container>(
        find.byKey(const Key('podcast_list_discover_country_button_container')),
      );
      final countryButtonDecoration =
          countryButtonContainer.decoration! as BoxDecoration;
      final resolvedCountryRadius =
          (countryButtonDecoration.borderRadius! as BorderRadius).resolve(
            TextDirection.ltr,
          );
      expect(resolvedCountryRadius.topLeft.x, equals(kPodcastMiniCornerRadius));
      expect(
        resolvedCountryRadius.topRight.x,
        equals(kPodcastMiniCornerRadius),
      );

      await tester.tap(
        find.byKey(const Key('podcast_list_discover_hint_action')),
      );
      await tester.pumpAndSettle();

      expect(find.text(l10n.podcast_network_hint), findsOneWidget);
    });

    testWidgets('maps top-right actions to existing behaviors', (tester) async {
      final container = ProviderContainer(
        overrides: [
          podcastSubscriptionProvider.overrideWith(
            () => _TestPodcastSubscriptionNotifier(
              PodcastSubscriptionState(
                subscriptions: [_subscription()],
                hasMore: false,
                total: 1,
              ),
            ),
          ),
          search.podcastSearchProvider.overrideWithValue(
            const search.PodcastSearchState(),
          ),
          localStorageServiceProvider.overrideWithValue(
            _MockLocalStorageService(),
          ),
        ],
      );
      addTearDown(container.dispose);

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: const PodcastListPage(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('podcast_list_action_add')));
      await tester.pumpAndSettle();
      expect(find.byType(AddPodcastDialog), findsOneWidget);
      Navigator.of(tester.element(find.byType(AddPodcastDialog))).pop();
      await tester.pumpAndSettle();

      await tester.tap(
        find.byKey(const Key('podcast_list_action_bulk_import')),
      );
      await tester.pumpAndSettle();
      expect(find.byType(BulkImportDialog), findsOneWidget);
      Navigator.of(tester.element(find.byType(BulkImportDialog))).pop();
      await tester.pumpAndSettle();

      await tester.tap(
        find.byKey(const Key('podcast_list_action_select_mode')),
      );
      await tester.pumpAndSettle();

      expect(container.read(bulkSelectionProvider).isSelectionMode, isTrue);
      expect(
        find.byKey(const Key('podcast_list_action_select_mode')),
        findsNothing,
      );
    });
  });
}

class _MockLocalStorageService implements LocalStorageService {
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

class _TestPodcastSubscriptionNotifier extends PodcastSubscriptionNotifier {
  _TestPodcastSubscriptionNotifier(this._initialState);

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
