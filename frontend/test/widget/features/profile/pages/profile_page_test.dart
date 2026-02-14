import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/network/dio_client.dart';
import 'package:personal_ai_assistant/core/providers/core_providers.dart';
import 'package:personal_ai_assistant/core/services/app_cache_service.dart';
import 'package:personal_ai_assistant/core/storage/local_storage_service.dart';
import 'package:personal_ai_assistant/features/auth/domain/models/user.dart';
import 'package:personal_ai_assistant/features/auth/presentation/providers/auth_provider.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/profile_stats_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_state_models.dart';
import 'package:personal_ai_assistant/features/podcast/data/repositories/podcast_repository.dart';
import 'package:personal_ai_assistant/features/podcast/data/services/podcast_api_service.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/profile/presentation/pages/profile_page.dart';
import 'package:shared_preferences/shared_preferences.dart';

class _TestAuthNotifier extends AuthNotifier {
  @override
  AuthState build() {
    return AuthState(
      isAuthenticated: true,
      user: User(
        id: '1',
        email: 'test@example.com',
        username: 'tester',
        fullName: 'Test User',
        isVerified: true,
        isActive: true,
      ),
    );
  }
}

class _ThrowingPodcastApiService extends Mock implements PodcastApiService {}

class _ThrowingPodcastRepository extends PodcastRepository {
  _ThrowingPodcastRepository() : super(_ThrowingPodcastApiService());

  @override
  Future<ProfileStatsModel> getProfileStats() async {
    throw Exception('profile stats failed');
  }
}

class _TestPodcastSubscriptionNotifier extends PodcastSubscriptionNotifier {
  @override
  PodcastSubscriptionState build() {
    return const PodcastSubscriptionState(total: 5);
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

class _MockDioClient extends Mock implements DioClient {
  @override
  Future<void> clearCache() => super.noSuchMethod(
        Invocation.method(#clearCache, []),
        returnValue: Future<void>.value(),
        returnValueForMissingStub: Future<void>.value(),
      ) as Future<void>;

  @override
  void clearETagCache() => super.noSuchMethod(
        Invocation.method(#clearETagCache, []),
        returnValueForMissingStub: null,
      );
}

class _MockAppCacheService extends Mock implements AppCacheService {
  @override
  Future<void> clearAll() => super.noSuchMethod(
        Invocation.method(#clearAll, []),
        returnValue: Future<void>.value(),
        returnValueForMissingStub: Future<void>.value(),
      ) as Future<void>;
}

const MethodChannel _packageInfoChannel = MethodChannel(
  'dev.fluttercommunity.plus/package_info',
);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUpAll(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_packageInfoChannel, (methodCall) async {
          if (methodCall.method == 'getAll') {
            return <String, dynamic>{
              'appName': 'Personal AI Assistant',
              'packageName': 'com.example.personal_ai_assistant',
              'version': '1.2.3',
              'buildNumber': '123',
              'buildSignature': '',
              'installerStore': null,
            };
          }
          return null;
        });
  });

  tearDownAll(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_packageInfoChannel, null);
  });

  setUp(() {
    SharedPreferences.setMockInitialValues({});
  });

  testWidgets(
    'renders lightweight stats with viewed count from playedEpisodes',
    (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith(_TestAuthNotifier.new),
            profileStatsProvider.overrideWith((ref) async {
              return const ProfileStatsModel(
                totalSubscriptions: 1,
                totalEpisodes: 23,
                summariesGenerated: 12,
                pendingSummaries: 11,
                playedEpisodes: 8,
              );
            }),
            podcastSubscriptionProvider.overrideWith(
              _TestPodcastSubscriptionNotifier.new,
            ),
          ],
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: const Scaffold(body: ProfilePage()),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('23'), findsOneWidget);
      expect(find.text('12'), findsOneWidget);
      expect(find.text('8'), findsOneWidget);
      expect(find.text('5'), findsOneWidget);
      expect(
        find.byKey(const Key('profile_viewed_card_chevron')),
        findsOneWidget,
      );
    },
  );

  testWidgets('shows loading placeholders when profile stats is loading', (
    WidgetTester tester,
  ) async {
    final pending = Completer<ProfileStatsModel?>();

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          profileStatsProvider.overrideWith((ref) => pending.future),
            podcastSubscriptionProvider.overrideWith(
              _TestPodcastSubscriptionNotifier.new,
            ),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pump();

    expect(find.text('...'), findsNWidgets(3));
    expect(find.text('5'), findsOneWidget);
  });

  testWidgets('falls back to 0 when profile stats provider returns null', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          profileStatsProvider.overrideWith((ref) async => null),
            podcastSubscriptionProvider.overrideWith(
              _TestPodcastSubscriptionNotifier.new,
            ),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pumpAndSettle();

      expect(find.text('0'), findsNWidgets(3));
      expect(find.text('5'), findsOneWidget);
  });

  testWidgets('falls back to 0 when repository throws in provider chain', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          podcastRepositoryProvider.overrideWithValue(
            _ThrowingPodcastRepository(),
          ),
            podcastSubscriptionProvider.overrideWith(
              _TestPodcastSubscriptionNotifier.new,
            ),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pumpAndSettle();

      expect(find.text('0'), findsNWidgets(3));
      expect(find.text('5'), findsOneWidget);
  });

  testWidgets('clear cache entry triggers cache clear flow', (
    WidgetTester tester,
  ) async {
    final dioClient = _MockDioClient();
    final cacheService = _MockAppCacheService();

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          profileStatsProvider.overrideWith((ref) async {
            return const ProfileStatsModel(
              totalSubscriptions: 1,
              totalEpisodes: 23,
              summariesGenerated: 12,
              pendingSummaries: 11,
              playedEpisodes: 8,
            );
          }),
          podcastSubscriptionProvider.overrideWith(
            _TestPodcastSubscriptionNotifier.new,
          ),
          dioClientProvider.overrideWithValue(dioClient),
          appCacheServiceProvider.overrideWithValue(cacheService),
        ],
        child: MaterialApp(
          locale: const Locale('en'),
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pumpAndSettle();

    final clearCacheItem = find.byKey(const Key('profile_clear_cache_item'));
    await tester.scrollUntilVisible(
      clearCacheItem,
      300,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.tap(clearCacheItem);
    await tester.pumpAndSettle();

    await tester.tap(find.widgetWithText(FilledButton, 'Clear'));
    await tester.pumpAndSettle();

    verify(dioClient.clearCache()).called(1);
    verify(dioClient.clearETagCache()).called(1);
    verify(cacheService.clearAll()).called(1);

    await tester.pump(const Duration(seconds: 4));
    await tester.pumpAndSettle();
  });

  testWidgets('removes settings entries and updates action buttons', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          profileStatsProvider.overrideWith((ref) async {
            return const ProfileStatsModel(
              totalSubscriptions: 1,
              totalEpisodes: 23,
              summariesGenerated: 12,
              pendingSummaries: 11,
              playedEpisodes: 8,
            );
          }),
          podcastSubscriptionProvider.overrideWith(
            _TestPodcastSubscriptionNotifier.new,
          ),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pumpAndSettle();

    final context = tester.element(find.byType(ProfilePage));
    final l10n = AppLocalizations.of(context)!;

    expect(find.text(l10n.profile_edit_profile), findsNothing);
    expect(find.text(l10n.profile_auto_sync), findsNothing);

    expect(
      find.byKey(const Key('profile_user_menu_button')),
      findsOneWidget,
    );
  });

  testWidgets('top logout and user edit buttons open expected dialogs', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          profileStatsProvider.overrideWith((ref) async {
            return const ProfileStatsModel(
              totalSubscriptions: 1,
              totalEpisodes: 23,
              summariesGenerated: 12,
              pendingSummaries: 11,
              playedEpisodes: 8,
            );
          }),
          podcastSubscriptionProvider.overrideWith(
            _TestPodcastSubscriptionNotifier.new,
          ),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pumpAndSettle();
    final context = tester.element(find.byType(ProfilePage));
    final l10n = AppLocalizations.of(context)!;

    await tester.tap(find.byKey(const Key('profile_user_menu_button')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('profile_user_menu_item_logout')));
    await tester.pumpAndSettle();
    expect(find.text(l10n.profile_logout_message), findsOneWidget);

    await tester.tap(find.text(l10n.cancel));
    await tester.pumpAndSettle();

    await tester.tap(find.byKey(const Key('profile_user_menu_button')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('profile_user_menu_item_edit')));
    await tester.pumpAndSettle();
    expect(find.text(l10n.profile_edit_profile), findsOneWidget);
  });

  testWidgets('uses updated icons and consistent dialog widths on mobile', (
    WidgetTester tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          profileStatsProvider.overrideWith((ref) async {
            return const ProfileStatsModel(
              totalSubscriptions: 1,
              totalEpisodes: 23,
              summariesGenerated: 12,
              pendingSummaries: 11,
              playedEpisodes: 8,
            );
          }),
          podcastSubscriptionProvider.overrideWith(
            _TestPodcastSubscriptionNotifier.new,
          ),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pumpAndSettle();
    final context = tester.element(find.byType(ProfilePage));
    final l10n = AppLocalizations.of(context)!;

    final securityTile = tester.widget<ListTile>(
      find.widgetWithText(ListTile, l10n.profile_security),
    );

    expect((securityTile.leading as Icon).icon, Icons.shield);

    await tester.tap(find.byKey(const Key('profile_user_menu_button')));
    await tester.pumpAndSettle();
    expect(
      find.descendant(
        of: find.byKey(const Key('profile_user_menu_item_logout')),
        matching: find.byIcon(Icons.logout),
      ),
      findsOneWidget,
    );
    expect(
      find.descendant(
        of: find.byKey(const Key('profile_user_menu_item_edit')),
        matching: find.byIcon(Icons.edit_note),
      ),
      findsOneWidget,
    );
    await tester.tap(find.byKey(const Key('profile_user_menu_item_edit')));
    await tester.pumpAndSettle();
    final editDialogWidth = tester.getSize(find.byType(AlertDialog)).width;
    await tester.tap(find.text(l10n.cancel));
    await tester.pumpAndSettle();

    final languageTile = find.widgetWithText(ListTile, l10n.language);
    await tester.ensureVisible(languageTile);
    await tester.tap(languageTile);
    await tester.pumpAndSettle();
    final languageDialogWidth = tester.getSize(find.byType(AlertDialog)).width;
    await tester.tap(find.text(l10n.close));
    await tester.pumpAndSettle();

    final securityTileFinder = find.widgetWithText(
      ListTile,
      l10n.profile_security,
    );
    await tester.ensureVisible(securityTileFinder);
    await tester.tap(securityTileFinder);
    await tester.pumpAndSettle();
    final securityDialogWidth = tester.getSize(find.byType(AlertDialog)).width;
    await tester.tap(find.text(l10n.close));
    await tester.pumpAndSettle();

    final helpTile = find.widgetWithText(ListTile, l10n.profile_help_center);
    await tester.ensureVisible(helpTile);
    await tester.tap(helpTile);
    await tester.pumpAndSettle();
    final helpDialogWidth = tester.getSize(find.byType(AlertDialog)).width;
    await tester.tap(find.text(l10n.close));
    await tester.pumpAndSettle();

    final versionTile = find.byKey(const Key('profile_version_item'));
    await tester.ensureVisible(versionTile);
    await tester.tap(versionTile);
    await tester.pump(const Duration(milliseconds: 1300));
    await tester.pumpAndSettle();
    final aboutDialogWidth = tester.getSize(find.byType(AlertDialog)).width;
    await tester.tap(find.text(l10n.ok));
    await tester.pumpAndSettle();

    expect(editDialogWidth, closeTo(languageDialogWidth, 0.01));
    expect(securityDialogWidth, closeTo(languageDialogWidth, 0.01));
    expect(helpDialogWidth, closeTo(languageDialogWidth, 0.01));
    expect(aboutDialogWidth, closeTo(languageDialogWidth, 0.01));
  });

  testWidgets('single tap version opens about and 5 taps opens server config', (
    WidgetTester tester,
  ) async {
    final prefs = await SharedPreferences.getInstance();
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          profileStatsProvider.overrideWith((ref) async {
            return const ProfileStatsModel(
              totalSubscriptions: 1,
              totalEpisodes: 23,
              summariesGenerated: 12,
              pendingSummaries: 11,
              playedEpisodes: 8,
            );
          }),
          localStorageServiceProvider.overrideWithValue(
            LocalStorageServiceImpl(prefs),
          ),
          podcastSubscriptionProvider.overrideWith(
            _TestPodcastSubscriptionNotifier.new,
          ),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pumpAndSettle();
    final context = tester.element(find.byType(ProfilePage));
    final l10n = AppLocalizations.of(context)!;
    final versionFinder = find.byKey(const Key('profile_version_item'));

    await tester.ensureVisible(versionFinder);
    await tester.tap(versionFinder);
    await tester.pump(const Duration(milliseconds: 1300));
    await tester.pumpAndSettle();
    expect(find.text(l10n.appTitle), findsOneWidget);

    await tester.tap(find.text(l10n.ok));
    await tester.pumpAndSettle();

    await tester.ensureVisible(versionFinder);
    for (var i = 0; i < 5; i++) {
      await tester.tap(versionFinder);
      await tester.pump(const Duration(milliseconds: 100));
    }
    await tester.pumpAndSettle();
    expect(find.text(l10n.backend_api_server_config), findsOneWidget);
  });

  testWidgets('two taps on version does not trigger dialogs', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          profileStatsProvider.overrideWith((ref) async {
            return const ProfileStatsModel(
              totalSubscriptions: 1,
              totalEpisodes: 23,
              summariesGenerated: 12,
              pendingSummaries: 11,
              playedEpisodes: 8,
            );
          }),
          podcastSubscriptionProvider.overrideWith(
            _TestPodcastSubscriptionNotifier.new,
          ),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pumpAndSettle();
    final context = tester.element(find.byType(ProfilePage));
    final l10n = AppLocalizations.of(context)!;
    final versionFinder = find.byKey(const Key('profile_version_item'));

    await tester.ensureVisible(versionFinder);
    await tester.tap(versionFinder);
    await tester.pump(const Duration(milliseconds: 100));
    await tester.tap(versionFinder);
    await tester.pump(const Duration(milliseconds: 1300));
    await tester.pumpAndSettle();

    expect(find.text(l10n.appTitle), findsNothing);
    expect(find.text(l10n.backend_api_server_config), findsNothing);
  });

  testWidgets('uses feed-style card shape and width on mobile profile cards', (
    WidgetTester tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          profileStatsProvider.overrideWith((ref) async {
            return const ProfileStatsModel(
              totalSubscriptions: 1,
              totalEpisodes: 23,
              summariesGenerated: 12,
              pendingSummaries: 11,
              playedEpisodes: 8,
            );
          }),
          podcastSubscriptionProvider.overrideWith(
            _TestPodcastSubscriptionNotifier.new,
          ),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pumpAndSettle();

    final cards = tester.widgetList<Card>(find.byType(Card)).toList();
    expect(cards, isNotEmpty);

    for (final card in cards) {
      expect(card.margin, const EdgeInsets.symmetric(horizontal: 4));
      expect(card.shape, isA<RoundedRectangleBorder>());

      final shape = card.shape! as RoundedRectangleBorder;
      expect(shape.borderRadius, BorderRadius.circular(12));
      expect(shape.side.style, BorderStyle.none);
      expect(shape.side.width, 0);
    }
  });

  testWidgets('keeps desktop profile cards unchanged', (
    WidgetTester tester,
  ) async {
    tester.view.physicalSize = const Size(1200, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          authProvider.overrideWith(_TestAuthNotifier.new),
          profileStatsProvider.overrideWith((ref) async {
            return const ProfileStatsModel(
              totalSubscriptions: 1,
              totalEpisodes: 23,
              summariesGenerated: 12,
              pendingSummaries: 11,
              playedEpisodes: 8,
            );
          }),
          podcastSubscriptionProvider.overrideWith(
            _TestPodcastSubscriptionNotifier.new,
          ),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(body: ProfilePage()),
        ),
      ),
    );

    await tester.pumpAndSettle();

    expect(
      find.byKey(const Key('profile_viewed_card_chevron')),
      findsOneWidget,
    );

    final cards = tester.widgetList<Card>(find.byType(Card)).toList();
    expect(cards, isNotEmpty);

    for (final card in cards) {
      expect(card.margin, EdgeInsets.zero);
      expect(card.shape, isNull);
    }
  });
}
