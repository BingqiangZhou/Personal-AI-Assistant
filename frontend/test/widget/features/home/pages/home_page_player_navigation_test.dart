import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/storage/local_storage_service.dart';
import 'package:personal_ai_assistant/features/auth/domain/models/user.dart';
import 'package:personal_ai_assistant/features/auth/presentation/providers/auth_provider.dart';
import 'package:personal_ai_assistant/features/home/presentation/pages/home_page.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/audio_player_state_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_state_models.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/profile_stats_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/profile/presentation/pages/profile_page.dart';

void main() {
  group('HomePage player navigation behavior', () {
    testWidgets('enters home and triggers restore once', (tester) async {
      final audioNotifier = TestAudioPlayerNotifier(const AudioPlayerState());

      await _pumpHomePage(tester, audioNotifier: audioNotifier, initialTab: 0);

      expect(audioNotifier.restoreCallCount, 1);
    });

    testWidgets('initial profile tab auto-collapses expanded player', (
      tester,
    ) async {
      final audioNotifier = TestAudioPlayerNotifier(
        AudioPlayerState(currentEpisode: _testEpisode(), isExpanded: true),
      );

      await _pumpHomePage(tester, audioNotifier: audioNotifier, initialTab: 2);

      expect(audioNotifier.state.isExpanded, isFalse);
      expect(audioNotifier.setExpandedCalls, greaterThanOrEqualTo(1));
    });

    testWidgets('navigating from feed to profile collapses expanded player', (
      tester,
    ) async {
      final audioNotifier = TestAudioPlayerNotifier(
        AudioPlayerState(currentEpisode: _testEpisode(), isExpanded: true),
      );

      await _pumpHomePage(tester, audioNotifier: audioNotifier, initialTab: 1);

      expect(audioNotifier.state.isExpanded, isTrue);

      await tester.tap(find.byIcon(Icons.person_outline));
      await tester.pumpAndSettle();

      expect(find.byType(ProfilePage), findsOneWidget);
      expect(audioNotifier.state.isExpanded, isFalse);
    });

    testWidgets(
      'profile remains scrollable when player was previously expanded',
      (tester) async {
        final audioNotifier = TestAudioPlayerNotifier(
          AudioPlayerState(currentEpisode: _testEpisode(), isExpanded: true),
        );

        await _pumpHomePage(
          tester,
          audioNotifier: audioNotifier,
          initialTab: 2,
        );

        expect(audioNotifier.state.isExpanded, isFalse);

        final profileScrollView = find.descendant(
          of: find.byType(ProfilePage),
          matching: find.byType(SingleChildScrollView),
        );
        final profileScrollable = find.descendant(
          of: find.byType(ProfilePage),
          matching: find.byType(Scrollable),
        );

        expect(profileScrollView, findsOneWidget);
        expect(profileScrollable, findsWidgets);

        final before = tester
            .state<ScrollableState>(profileScrollable.first)
            .position
            .pixels;

        await tester.drag(profileScrollView, const Offset(0, -300));
        await tester.pumpAndSettle();

        final after = tester
            .state<ScrollableState>(profileScrollable.first)
            .position
            .pixels;
        expect(after, greaterThan(before));
      },
    );

    testWidgets(
      'podcast tab still supports barrier tap to collapse expanded player',
      (tester) async {
        final audioNotifier = TestAudioPlayerNotifier(
          AudioPlayerState(currentEpisode: _testEpisode(), isExpanded: true),
        );

        await _pumpHomePage(
          tester,
          audioNotifier: audioNotifier,
          initialTab: 1,
        );

        expect(
          find.byKey(const Key('podcast_bottom_player_expanded')),
          findsOneWidget,
        );

        await tester.tapAt(const Offset(195, 120));
        await tester.pumpAndSettle();

        expect(audioNotifier.state.isExpanded, isFalse);
        expect(
          find.byKey(const Key('podcast_bottom_player_mini')),
          findsOneWidget,
        );
      },
    );
  });
}

Future<void> _pumpHomePage(
  WidgetTester tester, {
  required TestAudioPlayerNotifier audioNotifier,
  required int initialTab,
}) async {
  tester.view.physicalSize = const Size(390, 640);
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        localStorageServiceProvider.overrideWithValue(
          _MockLocalStorageService(),
        ),
        authProvider.overrideWith(TestAuthNotifier.new),
        audioPlayerProvider.overrideWith(() => audioNotifier),
        podcastFeedProvider.overrideWith(TestPodcastFeedNotifier.new),
        profileStatsProvider.overrideWith((ref) async {
          return const ProfileStatsModel(
            totalSubscriptions: 2,
            totalEpisodes: 8,
            summariesGenerated: 3,
            pendingSummaries: 1,
            playedEpisodes: 4,
          );
        }),
      ],
      child: MaterialApp(
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: HomePage(initialTab: initialTab),
      ),
    ),
  );

  await tester.pumpAndSettle();
}

class TestAuthNotifier extends AuthNotifier {
  @override
  AuthState build() {
    return AuthState(
      isAuthenticated: true,
      user: User(
        id: '1',
        email: 'tester@example.com',
        username: 'tester',
        fullName: 'Test User',
        isVerified: true,
        isActive: true,
      ),
    );
  }
}

class TestAudioPlayerNotifier extends AudioPlayerNotifier {
  TestAudioPlayerNotifier(this._initialState);

  final AudioPlayerState _initialState;
  int setExpandedCalls = 0;
  int restoreCallCount = 0;

  @override
  AudioPlayerState build() {
    return _initialState;
  }

  @override
  void setExpanded(bool expanded) {
    setExpandedCalls += 1;
    state = state.copyWith(isExpanded: expanded);
  }

  @override
  Future<void> restoreLastPlayedEpisodeIfNeeded() async {
    restoreCallCount += 1;
  }
}

class TestPodcastFeedNotifier extends PodcastFeedNotifier {
  @override
  PodcastFeedState build() {
    return const PodcastFeedState();
  }

  @override
  Future<void> loadInitialFeed() async {}

  @override
  Future<void> refreshFeed() async {}

  @override
  Future<void> loadMoreFeed() async {}
}

PodcastEpisodeModel _testEpisode() {
  final now = DateTime.now();
  return PodcastEpisodeModel(
    id: 11,
    subscriptionId: 22,
    title: 'Test Episode',
    description: 'Test Description',
    audioUrl: 'https://example.com/test.mp3',
    publishedAt: now,
    createdAt: now,
  );
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
