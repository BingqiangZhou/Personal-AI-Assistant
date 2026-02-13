import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
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

      await _pumpHomePage(tester, audioNotifier: audioNotifier, initialTab: 0);

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
          initialTab: 0,
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

  @override
  AudioPlayerState build() {
    return _initialState;
  }

  @override
  void setExpanded(bool expanded) {
    setExpandedCalls += 1;
    state = state.copyWith(isExpanded: expanded);
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
