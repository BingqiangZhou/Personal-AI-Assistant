import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/audio_player_state_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_state_models.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_episodes_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_bottom_player_widget.dart';

void main() {
  group('PodcastEpisodesPage bottom spacer', () {
    testWidgets('mobile shows white spacer under player when player exists', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(390, 844);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      final audioNotifier = _TestAudioPlayerNotifier(
        AudioPlayerState(currentEpisode: _episode(), duration: 180000),
      );
      final episodesNotifier = _TestPodcastEpisodesNotifier(
        const PodcastEpisodesState(episodes: [], hasMore: false, total: 0),
      );

      await tester.pumpWidget(
        _createWidget(
          audioNotifier: audioNotifier,
          episodesNotifier: episodesNotifier,
        ),
      );
      await tester.pumpAndSettle();

      final playerFinder = find.byType(PodcastBottomPlayerWidget);
      expect(playerFinder, findsOneWidget);
      final playerWidget = tester.widget<PodcastBottomPlayerWidget>(
        playerFinder,
      );
      expect(playerWidget.applySafeArea, isFalse);

      final spacerFinder = find.byKey(
        const Key('podcast_episodes_mobile_bottom_spacer'),
      );
      expect(spacerFinder, findsOneWidget);
      final spacerContainer = tester.widget<Container>(spacerFinder);
      final theme = Theme.of(tester.element(spacerFinder));
      expect(spacerContainer.color, theme.colorScheme.surface);
      expect(tester.getRect(spacerFinder).height, closeTo(65.0, 0.1));
    });

    testWidgets('mobile expanded player keeps white spacer background', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(390, 844);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      final audioNotifier = _TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _episode(),
          duration: 180000,
          isExpanded: true,
        ),
      );
      final episodesNotifier = _TestPodcastEpisodesNotifier(
        const PodcastEpisodesState(episodes: [], hasMore: false, total: 0),
      );

      await tester.pumpWidget(
        _createWidget(
          audioNotifier: audioNotifier,
          episodesNotifier: episodesNotifier,
        ),
      );
      await tester.pumpAndSettle();

      final spacerFinder = find.byKey(
        const Key('podcast_episodes_mobile_bottom_spacer'),
      );
      expect(spacerFinder, findsOneWidget);
      final spacerContainer = tester.widget<Container>(spacerFinder);
      final theme = Theme.of(tester.element(spacerFinder));
      expect(spacerContainer.color, theme.colorScheme.surface);
      expect(tester.getRect(spacerFinder).height, closeTo(65.0, 0.1));
    });

    testWidgets('mobile does not show spacer when player does not exist', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(390, 844);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      final audioNotifier = _TestAudioPlayerNotifier(const AudioPlayerState());
      final episodesNotifier = _TestPodcastEpisodesNotifier(
        const PodcastEpisodesState(episodes: [], hasMore: false, total: 0),
      );

      await tester.pumpWidget(
        _createWidget(
          audioNotifier: audioNotifier,
          episodesNotifier: episodesNotifier,
        ),
      );
      await tester.pumpAndSettle();

      expect(
        find.byKey(const Key('podcast_episodes_mobile_bottom_spacer')),
        findsNothing,
      );
      expect(find.byType(PodcastBottomPlayerWidget), findsNothing);
    });

    testWidgets('switching subscription triggers forced reload once', (
      tester,
    ) async {
      final audioNotifier = _TestAudioPlayerNotifier(const AudioPlayerState());
      final episodesNotifier = _TestPodcastEpisodesNotifier(
        const PodcastEpisodesState(episodes: [], hasMore: false, total: 0),
      );

      await tester.pumpWidget(
        _createWidget(
          audioNotifier: audioNotifier,
          episodesNotifier: episodesNotifier,
          subscriptionId: 1,
        ),
      );
      await tester.pumpAndSettle();

      await tester.pumpWidget(
        _createWidget(
          audioNotifier: audioNotifier,
          episodesNotifier: episodesNotifier,
          subscriptionId: 2,
        ),
      );
      await tester.pumpAndSettle();

      expect(episodesNotifier.loadCalls.length, 2);
      expect(episodesNotifier.loadCalls.first.subscriptionId, 1);
      expect(episodesNotifier.loadCalls.first.forceRefresh, isFalse);
      expect(episodesNotifier.loadCalls.last.subscriptionId, 2);
      expect(episodesNotifier.loadCalls.last.forceRefresh, isTrue);
    });
  });
}

Widget _createWidget({
  required _TestAudioPlayerNotifier audioNotifier,
  required _TestPodcastEpisodesNotifier episodesNotifier,
  int subscriptionId = 1,
}) {
  return ProviderScope(
    overrides: [
      audioPlayerProvider.overrideWith(() => audioNotifier),
      podcastEpisodesProvider.overrideWith(() => episodesNotifier),
    ],
    child: MaterialApp(
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: PodcastEpisodesPage(
        subscriptionId: subscriptionId,
        podcastTitle: 'Demo',
      ),
    ),
  );
}

class _TestAudioPlayerNotifier extends AudioPlayerNotifier {
  _TestAudioPlayerNotifier(this._initialState);

  final AudioPlayerState _initialState;

  @override
  AudioPlayerState build() {
    return _initialState;
  }
}

class _TestPodcastEpisodesNotifier extends PodcastEpisodesNotifier {
  _TestPodcastEpisodesNotifier(this._initialState);

  final PodcastEpisodesState _initialState;
  final List<_LoadEpisodesCall> loadCalls = [];

  @override
  PodcastEpisodesState build() {
    return _initialState;
  }

  @override
  Future<void> loadEpisodesForSubscription({
    required int subscriptionId,
    int page = 1,
    int size = 20,
    String? status,
    bool? hasSummary,
    bool forceRefresh = false,
  }) async {
    loadCalls.add(
      _LoadEpisodesCall(
        subscriptionId: subscriptionId,
        forceRefresh: forceRefresh,
      ),
    );
  }

  @override
  Future<void> loadMoreEpisodesForSubscription({
    required int subscriptionId,
    String? status,
    bool? hasSummary,
  }) async {}

  @override
  Future<void> refreshEpisodesForSubscription({
    required int subscriptionId,
    String? status,
    bool? hasSummary,
  }) async {}
}

class _LoadEpisodesCall {
  const _LoadEpisodesCall({
    required this.subscriptionId,
    required this.forceRefresh,
  });

  final int subscriptionId;
  final bool forceRefresh;
}

PodcastEpisodeModel _episode() {
  final now = DateTime.now();
  return PodcastEpisodeModel(
    id: 1,
    subscriptionId: 1,
    title: 'Test Episode',
    description: 'Description',
    audioUrl: 'https://example.com/audio.mp3',
    publishedAt: now,
    createdAt: now,
  );
}
