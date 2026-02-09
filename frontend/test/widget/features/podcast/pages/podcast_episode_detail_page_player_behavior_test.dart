import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/audio_player_state_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_transcription_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_episode_detail_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/transcription_providers.dart';

void main() {
  group('PodcastEpisodeDetailPage player behavior', () {
    testWidgets('shows bottom player and auto-collapses on upward scroll', (
      tester,
    ) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _episode(),
          duration: 180000,
          isExpanded: true,
          isPlaying: true,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      expect(
        find.byKey(const Key('podcast_bottom_player_expanded')),
        findsOneWidget,
      );

      final context = tester.element(find.byType(PageView).first);
      final metrics = FixedScrollMetrics(
        minScrollExtent: 0,
        maxScrollExtent: 400,
        pixels: 100,
        viewportDimension: 400,
        axisDirection: AxisDirection.down,
        devicePixelRatio: 1.0,
      );
      ScrollUpdateNotification(
        metrics: metrics,
        context: context,
        scrollDelta: 12.0,
      ).dispatch(context);

      await tester.pumpAndSettle();

      expect(notifier.state.isExpanded, isFalse);
      expect(
        find.byKey(const Key('podcast_bottom_player_mini')),
        findsOneWidget,
      );
    });

    testWidgets('does not auto-expand on downward scroll', (tester) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _episode(),
          duration: 180000,
          isExpanded: false,
          isPlaying: true,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      final context = tester.element(find.byType(PageView).first);
      final metrics = FixedScrollMetrics(
        minScrollExtent: 0,
        maxScrollExtent: 400,
        pixels: 100,
        viewportDimension: 400,
        axisDirection: AxisDirection.down,
        devicePixelRatio: 1.0,
      );
      ScrollUpdateNotification(
        metrics: metrics,
        context: context,
        scrollDelta: -12.0,
      ).dispatch(context);

      await tester.pumpAndSettle();

      expect(notifier.state.isExpanded, isFalse);
      expect(
        find.byKey(const Key('podcast_bottom_player_mini')),
        findsOneWidget,
      );
    });

    testWidgets('same episode paused tap should call resume only', (
      tester,
    ) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _episode(),
          duration: 180000,
          isPlaying: false,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      final playButton = find.byKey(
        const Key('podcast_episode_detail_play_button'),
      );
      expect(playButton, findsOneWidget);

      await tester.tap(playButton);
      await tester.pump();

      expect(notifier.resumeCalls, 1);
      expect(notifier.playEpisodeCalls, 0);
    });

    testWidgets('same episode playing tap should no-op', (tester) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _episode(),
          duration: 180000,
          isPlaying: true,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      final playButton = find.byKey(
        const Key('podcast_episode_detail_play_button'),
      );
      expect(playButton, findsOneWidget);

      await tester.tap(playButton);
      await tester.pump();

      expect(notifier.resumeCalls, 0);
      expect(notifier.playEpisodeCalls, 0);
    });

    testWidgets('different episode tap should call playEpisode', (
      tester,
    ) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _otherEpisode(),
          duration: 180000,
          isPlaying: false,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      final playButton = find.byKey(
        const Key('podcast_episode_detail_play_button'),
      );
      expect(playButton, findsOneWidget);

      await tester.tap(playButton);
      await tester.pump();

      expect(notifier.playEpisodeCalls, 1);
      expect(notifier.resumeCalls, 0);
    });
  });
}

Widget _createWidget(TestAudioPlayerNotifier notifier) {
  return ProviderScope(
    overrides: [
      audioPlayerProvider.overrideWith(() => notifier),
      episodeDetailProvider.overrideWith(
        (ref, episodeId) async => _episodeDetail(),
      ),
      getTranscriptionProvider(
        1,
      ).overrideWith(() => MockTranscriptionNotifier(1)),
    ],
    child: MaterialApp(
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: const PodcastEpisodeDetailPage(episodeId: 1),
    ),
  );
}

PodcastEpisodeModel _episode() {
  final now = DateTime.now();
  return PodcastEpisodeModel(
    id: 1,
    subscriptionId: 1,
    title: 'Detail Episode',
    description: 'A long long description to support detail content rendering.',
    audioUrl: 'https://example.com/audio.mp3',
    publishedAt: now,
    createdAt: now,
    audioDuration: 180,
  );
}

PodcastEpisodeModel _otherEpisode() {
  final now = DateTime.now();
  return PodcastEpisodeModel(
    id: 2,
    subscriptionId: 1,
    title: 'Another Episode',
    description: 'Another episode for mismatch scenario.',
    audioUrl: 'https://example.com/audio-2.mp3',
    publishedAt: now,
    createdAt: now,
    audioDuration: 200,
  );
}

PodcastEpisodeDetailResponse _episodeDetail() {
  final now = DateTime.now();
  return PodcastEpisodeDetailResponse(
    id: 1,
    subscriptionId: 1,
    title: 'Detail Episode',
    description: List.filled(80, 'This is shownotes content').join(' '),
    audioUrl: 'https://example.com/audio.mp3',
    audioDuration: 180,
    publishedAt: now,
    aiSummary: 'summary',
    transcriptContent: 'transcript',
    status: 'published',
    createdAt: now,
    updatedAt: now,
    subscription: null,
    relatedEpisodes: const [],
  );
}

class TestAudioPlayerNotifier extends AudioPlayerNotifier {
  TestAudioPlayerNotifier(this._initialState);

  final AudioPlayerState _initialState;
  int playEpisodeCalls = 0;
  int resumeCalls = 0;

  @override
  AudioPlayerState build() {
    return _initialState;
  }

  @override
  void setExpanded(bool expanded) {
    state = state.copyWith(isExpanded: expanded);
  }

  @override
  Future<void> pause() async {
    state = state.copyWith(isPlaying: false);
  }

  @override
  Future<void> resume() async {
    resumeCalls++;
    state = state.copyWith(isPlaying: true);
  }

  @override
  Future<void> playEpisode(
    PodcastEpisodeModel episode, {
    PlaySource source = PlaySource.direct,
    int? queueEpisodeId,
  }) async {
    playEpisodeCalls++;
    state = state.copyWith(
      currentEpisode: episode,
      isPlaying: true,
      isLoading: false,
      error: null,
    );
  }

  @override
  Future<void> seekTo(int position) async {
    state = state.copyWith(position: position);
  }

  @override
  Future<void> setPlaybackRate(double rate) async {
    state = state.copyWith(playbackRate: rate);
  }

  @override
  Future<void> stop() async {
    state = state.copyWith(clearCurrentEpisode: true);
  }
}

class MockTranscriptionNotifier extends TranscriptionNotifier {
  MockTranscriptionNotifier(super.episodeId);

  @override
  Future<PodcastTranscriptionResponse?> build() async {
    return null;
  }

  @override
  Future<void> checkOrStartTranscription() async {}

  @override
  Future<void> startTranscription() async {}

  @override
  Future<void> loadTranscription() async {}
}
