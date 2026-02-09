import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/audio_player_state_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_bottom_player_widget.dart';

void main() {
  group('PodcastBottomPlayerWidget', () {
    testWidgets('does not render when no episode is loaded', (tester) async {
      final notifier = TestAudioPlayerNotifier(const AudioPlayerState());

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('podcast_bottom_player_mini')), findsNothing);
      expect(
        find.byKey(const Key('podcast_bottom_player_expanded')),
        findsNothing,
      );
    });

    testWidgets('renders mini player when episode exists', (tester) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          position: 25000,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      expect(
        find.byKey(const Key('podcast_bottom_player_mini')),
        findsOneWidget,
      );
      expect(find.text('Test Episode'), findsOneWidget);
    });

    testWidgets('mini player height matches profile menu button height', (
      tester,
    ) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          position: 25000,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      final miniSize = tester.getSize(
        find.byKey(const Key('podcast_bottom_player_mini')),
      );
      expect(miniSize.height, 56);
    });

    testWidgets('desktop mini visual wrapper height is 64', (tester) async {
      tester.view.physicalSize = const Size(1200, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          position: 25000,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      final wrapperSize = tester.getSize(
        find.byKey(const Key('podcast_bottom_player_mini_wrapper')),
      );
      expect(wrapperSize.height, 64);
    });

    testWidgets('desktop mini elevation is 0 for visual height alignment', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(1200, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          position: 25000,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      final miniMaterial = tester.widget<Material>(
        find.byKey(const Key('podcast_bottom_player_mini')),
      );
      expect(miniMaterial.elevation, 0);
    });

    testWidgets('expands when mini player is tapped', (tester) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(currentEpisode: _testEpisode(), duration: 180000),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('podcast_bottom_player_mini')));
      await tester.pumpAndSettle();

      expect(
        find.byKey(const Key('podcast_bottom_player_expanded')),
        findsOneWidget,
      );
      expect(notifier.state.isExpanded, isTrue);
    });

    testWidgets('play pause button triggers notifier action', (tester) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          isExpanded: true,
          isPlaying: true,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      await tester.tap(
        find.byKey(const Key('podcast_bottom_player_play_pause')),
      );
      await tester.pumpAndSettle();

      expect(notifier.pauseCalls, 1);
      expect(notifier.state.isPlaying, isFalse);
    });

    testWidgets('expanded player does not show play/pause text labels', (
      tester,
    ) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          isExpanded: true,
          isPlaying: false,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      expect(find.text('Play'), findsNothing);
      expect(find.text('Pause'), findsNothing);
    });

    testWidgets(
      'expanded controls order is speed -> rewind -> play/pause -> forward -> playlist',
      (tester) async {
        tester.view.physicalSize = const Size(1200, 900);
        tester.view.devicePixelRatio = 1.0;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        final notifier = TestAudioPlayerNotifier(
          AudioPlayerState(
            currentEpisode: _testEpisode(),
            duration: 180000,
            isExpanded: true,
          ),
        );

        await tester.pumpWidget(_createWidget(notifier));
        await tester.pumpAndSettle();

        final speed = tester.getRect(
          find.byKey(const Key('podcast_bottom_player_speed')),
        );
        final rewind = tester.getRect(
          find.byKey(const Key('podcast_bottom_player_rewind_10')),
        );
        final playPause = tester.getRect(
          find.byKey(const Key('podcast_bottom_player_play_pause')),
        );
        final forward = tester.getRect(
          find.byKey(const Key('podcast_bottom_player_forward_30')),
        );
        final playlist = tester.getRect(
          find.byKey(const Key('podcast_bottom_player_playlist')),
        );

        expect(speed.left, lessThan(rewind.left));
        expect(rewind.left, lessThan(playPause.left));
        expect(playPause.left, lessThan(forward.left));
        expect(forward.left, lessThan(playlist.left));
      },
    );

    testWidgets('playlist icon is visible in expanded mode', (tester) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          isExpanded: true,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      expect(
        find.byKey(const Key('podcast_bottom_player_playlist')),
        findsOneWidget,
      );
    });

    testWidgets('tap playlist icon shows placeholder snackbar', (tester) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          isExpanded: true,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('podcast_bottom_player_playlist')));
      await tester.pump();

      expect(find.byType(SnackBar), findsOneWidget);
      expect(
        find.text('Playlist coming soon').evaluate().isNotEmpty ||
            find.text('播放列表即将上线').evaluate().isNotEmpty,
        isTrue,
      );
    });
  });
}

Widget _createWidget(TestAudioPlayerNotifier notifier) {
  return ProviderScope(
    overrides: [audioPlayerProvider.overrideWith(() => notifier)],
    child: const MaterialApp(
      home: Scaffold(
        body: SizedBox.shrink(),
        bottomNavigationBar: PodcastBottomPlayerWidget(),
      ),
    ),
  );
}

PodcastEpisodeModel _testEpisode() {
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

class TestAudioPlayerNotifier extends AudioPlayerNotifier {
  TestAudioPlayerNotifier(this._initialState);

  final AudioPlayerState _initialState;
  int pauseCalls = 0;

  @override
  AudioPlayerState build() {
    return _initialState;
  }

  @override
  Future<void> pause() async {
    pauseCalls++;
    state = state.copyWith(isPlaying: false);
  }

  @override
  Future<void> resume() async {
    state = state.copyWith(isPlaying: true);
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
    state = state.copyWith(
      clearCurrentEpisode: true,
      isPlaying: false,
      position: 0,
    );
  }

  @override
  void setExpanded(bool expanded) {
    state = state.copyWith(isExpanded: expanded);
  }
}
