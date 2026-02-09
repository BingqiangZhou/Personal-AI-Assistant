import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/audio_player_state_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/audio_player_widget.dart';

void main() {
  group('AudioPlayerWidget speed selector', () {
    setUp(() {
      TestWidgetsFlutterBinding.ensureInitialized();
    });

    testWidgets('shows 3x option and subscription checkbox', (tester) async {
      tester.view.physicalSize = const Size(1200, 1400);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      final notifier = _TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _episode(),
          duration: 180000,
          isExpanded: true,
          playbackRate: 1.0,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('audio_player_speed_button')));
      await tester.pumpAndSettle();

      expect(find.text('3x'), findsOneWidget);
      expect(
        find.text('Only apply to current show (current subscription)'),
        findsOneWidget,
      );
    });

    testWidgets('forwards applyToSubscription in audio player', (tester) async {
      tester.view.physicalSize = const Size(1200, 1400);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      final notifier = _TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _episode(),
          duration: 180000,
          isExpanded: true,
          playbackRate: 1.0,
        ),
      );

      await tester.pumpWidget(_createWidget(notifier));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('audio_player_speed_button')));
      await tester.pumpAndSettle();
      await tester.tap(
        find.text('Only apply to current show (current subscription)'),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('2.5x'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Apply'));
      await tester.pumpAndSettle();

      expect(notifier.lastPlaybackRate, 2.5);
      expect(notifier.lastApplyToSubscription, isTrue);
    });
  });
}

Widget _createWidget(_TestAudioPlayerNotifier notifier) {
  return ProviderScope(
    overrides: [audioPlayerProvider.overrideWith(() => notifier)],
    child: const MaterialApp(home: Scaffold(body: AudioPlayerWidget())),
  );
}

PodcastEpisodeModel _episode() {
  final now = DateTime.now();
  return PodcastEpisodeModel(
    id: 1,
    subscriptionId: 1,
    title: 'Audio Widget Episode',
    description: 'desc',
    audioUrl: 'https://example.com/audio.mp3',
    publishedAt: now,
    createdAt: now,
    audioDuration: 180,
  );
}

class _TestAudioPlayerNotifier extends AudioPlayerNotifier {
  _TestAudioPlayerNotifier(this._initialState);

  final AudioPlayerState _initialState;
  double? lastPlaybackRate;
  bool? lastApplyToSubscription;

  @override
  AudioPlayerState build() => _initialState;

  @override
  Future<void> setPlaybackRate(
    double rate, {
    bool applyToSubscription = false,
  }) async {
    lastPlaybackRate = rate;
    lastApplyToSubscription = applyToSubscription;
    state = state.copyWith(playbackRate: rate);
  }

  @override
  Future<void> pause() async {
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
}
