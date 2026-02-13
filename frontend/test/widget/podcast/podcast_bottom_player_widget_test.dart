import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/audio_player_state_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_queue_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_bottom_player_widget.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_queue_sheet.dart';

void main() {
  group('PodcastBottomPlayerWidget playlist behavior', () {
    testWidgets('mini playlist button opens queue sheet', (tester) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          isExpanded: false,
        ),
      );
      final queueController = TestPodcastQueueController();

      await tester.pumpWidget(
        _createWidget(notifier: notifier, queueController: queueController),
      );
      await tester.pumpAndSettle();

      await tester.tap(
        find.byKey(const Key('podcast_bottom_player_mini_playlist')),
      );
      await tester.pumpAndSettle();

      expect(find.byType(PodcastQueueSheet), findsOneWidget);
      expect(queueController.loadQueueCalls, 1);
    });

    testWidgets(
      'rapid double tap on mini playlist only opens one queue sheet',
      (tester) async {
        final notifier = TestAudioPlayerNotifier(
          AudioPlayerState(
            currentEpisode: _testEpisode(),
            duration: 180000,
            isExpanded: false,
          ),
        );
        final queueController = TestPodcastQueueController(
          loadDelay: const Duration(milliseconds: 120),
        );

        await tester.pumpWidget(
          _createWidget(notifier: notifier, queueController: queueController),
        );
        await tester.pumpAndSettle();

        final playlistButton = tester.widget<IconButton>(
          find.byKey(const Key('podcast_bottom_player_mini_playlist')),
        );
        playlistButton.onPressed?.call();
        playlistButton.onPressed?.call();
        await tester.pump();
        await tester.pump(const Duration(milliseconds: 150));
        await tester.pumpAndSettle();

        expect(find.byType(PodcastQueueSheet), findsOneWidget);
        expect(queueController.loadQueueCalls, 1);
      },
    );
  });
}

Widget _createWidget({
  required TestAudioPlayerNotifier notifier,
  required TestPodcastQueueController queueController,
}) {
  return ProviderScope(
    overrides: [
      audioPlayerProvider.overrideWith(() => notifier),
      podcastQueueControllerProvider.overrideWith(() => queueController),
    ],
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

  @override
  AudioPlayerState build() {
    return _initialState;
  }

  @override
  void setExpanded(bool expanded) {
    state = state.copyWith(isExpanded: expanded);
  }
}

class TestPodcastQueueController extends PodcastQueueController {
  TestPodcastQueueController({this.loadDelay = Duration.zero});

  final Duration loadDelay;
  int loadQueueCalls = 0;

  @override
  Future<PodcastQueueModel> build() async {
    return PodcastQueueModel.empty();
  }

  @override
  Future<PodcastQueueModel> loadQueue() async {
    loadQueueCalls += 1;
    if (loadDelay > Duration.zero) {
      await Future<void>.delayed(loadDelay);
    }
    state = const AsyncValue.data(PodcastQueueModel());
    return PodcastQueueModel.empty();
  }
}
