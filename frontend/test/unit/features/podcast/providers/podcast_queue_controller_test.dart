import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/audio_player_state_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_queue_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/repositories/podcast_repository.dart';
import 'package:personal_ai_assistant/features/podcast/data/services/podcast_api_service.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';

void main() {
  group('PodcastQueueController.addToQueue', () {
    test('deduplicates in-flight requests for the same episode', () async {
      final repository = _FakePodcastRepository(
        addDelay: const Duration(milliseconds: 80),
      );
      final container = ProviderContainer(
        overrides: [
          podcastRepositoryProvider.overrideWithValue(repository),
          audioPlayerProvider.overrideWith(() => _FakeAudioPlayerNotifier()),
        ],
      );
      addTearDown(container.dispose);

      final notifier = container.read(podcastQueueControllerProvider.notifier);
      final first = notifier.addToQueue(42);
      final second = notifier.addToQueue(42);

      await Future.wait([first, second]);

      expect(repository.addQueueItemCallCount, 1);
    });
  });
}

class _FakePodcastRepository extends PodcastRepository {
  _FakePodcastRepository({this.addDelay = Duration.zero})
    : super(_NoopPodcastApiService());

  final Duration addDelay;
  int addQueueItemCallCount = 0;

  @override
  Future<PodcastQueueModel> getQueue() async {
    return PodcastQueueModel.empty();
  }

  @override
  Future<PodcastQueueModel> addQueueItem(int episodeId) async {
    addQueueItemCallCount += 1;
    if (addDelay > Duration.zero) {
      await Future<void>.delayed(addDelay);
    }
    return PodcastQueueModel(
      currentEpisodeId: episodeId,
      revision: addQueueItemCallCount,
      items: [
        PodcastQueueItemModel(
          episodeId: episodeId,
          position: 0,
          title: 'Episode $episodeId',
          podcastId: 1,
          audioUrl: 'https://example.com/audio-$episodeId.mp3',
        ),
      ],
    );
  }
}

class _NoopPodcastApiService implements PodcastApiService {
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _FakeAudioPlayerNotifier extends AudioPlayerNotifier {
  @override
  AudioPlayerState build() {
    return const AudioPlayerState();
  }
}
