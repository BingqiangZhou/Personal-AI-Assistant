import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/audio_player_state_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
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

  group('PodcastQueueController.playFromQueue', () {
    test('activates queue item once before playback', () async {
      final repository = _FakePodcastRepository();
      final audioNotifier = _FakeAudioPlayerNotifier();
      final container = ProviderContainer(
        overrides: [
          podcastRepositoryProvider.overrideWithValue(repository),
          audioPlayerProvider.overrideWith(() => audioNotifier),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(
        podcastQueueControllerProvider.notifier,
      );
      await controller.playFromQueue(7);

      expect(repository.activateQueueEpisodeCallCount, 1);
      expect(audioNotifier.playEpisodeCalls, 1);
      expect(audioNotifier.lastPlaySource, PlaySource.queue);
      expect(audioNotifier.lastQueueEpisodeId, 7);
    });
  });

  group('PodcastQueueController queueSyncing', () {
    test('stays true until all in-flight queue operations complete', () async {
      final repository = _FakePodcastRepository();
      repository.removeCompleter = Completer<void>();
      repository.reorderCompleter = Completer<void>();
      final audioNotifier = _FakeAudioPlayerNotifier();
      final container = ProviderContainer(
        overrides: [
          podcastRepositoryProvider.overrideWithValue(repository),
          audioPlayerProvider.overrideWith(() => audioNotifier),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(
        podcastQueueControllerProvider.notifier,
      );
      final removeFuture = controller.removeFromQueue(10);
      final reorderFuture = controller.reorderQueue(<int>[10, 11]);
      await Future<void>.delayed(Duration.zero);

      expect(container.read(audioPlayerProvider).queueSyncing, isTrue);

      repository.removeCompleter!.complete();
      await removeFuture;
      expect(container.read(audioPlayerProvider).queueSyncing, isTrue);

      repository.reorderCompleter!.complete();
      await reorderFuture;
      expect(container.read(audioPlayerProvider).queueSyncing, isFalse);
    });
  });

  group('PodcastQueueController revision guard', () {
    test('ignores stale queue snapshots with lower revision', () async {
      final repository = _FakePodcastRepository(
        queuedGetQueueResponses: <PodcastQueueModel>[
          _queue(revision: 1, currentEpisodeId: 1),
          _queue(revision: 1, currentEpisodeId: 1),
        ],
        reorderQueueResult: _queue(revision: 2, currentEpisodeId: 2),
      );
      final container = ProviderContainer(
        overrides: [
          podcastRepositoryProvider.overrideWithValue(repository),
          audioPlayerProvider.overrideWith(() => _FakeAudioPlayerNotifier()),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(
        podcastQueueControllerProvider.notifier,
      );
      await controller.loadQueue(forceRefresh: true);
      expect(container.read(podcastQueueControllerProvider).value?.revision, 1);

      await controller.reorderQueue(<int>[2, 1]);
      expect(container.read(podcastQueueControllerProvider).value?.revision, 2);

      await controller.loadQueue(forceRefresh: true);
      expect(container.read(podcastQueueControllerProvider).value?.revision, 2);
    });
  });
}

PodcastQueueModel _queue({
  required int revision,
  required int? currentEpisodeId,
}) {
  return PodcastQueueModel(
    currentEpisodeId: currentEpisodeId,
    revision: revision,
    items: const <PodcastQueueItemModel>[
      PodcastQueueItemModel(
        episodeId: 1,
        position: 0,
        title: 'Episode 1',
        podcastId: 1,
        audioUrl: 'https://example.com/audio-1.mp3',
      ),
      PodcastQueueItemModel(
        episodeId: 2,
        position: 1024,
        title: 'Episode 2',
        podcastId: 1,
        audioUrl: 'https://example.com/audio-2.mp3',
      ),
    ],
  );
}

class _FakePodcastRepository extends PodcastRepository {
  _FakePodcastRepository({
    this.addDelay = Duration.zero,
    List<PodcastQueueModel>? queuedGetQueueResponses,
    PodcastQueueModel? reorderQueueResult,
    PodcastQueueModel? activateQueueResult,
  }) : _queuedGetQueueResponses = List<PodcastQueueModel>.from(
         queuedGetQueueResponses ??
             <PodcastQueueModel>[const PodcastQueueModel()],
       ),
       _reorderQueueResult =
           reorderQueueResult ?? const PodcastQueueModel(revision: 1),
       _activateQueueResult =
           activateQueueResult ??
           const PodcastQueueModel(
             currentEpisodeId: 7,
             revision: 1,
             items: <PodcastQueueItemModel>[
               PodcastQueueItemModel(
                 episodeId: 7,
                 position: 0,
                 title: 'Episode 7',
                 podcastId: 1,
                 audioUrl: 'https://example.com/audio-7.mp3',
               ),
             ],
           ),
       super(_NoopPodcastApiService());

  final Duration addDelay;
  final List<PodcastQueueModel> _queuedGetQueueResponses;
  final PodcastQueueModel _reorderQueueResult;
  final PodcastQueueModel _activateQueueResult;

  int addQueueItemCallCount = 0;
  int activateQueueEpisodeCallCount = 0;
  Completer<void>? removeCompleter;
  Completer<void>? reorderCompleter;

  @override
  Future<PodcastQueueModel> getQueue() async {
    if (_queuedGetQueueResponses.length > 1) {
      return _queuedGetQueueResponses.removeAt(0);
    }
    return _queuedGetQueueResponses.first;
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
      items: <PodcastQueueItemModel>[
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

  @override
  Future<PodcastQueueModel> removeQueueItem(int episodeId) async {
    final completer = removeCompleter;
    if (completer != null) {
      await completer.future;
    }
    return const PodcastQueueModel(revision: 10);
  }

  @override
  Future<PodcastQueueModel> reorderQueueItems(List<int> episodeIds) async {
    final completer = reorderCompleter;
    if (completer != null) {
      await completer.future;
    }
    return _reorderQueueResult;
  }

  @override
  Future<PodcastQueueModel> activateQueueEpisode(int episodeId) async {
    activateQueueEpisodeCallCount += 1;
    return _activateQueueResult;
  }
}

class _NoopPodcastApiService implements PodcastApiService {
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _FakeAudioPlayerNotifier extends AudioPlayerNotifier {
  int playEpisodeCalls = 0;
  PlaySource? lastPlaySource;
  int? lastQueueEpisodeId;

  @override
  AudioPlayerState build() {
    return const AudioPlayerState();
  }

  @override
  Future<void> playEpisode(
    PodcastEpisodeModel episode, {
    PlaySource source = PlaySource.direct,
    int? queueEpisodeId,
  }) async {
    playEpisodeCalls += 1;
    lastPlaySource = source;
    lastQueueEpisodeId = queueEpisodeId;
  }
}
