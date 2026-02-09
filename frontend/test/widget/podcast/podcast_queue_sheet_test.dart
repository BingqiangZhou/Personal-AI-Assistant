import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_queue_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_queue_sheet.dart';

void main() {
  group('PodcastQueueSheet', () {
    testWidgets('uses custom left drag handle and does not overlap delete icon', (
      tester,
    ) async {
      final controller = TestPodcastQueueController(_queue());
      await tester.pumpWidget(_createWidget(controller));
      await tester.pumpAndSettle();

      final list = tester.widget<ReorderableListView>(
        find.byType(ReorderableListView),
      );
      expect(list.buildDefaultDragHandles, isFalse);

      final dragRect = tester.getRect(find.byKey(const Key('queue_item_drag_1')));
      final deleteRect = tester.getRect(
        find.byKey(const Key('queue_item_remove_1')),
      );
      expect(dragRect.overlaps(deleteRect), isFalse);
    });

    testWidgets('shows fallback podcast icon when item has no image', (
      tester,
    ) async {
      final controller = TestPodcastQueueController(_queue(withImages: false));
      await tester.pumpWidget(_createWidget(controller));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('queue_item_cover_fallback_1')), findsOneWidget);
      expect(find.byIcon(Icons.podcasts), findsWidgets);
    });

    testWidgets('prefers subscription image over episode image for cover', (
      tester,
    ) async {
      final controller = TestPodcastQueueController(_queue(withImages: true));
      await tester.pumpWidget(_createWidget(controller));
      await tester.pumpAndSettle();

      final imageFinder = find.descendant(
        of: find.byKey(const Key('queue_item_cover_1')),
        matching: find.byType(Image),
      );
      expect(imageFinder, findsOneWidget);

      final image = tester.widget<Image>(imageFinder);
      final provider = image.image;
      expect(provider, isA<NetworkImage>());
      expect((provider as NetworkImage).url, 'https://example.com/subscription-1.jpg');
    });

    testWidgets('shows equalizer badge only on current queue item', (tester) async {
      final controller = TestPodcastQueueController(_queue());
      await tester.pumpWidget(_createWidget(controller));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('queue_item_playing_badge_1')), findsOneWidget);
      expect(find.byKey(const Key('queue_item_playing_badge_2')), findsNothing);
    });

    testWidgets('tapping item and delete trigger expected controller methods', (
      tester,
    ) async {
      final controller = TestPodcastQueueController(_queue());
      await tester.pumpWidget(_createWidget(controller));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Episode 1'));
      await tester.pumpAndSettle();
      expect(controller.playedEpisodeId, 1);

      await tester.tap(find.byKey(const Key('queue_item_remove_1')));
      await tester.pumpAndSettle();
      expect(controller.removedEpisodeId, 1);
    });

    testWidgets('reorder callback triggers reorderQueue with expected order', (
      tester,
    ) async {
      final controller = TestPodcastQueueController(_queue());
      await tester.pumpWidget(_createWidget(controller));
      await tester.pumpAndSettle();

      final list = tester.widget<ReorderableListView>(
        find.byType(ReorderableListView),
      );
      list.onReorder(0, 2);
      await tester.pumpAndSettle();

      expect(controller.reorderedEpisodeIds, <int>[2, 1, 3]);
    });
  });
}

Widget _createWidget(TestPodcastQueueController controller) {
  return ProviderScope(
    overrides: [podcastQueueControllerProvider.overrideWith(() => controller)],
    child: const MaterialApp(
      home: Scaffold(
        body: SizedBox(
          width: 430,
          height: 760,
          child: PodcastQueueSheet(),
        ),
      ),
    ),
  );
}

PodcastQueueModel _queue({bool withImages = false}) {
  return PodcastQueueModel(
    currentEpisodeId: 1,
    items: [
      PodcastQueueItemModel(
        episodeId: 1,
        position: 0,
        title: 'Episode 1',
        podcastId: 10,
        audioUrl: 'https://example.com/1.mp3',
        duration: 3600,
        subscriptionTitle: 'Podcast A',
        imageUrl: withImages ? 'https://example.com/episode-1.jpg' : null,
        subscriptionImageUrl: withImages
            ? 'https://example.com/subscription-1.jpg'
            : null,
      ),
      PodcastQueueItemModel(
        episodeId: 2,
        position: 1,
        title: 'Episode 2',
        podcastId: 11,
        audioUrl: 'https://example.com/2.mp3',
        duration: 2400,
        subscriptionTitle: 'Podcast B',
      ),
      PodcastQueueItemModel(
        episodeId: 3,
        position: 2,
        title: 'Episode 3',
        podcastId: 12,
        audioUrl: 'https://example.com/3.mp3',
        duration: 1800,
        subscriptionTitle: 'Podcast C',
      ),
    ],
  );
}

class TestPodcastQueueController extends PodcastQueueController {
  TestPodcastQueueController(this.initialQueue);

  final PodcastQueueModel initialQueue;
  int? playedEpisodeId;
  int? removedEpisodeId;
  List<int>? reorderedEpisodeIds;

  @override
  Future<PodcastQueueModel> build() async {
    return initialQueue;
  }

  @override
  Future<PodcastQueueModel> loadQueue() async {
    state = AsyncValue.data(initialQueue);
    return initialQueue;
  }

  @override
  Future<PodcastQueueModel> removeFromQueue(int episodeId) async {
    removedEpisodeId = episodeId;
    return state.value ?? initialQueue;
  }

  @override
  Future<PodcastQueueModel> reorderQueue(List<int> episodeIds) async {
    reorderedEpisodeIds = List<int>.from(episodeIds);
    return state.value ?? initialQueue;
  }

  @override
  Future<PodcastQueueModel> playFromQueue(int episodeId) async {
    playedEpisodeId = episodeId;
    return state.value ?? initialQueue;
  }
}
