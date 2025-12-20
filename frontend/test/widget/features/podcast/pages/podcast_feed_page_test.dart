import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_feed_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';

void main() {
  group('PodcastFeedPage Widget Tests', () {
    late ProviderContainer container;

    setUp(() {
      container = ProviderContainer();
    });

    tearDown(() {
      container.dispose();
    });

    testWidgets('displays loading shimmer initially', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastFeedPage(),
          ),
        ),
      );

      // Assert
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      expect(find.text('信息流'), findsOneWidget);
    });

    testWidgets('displays empty state when no episodes', (WidgetTester tester) async {
      // Arrange - Override provider to return empty state
      final testContainer = ProviderContainer(
        overrides: [
          podcastFeedNotifierProvider.overrideWith((ref) {
            final notifier = TestPodcastFeedNotifier();
            notifier.state = const PodcastFeedState(
              episodes: [],
              isLoading: false,
              hasMore: false,
              total: 0,
            );
            return notifier;
          }),
        ],
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: testContainer,
          child: MaterialApp(
            home: PodcastFeedPage(),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert
      expect(find.text('还没有订阅内容'), findsOneWidget);
      expect(find.text('去订阅一些你感兴趣的播客吧！'), findsOneWidget);
      expect(find.text('订阅播客'), findsOneWidget);

      testContainer.dispose();
    });

    testWidgets('displays episode cards when data is loaded', (WidgetTester tester) async {
      // Arrange - Create mock episodes
      final mockEpisodes = [
        PodcastEpisodeModel(
          id: 1,
          subscriptionId: 1,
          title: 'Test Episode 1',
          audioUrl: 'https://example.com/audio1.mp3',
          publishedAt: DateTime.now().subtract(const Duration(hours: 2)),
          createdAt: DateTime.now(),
        ),
        PodcastEpisodeModel(
          id: 2,
          subscriptionId: 1,
          title: 'Test Episode 2',
          audioUrl: 'https://example.com/audio2.mp3',
          publishedAt: DateTime.now().subtract(const Duration(days: 1)),
          createdAt: DateTime.now(),
        ),
      ];

      // Override provider with mock data
      final testContainer = ProviderContainer(
        overrides: [
          podcastFeedNotifierProvider.overrideWith((ref) {
            final notifier = TestPodcastFeedNotifier();
            notifier.state = PodcastFeedState(
              episodes: mockEpisodes,
              isLoading: false,
              hasMore: true,
              total: 2,
            );
            return notifier;
          }),
        ],
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: testContainer,
          child: MaterialApp(
            home: PodcastFeedPage(),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert
      expect(find.text('Test Episode 1'), findsOneWidget);
      expect(find.text('Test Episode 2'), findsOneWidget);
      expect(find.byType(Card), findsNWidgets(2));

      testContainer.dispose();
    });

    testWidgets('displays error state when loading fails', (WidgetTester tester) async {
      // Arrange - Override provider to return error state
      final testContainer = ProviderContainer(
        overrides: [
          podcastFeedNotifierProvider.overrideWith((ref) {
            final notifier = TestPodcastFeedNotifier();
            notifier.state = const PodcastFeedState(
              episodes: [],
              isLoading: false,
              hasMore: false,
              total: 0,
              error: 'Network error occurred',
            );
            return notifier;
          }),
        ],
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: testContainer,
          child: MaterialApp(
            home: PodcastFeedPage(),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert
      expect(find.text('加载失败'), findsOneWidget);
      expect(find.text('Network error occurred'), findsOneWidget);
      expect(find.text('重试'), findsOneWidget);

      testContainer.dispose();
    });

    testWidgets('displays loading more indicator', (WidgetTester tester) async {
      // Arrange - Create mock episodes with loading state
      final mockEpisodes = [
        PodcastEpisodeModel(
          id: 1,
          subscriptionId: 1,
          title: 'Test Episode 1',
          audioUrl: 'https://example.com/audio1.mp3',
          publishedAt: DateTime.now(),
          createdAt: DateTime.now(),
        ),
      ];

      // Override provider with mock data and loading more state
      final testContainer = ProviderContainer(
        overrides: [
          podcastFeedNotifierProvider.overrideWith((ref) {
            final notifier = TestPodcastFeedNotifier();
            notifier.state = PodcastFeedState(
              episodes: mockEpisodes,
              isLoading: false,
              isLoadingMore: true,
              hasMore: true,
              total: 1,
            );
            return notifier;
          }),
        ],
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: testContainer,
          child: MaterialApp(
            home: PodcastFeedPage(),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert
      expect(find.text('Test Episode 1'), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsOneWidget);

      testContainer.dispose();
    });

    testWidgets('displays end of content message', (WidgetTester tester) async {
      // Arrange - Create mock episodes with no more content
      final mockEpisodes = [
        PodcastEpisodeModel(
          id: 1,
          subscriptionId: 1,
          title: 'Test Episode 1',
          audioUrl: 'https://example.com/audio1.mp3',
          publishedAt: DateTime.now(),
          createdAt: DateTime.now(),
        ),
      ];

      // Override provider with mock data and no more content
      final testContainer = ProviderContainer(
        overrides: [
          podcastFeedNotifierProvider.overrideWith((ref) {
            final notifier = TestPodcastFeedNotifier();
            notifier.state = PodcastFeedState(
              episodes: mockEpisodes,
              isLoading: false,
              hasMore: false,
              total: 1,
            );
            return notifier;
          }),
        ],
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: testContainer,
          child: MaterialApp(
            home: PodcastFeedPage(),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert
      expect(find.text('Test Episode 1'), findsOneWidget);
      expect(find.text('已加载全部内容'), findsOneWidget);

      testContainer.dispose();
    });
  });
}

// Test helper classes
class TestPodcastFeedNotifier extends _$PodcastFeedNotifier {
  TestPodcastFeedNotifier();

  @override
  PodcastFeedState build() {
    return const PodcastFeedState();
  }
}