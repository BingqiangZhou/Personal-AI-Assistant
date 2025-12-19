import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:mockito/mockito.dart';

import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_list_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';

import '../../../mocks/test_mocks.dart';

void main() {
  group('PodcastListPage Widget Tests', () {
    late ProviderContainer container;
    late MockPodcastRepository mockRepository;

    setUp(() {
      mockRepository = MockPodcastRepository();
      container = ProviderContainer(
        overrides: [
          podcastRepositoryProvider.overrideWithValue(mockRepository),
        ],
      );
    });

    tearDown(() {
      container.dispose();
    });

    testWidgets('displays loading state initially', (WidgetTester tester) async {
      // Mock loading state
      when(mockRepository.listSubscriptions()).thenThrow(
        AsyncValue<PodcastSubscriptionListResponse>.loading(),
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp.router(
            routerConfig: GoRouter(
              routes: [
                GoRoute(
                  path: '/',
                  builder: (context, state) => const PodcastListPage(),
                ),
              ],
            ),
          ),
        ),
      );

      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });

    testWidgets('displays empty state when no subscriptions', (WidgetTester tester) async {
      // Mock empty response
      final emptyResponse = PodcastSubscriptionListResponse(
        subscriptions: [],
        total: 0,
        page: 1,
        size: 20,
        pages: 0,
      );

      // Create a notifier and set the state manually
      final notifier = PodcastSubscriptionNotifier();
      notifier.state = AsyncValue.data(emptyResponse);

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              podcastSubscriptionNotifierProvider.overrideWith((ref) => notifier),
            ],
          ),
          child: MaterialApp.router(
            routerConfig: GoRouter(
              routes: [
                GoRoute(
                  path: '/',
                  builder: (context, state) => const PodcastListPage(),
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('No Podcasts Yet'), findsOneWidget);
      expect(find.text('Add your first podcast to get started'), findsOneWidget);
      expect(find.byIcon(Icons.add), findsOneWidget);
    });

    testWidgets('displays subscription list when data is loaded', (WidgetTester tester) async {
      // Mock sample data
      final subscriptions = [
        PodcastSubscriptionModel(
          id: 1,
          userId: 1,
          title: 'The Daily Tech Podcast',
          description: 'Daily tech news and updates',
          sourceUrl: 'https://example.com/feed.xml',
          status: 'active',
          fetchInterval: 3600,
          episodeCount: 50,
          unplayedCount: 10,
          createdAt: DateTime.now().subtract(const Duration(days: 30)),
        ),
        PodcastSubscriptionModel(
          id: 2,
          userId: 1,
          title: 'AI Insights',
          description: 'Exploring artificial intelligence',
          sourceUrl: 'https://example.com/ai-feed.xml',
          status: 'active',
          fetchInterval: 3600,
          episodeCount: 25,
          unplayedCount: 5,
          createdAt: DateTime.now().subtract(const Duration(days: 15)),
        ),
      ];

      final response = PodcastSubscriptionListResponse(
        subscriptions: subscriptions,
        total: 2,
        page: 1,
        size: 20,
        pages: 1,
      );

      // Create a notifier and set the state manually
      final notifier = PodcastSubscriptionNotifier();
      notifier.state = AsyncValue.data(response);

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              podcastSubscriptionNotifierProvider.overrideWith((ref) => notifier),
            ],
          ),
          child: MaterialApp.router(
            routerConfig: GoRouter(
              routes: [
                GoRoute(
                  path: '/',
                  builder: (context, state) => const PodcastListPage(),
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('The Daily Tech Podcast'), findsOneWidget);
      expect(find.text('AI Insights'), findsOneWidget);
      expect(find.text('50 Episodes'), findsOneWidget);
      expect(find.text('10 Unplayed'), findsOneWidget);
    });

    testWidgets('opens add podcast dialog when FAB is tapped', (WidgetTester tester) async {
      // Mock empty response
      final emptyResponse = PodcastSubscriptionListResponse(
        subscriptions: [],
        total: 0,
        page: 1,
        size: 20,
        pages: 0,
      );

      // Create a notifier and set the state manually
      final notifier = PodcastSubscriptionNotifier();
      notifier.state = AsyncValue.data(emptyResponse);

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              podcastSubscriptionNotifierProvider.overrideWith((ref) => notifier),
            ],
          ),
          child: MaterialApp.router(
            routerConfig: GoRouter(
              routes: [
                GoRoute(
                  path: '/',
                  builder: (context, state) => const PodcastListPage(),
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Tap the FAB
      await tester.tap(find.byType(FloatingActionButton));
      await tester.pumpAndSettle();

      // Check if dialog opens
      expect(find.text('Add Podcast'), findsOneWidget);
      expect(find.byType(TextField), findsOneWidget);
    });

    testWidgets('displays error state when loading fails', (WidgetTester tester) async {
      // Mock error
      const errorMessage = 'Failed to load subscriptions';
      final notifier = PodcastSubscriptionNotifier();
      notifier.state = const AsyncValue.error(errorMessage, StackTrace.empty);

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              podcastSubscriptionNotifierProvider.overrideWith((ref) => notifier),
            ],
          ),
          child: MaterialApp.router(
            routerConfig: GoRouter(
              routes: [
                GoRoute(
                  path: '/',
                  builder: (context, state) => const PodcastListPage(),
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('Failed to Load Podcasts'), findsOneWidget);
      expect(find.text(errorMessage), findsOneWidget);
      expect(find.text('Retry'), findsOneWidget);
    });

    testWidgets('pulls to refresh on pull gesture', (WidgetTester tester) async {
      // Mock sample data
      final subscriptions = [
        PodcastSubscriptionModel(
          id: 1,
          userId: 1,
          title: 'Test Podcast',
          description: 'Test description',
          sourceUrl: 'https://example.com/feed.xml',
          status: 'active',
          fetchInterval: 3600,
          episodeCount: 10,
          unplayedCount: 5,
          createdAt: DateTime.now(),
        ),
      ];

      final response = PodcastSubscriptionListResponse(
        subscriptions: subscriptions,
        total: 1,
        page: 1,
        size: 20,
        pages: 1,
      );

      // Create a notifier and set the state manually
      final notifier = PodcastSubscriptionNotifier();
      notifier.state = AsyncValue.data(response);

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              podcastSubscriptionNotifierProvider.overrideWith((ref) => notifier),
            ],
          ),
          child: MaterialApp.router(
            routerConfig: GoRouter(
              routes: [
                GoRoute(
                  path: '/',
                  builder: (context, state) => const PodcastListPage(),
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Perform pull to refresh
      await tester.fling(
        find.byType(RefreshIndicator),
        const Offset(0, 300),
        1000,
      );
      await tester.pumpAndSettle();

      // Verify that the refresh indicator is shown
      expect(find.byType(RefreshIndicator), findsOneWidget);
    });
  });
}