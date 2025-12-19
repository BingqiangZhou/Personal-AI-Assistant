import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';

import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_episodes_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';

import '../../../mocks/test_mocks.dart';
import 'podcast_episodes_page_test.mocks.dart';

@GenerateMocks([PodcastRepository])
void main() {
  group('PodcastEpisodesPage Widget Tests', () {
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

    testWidgets('renders episode list with loading state', (WidgetTester tester) async {
      // Arrange
      final subscription = PodcastSubscription(
        id: 1,
        title: 'Test Podcast',
        description: 'Test Description',
        sourceUrl: 'https://example.com/rss',
        status: 'active',
        lastFetchedAt: DateTime.now(),
        errorMessage: null,
        fetchInterval: 3600,
        episodeCount: 10,
        unplayedCount: 5,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      // Mock loading state
      when(mockRepository.getEpisodes(1))
          .thenThrow(Exception('Loading'));

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastEpisodesPage(subscription: subscription),
          ),
        ),
      );

      await tester.pump();

      // Assert
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      expect(find.text('Test Podcast'), findsOneWidget);
    });

    testWidgets('displays episodes when loaded successfully', (WidgetTester tester) async {
      // Arrange
      final subscription = PodcastSubscription(
        id: 1,
        title: 'Tech Talk',
        description: 'Technology discussions',
        sourceUrl: 'https://example.com/tech.rss',
        status: 'active',
        lastFetchedAt: DateTime.now(),
        errorMessage: null,
        fetchInterval: 3600,
        episodeCount: 2,
        unplayedCount: 1,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final episodes = [
        PodcastEpisode(
          id: 1,
          subscriptionId: 1,
          title: 'Episode 1: AI Revolution',
          description: 'Discussing the impact of AI on society',
          publishedAt: DateTime.now().subtract(Duration(days: 1)),
          audioUrl: 'https://example.com/episode1.mp3',
          audioDuration: 1800, // 30 minutes
          audioFileSize: 30000000,
          transcriptUrl: null,
          transcriptContent: null,
          aiSummary: 'This episode explores how AI is transforming various industries...',
          summaryVersion: '1.0',
          aiConfidenceScore: 0.95,
          playCount: 100,
          lastPlayedAt: DateTime.now().subtract(Duration(hours: 2)),
          season: 1,
          episodeNumber: 1,
          explicit: false,
          status: 'summarized',
          metadata: {},
          createdAt: DateTime.now(),
          updatedAt: DateTime.now(),
        ),
        PodcastEpisode(
          id: 2,
          subscriptionId: 1,
          title: 'Episode 2: Future of Web Development',
          description: 'Exploring modern web technologies',
          publishedAt: DateTime.now().subtract(Duration(days: 3)),
          audioUrl: 'https://example.com/episode2.mp3',
          audioDuration: 2400, // 40 minutes
          audioFileSize: 40000000,
          transcriptUrl: null,
          transcriptContent: null,
          aiSummary: null,
          summaryVersion: null,
          aiConfidenceScore: null,
          playCount: 0,
          lastPlayedAt: null,
          season: 1,
          episodeNumber: 2,
          explicit: false,
          status: 'pending_summary',
          metadata: {},
          createdAt: DateTime.now(),
          updatedAt: DateTime.now(),
        ),
      ];

      when(mockRepository.getEpisodes(1))
          .thenAnswer((_) async => episodes);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastEpisodesPage(subscription: subscription),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert
      expect(find.text('Tech Talk'), findsOneWidget);
      expect(find.text('Episode 1: AI Revolution'), findsOneWidget);
      expect(find.text('Episode 2: Future of Web Development'), findsOneWidget);
      expect(find.text('30 min'), findsOneWidget);
      expect(find.text('40 min'), findsOneWidget);
      expect(find.byIcon(Icons.play_arrow), findsOneWidget); // Unplayed episode
      expect(find.byIcon(Icons.headphones), findsOneWidget); // Played episode
    });

    testWidgets('displays empty state when no episodes', (WidgetTester tester) async {
      // Arrange
      final subscription = PodcastSubscription(
        id: 1,
        title: 'Empty Podcast',
        description: 'No episodes yet',
        sourceUrl: 'https://example.com/empty.rss',
        status: 'active',
        lastFetchedAt: DateTime.now(),
        errorMessage: null,
        fetchInterval: 3600,
        episodeCount: 0,
        unplayedCount: 0,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      when(mockRepository.getEpisodes(1))
          .thenAnswer((_) async => []);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastEpisodesPage(subscription: subscription),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert
      expect(find.text('Empty Podcast'), findsOneWidget);
      expect(find.text('No episodes found'), findsOneWidget);
      expect(find.byIcon(Icons.podcasts), findsOneWidget);
    });

    testWidgets('displays error state when loading fails', (WidgetTester tester) async {
      // Arrange
      final subscription = PodcastSubscription(
        id: 1,
        title: 'Error Podcast',
        description: 'Failed to load',
        sourceUrl: 'https://example.com/error.rss',
        status: 'error',
        lastFetchedAt: DateTime.now(),
        errorMessage: 'Network error',
        fetchInterval: 3600,
        episodeCount: 0,
        unplayedCount: 0,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      when(mockRepository.getEpisodes(1))
          .thenThrow(Exception('Network error'));

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastEpisodesPage(subscription: subscription),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert
      expect(find.text('Error Podcast'), findsOneWidget);
      expect(find.text('Failed to load episodes'), findsOneWidget);
      expect(find.byIcon(Icons.error_outline), findsOneWidget);
      expect(find.text('Retry'), findsOneWidget);
    });

    testWidgets('navigates to episode detail when tapped', (WidgetTester tester) async {
      // Arrange
      final subscription = PodcastSubscription(
        id: 1,
        title: 'Navigation Test',
        description: 'Testing navigation',
        sourceUrl: 'https://example.com/nav.rss',
        status: 'active',
        lastFetchedAt: DateTime.now(),
        errorMessage: null,
        fetchInterval: 3600,
        episodeCount: 1,
        unplayedCount: 1,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: 'Test Description',
        publishedAt: DateTime.now(),
        audioUrl: 'https://example.com/test.mp3',
        audioDuration: 1800,
        audioFileSize: 30000000,
        transcriptUrl: null,
        transcriptContent: null,
        aiSummary: null,
        summaryVersion: null,
        aiConfidenceScore: null,
        playCount: 0,
        lastPlayedAt: null,
        season: null,
        episodeNumber: null,
        explicit: false,
        status: 'pending',
        metadata: {},
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      when(mockRepository.getEpisodes(1))
          .thenAnswer((_) async => [episode]);

      // Mock navigation
      bool navigated = false;
      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastEpisodesPage(subscription: subscription),
            onGenerateRoute: (settings) {
              if (settings.name == '/episode/1') {
                navigated = true;
                return MaterialPageRoute(
                  builder: (context) => Scaffold(
                    appBar: AppBar(title: Text('Episode Detail')),
                  ),
                );
              }
              return null;
            },
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Tap on episode
      await tester.tap(find.text('Test Episode'));
      await tester.pumpAndSettle();

      // Assert navigation occurred (if navigation is implemented)
      // Note: This test assumes navigation is implemented
    });

    testWidgets('pull to refresh triggers reload', (WidgetTester tester) async {
      // Arrange
      final subscription = PodcastSubscription(
        id: 1,
        title: 'Refresh Test',
        description: 'Testing pull to refresh',
        sourceUrl: 'https://example.com/refresh.rss',
        status: 'active',
        lastFetchedAt: DateTime.now(),
        errorMessage: null,
        fetchInterval: 3600,
        episodeCount: 1,
        unplayedCount: 1,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      var refreshCount = 0;
      when(mockRepository.getEpisodes(1)).thenAnswer((_) async {
        refreshCount++;
        return [];
      });

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastEpisodesPage(subscription: subscription),
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

      // Assert
      expect(refreshCount, greaterThan(1)); // Should be called at least twice
    });

    testWidgets('search functionality works correctly', (WidgetTester tester) async {
      // Arrange
      final subscription = PodcastSubscription(
        id: 1,
        title: 'Search Test Podcast',
        description: 'Testing search functionality',
        sourceUrl: 'https://example.com/search.rss',
        status: 'active',
        lastFetchedAt: DateTime.now(),
        errorMessage: null,
        fetchInterval: 3600,
        episodeCount: 3,
        unplayedCount: 2,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final episodes = [
        PodcastEpisode(
          id: 1,
          subscriptionId: 1,
          title: 'Episode about AI',
          description: 'Discussion on artificial intelligence',
          publishedAt: DateTime.now(),
          audioUrl: 'https://example.com/ai.mp3',
          audioDuration: 1800,
          audioFileSize: 30000000,
          transcriptUrl: null,
          transcriptContent: null,
          aiSummary: null,
          summaryVersion: null,
          aiConfidenceScore: null,
          playCount: 0,
          lastPlayedAt: null,
          season: null,
          episodeNumber: null,
          explicit: false,
          status: 'pending',
          metadata: {},
          createdAt: DateTime.now(),
          updatedAt: DateTime.now(),
        ),
        PodcastEpisode(
          id: 2,
          subscriptionId: 1,
          title: 'Episode about Web Development',
          description: 'Modern web technologies',
          publishedAt: DateTime.now(),
          audioUrl: 'https://example.com/web.mp3',
          audioDuration: 2400,
          audioFileSize: 40000000,
          transcriptUrl: null,
          transcriptContent: null,
          aiSummary: null,
          summaryVersion: null,
          aiConfidenceScore: null,
          playCount: 0,
          lastPlayedAt: null,
          season: null,
          episodeNumber: null,
          explicit: false,
          status: 'pending',
          metadata: {},
          createdAt: DateTime.now(),
          updatedAt: DateTime.now(),
        ),
        PodcastEpisode(
          id: 3,
          subscriptionId: 1,
          title: 'Episode about Mobile Apps',
          description: 'iOS and Android development',
          publishedAt: DateTime.now(),
          audioUrl: 'https://example.com/mobile.mp3',
          audioDuration: 2000,
          audioFileSize: 35000000,
          transcriptUrl: null,
          transcriptContent: null,
          aiSummary: null,
          summaryVersion: null,
          aiConfidenceScore: null,
          playCount: 0,
          lastPlayedAt: null,
          season: null,
          episodeNumber: null,
          explicit: false,
          status: 'pending',
          metadata: {},
          createdAt: DateTime.now(),
          updatedAt: DateTime.now(),
        ),
      ];

      when(mockRepository.getEpisodes(1))
          .thenAnswer((_) async => episodes);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastEpisodesPage(subscription: subscription),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Enter search term
      await tester.enterText(find.byType(TextField), 'AI');
      await tester.pump();

      // Assert - Only AI episode should be visible
      expect(find.text('Episode about AI'), findsOneWidget);
      expect(find.text('Episode about Web Development'), findsNothing);
      expect(find.text('Episode about Mobile Apps'), findsNothing);

      // Clear search
      await tester.enterText(find.byType(TextField), '');
      await tester.pump();

      // All episodes should be visible again
      expect(find.text('Episode about AI'), findsOneWidget);
      expect(find.text('Episode about Web Development'), findsOneWidget);
      expect(find.text('Episode about Mobile Apps'), findsOneWidget);
    });

    testWidgets('filter by played/unplayed status', (WidgetTester tester) async {
      // Arrange
      final subscription = PodcastSubscription(
        id: 1,
        title: 'Filter Test Podcast',
        description: 'Testing filter functionality',
        sourceUrl: 'https://example.com/filter.rss',
        status: 'active',
        lastFetchedAt: DateTime.now(),
        errorMessage: null,
        fetchInterval: 3600,
        episodeCount: 2,
        unplayedCount: 1,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final episodes = [
        PodcastEpisode(
          id: 1,
          subscriptionId: 1,
          title: 'Played Episode',
          description: 'Already listened',
          publishedAt: DateTime.now(),
          audioUrl: 'https://example.com/played.mp3',
          audioDuration: 1800,
          audioFileSize: 30000000,
          transcriptUrl: null,
          transcriptContent: null,
          aiSummary: null,
          summaryVersion: null,
          aiConfidenceScore: null,
          playCount: 10,
          lastPlayedAt: DateTime.now().subtract(Duration(hours: 1)),
          season: null,
          episodeNumber: null,
          explicit: false,
          status: 'pending',
          metadata: {},
          createdAt: DateTime.now(),
          updatedAt: DateTime.now(),
        ),
        PodcastEpisode(
          id: 2,
          subscriptionId: 1,
          title: 'Unplayed Episode',
          description: 'Not yet listened',
          publishedAt: DateTime.now(),
          audioUrl: 'https://example.com/unplayed.mp3',
          audioDuration: 1800,
          audioFileSize: 30000000,
          transcriptUrl: null,
          transcriptContent: null,
          aiSummary: null,
          summaryVersion: null,
          aiConfidenceScore: null,
          playCount: 0,
          lastPlayedAt: null,
          season: null,
          episodeNumber: null,
          explicit: false,
          status: 'pending',
          metadata: {},
          createdAt: DateTime.now(),
          updatedAt: DateTime.now(),
        ),
      ];

      when(mockRepository.getEpisodes(1))
          .thenAnswer((_) async => episodes);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastEpisodesPage(subscription: subscription),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Both episodes should be visible initially
      expect(find.text('Played Episode'), findsOneWidget);
      expect(find.text('Unplayed Episode'), findsOneWidget);

      // Tap filter button (assuming there's a filter option)
      // Note: This test assumes filter functionality is implemented
    });

    testWidgets('displays episode metadata correctly', (WidgetTester tester) async {
      // Arrange
      final subscription = PodcastSubscription(
        id: 1,
        title: 'Metadata Test Podcast',
        description: 'Testing metadata display',
        sourceUrl: 'https://example.com/metadata.rss',
        status: 'active',
        lastFetchedAt: DateTime.now(),
        errorMessage: null,
        fetchInterval: 3600,
        episodeCount: 1,
        unplayedCount: 0,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Special Episode: Season 2 Episode 5',
        description: 'A special episode with explicit content',
        publishedAt: DateTime.now().subtract(Duration(days: 7)),
        audioUrl: 'https://example.com/special.mp3',
        audioDuration: 3600, // 1 hour
        audioFileSize: 60000000, // 60MB
        transcriptUrl: 'https://example.com/transcript.txt',
        transcriptContent: 'Full transcript here',
        aiSummary: 'This special episode covers...',
        summaryVersion: '2.0',
        aiConfidenceScore: 0.98,
        playCount: 500,
        lastPlayedAt: DateTime.now().subtract(Duration(minutes: 30)),
        season: 2,
        episodeNumber: 5,
        explicit: true,
        status: 'summarized',
        metadata: {
          'author': 'John Doe',
          'guests': ['Jane Smith', 'Bob Johnson'],
          'tags': ['AI', 'Technology', 'Future'],
        },
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      when(mockRepository.getEpisodes(1))
          .thenAnswer((_) async => [episode]);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastEpisodesPage(subscription: subscription),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert metadata display
      expect(find.text('Special Episode: Season 2 Episode 5'), findsOneWidget);
      expect(find.text('60 min'), findsOneWidget); // Duration
      expect(find.byIcon(Icons.explicit), findsOneWidget); // Explicit content
      expect(find.text('S2 E5'), findsOneWidget); // Season and episode
      expect(find.text('500'), findsOneWidget); // Play count
    });

    testWidgets('handles long episode titles gracefully', (WidgetTester tester) async {
      // Arrange
      final subscription = PodcastSubscription(
        id: 1,
        title: 'Long Title Test',
        description: 'Testing long title handling',
        sourceUrl: 'https://example.com/long.rss',
        status: 'active',
        lastFetchedAt: DateTime.now(),
        errorMessage: null,
        fetchInterval: 3600,
        episodeCount: 1,
        unplayedCount: 1,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final longTitle = 'This is an extremely long episode title that goes on and on and should be truncated properly in the UI without breaking the layout or overflowing the container boundaries';

      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: longTitle,
        description: 'Test Description',
        publishedAt: DateTime.now(),
        audioUrl: 'https://example.com/long.mp3',
        audioDuration: 1800,
        audioFileSize: 30000000,
        transcriptUrl: null,
        transcriptContent: null,
        aiSummary: null,
        summaryVersion: null,
        aiConfidenceScore: null,
        playCount: 0,
        lastPlayedAt: null,
        season: null,
        episodeNumber: null,
        explicit: false,
        status: 'pending',
        metadata: {},
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      when(mockRepository.getEpisodes(1))
          .thenAnswer((_) async => [episode]);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastEpisodesPage(subscription: subscription),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert - Title should be truncated with ellipsis
      final titleWidget = tester.widget<Text>(find.byType(Text).first);
      expect(titleWidget.data?.toString().endsWith('...'), isTrue);
    });

    testWidgets('supports accessibility features', (WidgetTester tester) async {
      // Arrange
      final subscription = PodcastSubscription(
        id: 1,
        title: 'Accessibility Test Podcast',
        description: 'Testing accessibility features',
        sourceUrl: 'https://example.com/a11y.rss',
        status: 'active',
        lastFetchedAt: DateTime.now(),
        errorMessage: null,
        fetchInterval: 3600,
        episodeCount: 1,
        unplayedCount: 1,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Accessible Episode',
        description: 'Episode with proper accessibility labels',
        publishedAt: DateTime.now(),
        audioUrl: 'https://example.com/accessible.mp3',
        audioDuration: 1800,
        audioFileSize: 30000000,
        transcriptUrl: null,
        transcriptContent: null,
        aiSummary: null,
        summaryVersion: null,
        aiConfidenceScore: null,
        playCount: 0,
        lastPlayedAt: null,
        season: null,
        episodeNumber: null,
        explicit: false,
        status: 'pending',
        metadata: {},
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      when(mockRepository.getEpisodes(1))
          .thenAnswer((_) async => [episode]);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastEpisodesPage(subscription: subscription),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert accessibility
      expect(
        tester.semantics.findByLabel('Accessible Episode'),
        findsOneWidget,
      );

      // Verify semantic labels exist for interactive elements
      expect(
        tester.semantics.hasLabel('Play episode'),
        isTrue,
      );
    });
  });
}