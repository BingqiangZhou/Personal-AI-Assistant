import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';

import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_episodes_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/navigation/podcast_navigation.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/data/repositories/podcast_repository.dart';

import '../../mocks/fixture_factories.dart';
import '../../mocks/mock_helpers.dart';
import 'podcast_episodes_page_test.mocks.dart';

@GenerateMocks([PodcastRepository])
void main() {
  group('PodcastEpisodesPage Widget Tests', () {
    late ProviderContainer container;
    late MockPodcastRepository mockRepository;

    setUp(() {
      mockRepository = MockPodcastRepository();
      container = TestProviderContainer.createWithOverrides(
        repository: mockRepository,
      );
    });

    tearDown(() {
      container.dispose();
    });

    group('Page Initialization', () {
      testWidgets('renders with subscriptionId parameter', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.create(
          id: 1,
          title: 'Test Podcast',
        );

        // Mock loading state
        MockSetupHelpers.setupRepositoryError(mockRepository, 1);

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage(
            subscriptionId: 1,
            podcastTitle: 'Test Podcast',
          ),
          container: container,
        );

        await tester.pump();

        // Assert
        expect(find.byType(CircularProgressIndicator), findsOneWidget);
        expect(find.text('Test Podcast'), findsOneWidget);
      });

      testWidgets('renders using withSubscription factory', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.create(
          id: 1,
          title: 'Factory Podcast',
        );

        MockSetupHelpers.setupRepositoryError(mockRepository, 1);

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage.withSubscription(subscription),
          container: container,
        );

        await tester.pump();

        // Assert
        expect(find.text('Factory Podcast'), findsOneWidget);
      });

      testWidgets('renders using fromArgs factory', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.create(
          id: 1,
          title: 'Args Podcast',
        );
        final args = PodcastEpisodesPageArgs.fromSubscription(subscription);

        MockSetupHelpers.setupRepositoryError(mockRepository, 1);

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage.fromArgs(args),
          container: container,
        );

        await tester.pump();

        // Assert
        expect(find.text('Args Podcast'), findsOneWidget);
      });
    });

    group('Episode Display', () {
      testWidgets('displays episodes when loaded successfully', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.create(
          id: 1,
          title: 'Tech Talk',
          episodeCount: 2,
        );

        final episodes = [
          PodcastEpisodeFactory.createWithSummary(),
          PodcastEpisodeFactory.createPlayed(),
        ];

        MockSetupHelpers.setupRepositorySuccess(mockRepository, 1, episodes);

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage.withSubscription(subscription),
          container: container,
        );

        await tester.pumpAndSettle();

        // Assert
        expect(find.text('Tech Talk'), findsOneWidget);
        expect(find.text('Episode with AI Summary'), findsOneWidget);
        expect(find.text('Played Episode'), findsOneWidget);
        expect(find.byIcon(Icons.play_arrow), findsOneWidget);
        expect(find.byIcon(Icons.headphones), findsOneWidget);
      });

      testWidgets('displays empty state when no episodes', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.createEmpty();

        MockSetupHelpers.setupRepositoryEmpty(mockRepository, 1);

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage.withSubscription(subscription),
          container: container,
        );

        await tester.pumpAndSettle();

        // Assert
        expect(find.text('Empty Podcast'), findsOneWidget);
        expect(find.text('No Episodes Found'), findsOneWidget);
        expect(find.byIcon(Icons.headphones_outlined), findsOneWidget);
      });

      testWidgets('displays error state when loading fails', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.createWithError();

        MockSetupHelpers.setupRepositoryError(
          mockRepository,
          1,
          errorMessage: 'Network error',
        );

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage.withSubscription(subscription),
          container: container,
        );

        await tester.pumpAndSettle();

        // Assert
        expect(find.text('Error Podcast'), findsOneWidget);
        expect(find.text('Failed to Load Episodes'), findsOneWidget);
        expect(find.byIcon(Icons.error_outline), findsOneWidget);
        expect(find.text('Retry'), findsOneWidget);
      });
    });

    group('Filter Functionality', () {
      testWidgets('filter chips are displayed', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.create();

        MockSetupHelpers.setupRepositoryEmpty(mockRepository, 1);

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage.withSubscription(subscription),
          container: container,
        );

        await tester.pumpAndSettle();

        // Assert
        expect(find.text('All'), findsOneWidget);
        expect(find.text('Unplayed'), findsOneWidget);
        expect(find.text('Played'), findsOneWidget);
        expect(find.text('With AI Summary'), findsOneWidget);
      });

      testWidgets('tapping filter chips triggers reload', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.create();
        var callCount = 0;

        when(mockRepository.getEpisodes(1)).thenAnswer((_) async {
          callCount++;
          return [];
        });

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage.withSubscription(subscription),
          container: container,
        );

        await tester.pumpAndSettle();

        // Tap unplayed filter
        await tester.tap(find.text('Unplayed'));
        await tester.pumpAndSettle();

        // Assert
        expect(callCount, greaterThanOrEqualTo(2)); // Initial load + filter
      });
    });

    group('Pull to Refresh', () {
      testWidgets('pull to refresh triggers reload', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.create();
        var refreshCount = 0;

        when(mockRepository.getEpisodes(1)).thenAnswer((_) async {
          refreshCount++;
          return [];
        });

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage.withSubscription(subscription),
          container: container,
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
    });

    group('Menu Actions', () {
      testWidgets('menu button is displayed', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.create();

        MockSetupHelpers.setupRepositoryEmpty(mockRepository, 1);

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage.withSubscription(subscription),
          container: container,
        );

        await tester.pumpAndSettle();

        // Assert
        expect(find.byType(PopupMenuButton<String>), findsOneWidget);
        expect(find.byIcon(Icons.filter_list), findsOneWidget);
      });

      testWidgets('filter dialog opens on filter button tap', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.create();

        MockSetupHelpers.setupRepositoryEmpty(mockRepository, 1);

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage.withSubscription(subscription),
          container: container,
        );

        await tester.pumpAndSettle();

        // Tap filter button
        await tester.tap(find.byIcon(Icons.filter_list));
        await tester.pumpAndSettle();

        // Assert
        expect(find.text('Filter Episodes'), findsOneWidget);
        expect(find.text('All Episodes'), findsOneWidget);
        expect(find.text('Unplayed Only'), findsOneWidget);
        expect(find.text('Played Only'), findsOneWidget);
      });
    });

    group('Episode Metadata Display', () {
      testWidgets('displays episode with metadata correctly', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.create();
        final episode = PodcastEpisodeFactory.createWithMetadata();

        MockSetupHelpers.setupRepositorySuccess(mockRepository, 1, [episode]);

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage.withSubscription(subscription),
          container: container,
        );

        await tester.pumpAndSettle();

        // Assert
        expect(find.text('Special Episode: Season 2 Episode 5'), findsOneWidget);
        expect(find.text('60 min'), findsOneWidget);
        expect(find.byIcon(Icons.explicit), findsOneWidget);
      });
    });

    group('Accessibility', () {
      testWidgets('supports semantic labels', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.create(
          title: 'Accessibility Test Podcast',
        );
        final episode = PodcastEpisodeFactory.create(
          title: 'Accessible Episode',
        );

        MockSetupHelpers.setupRepositorySuccess(mockRepository, 1, [episode]);

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage.withSubscription(subscription),
          container: container,
        );

        await tester.pumpAndSettle();

        // Assert
        expect(
          tester.semantics.findByLabel('Accessibility Test Podcast'),
          findsOneWidget,
        );
      });
    });

    group('Long Titles', () {
      testWidgets('handles long episode titles gracefully', (WidgetTester tester) async {
        // Arrange
        final subscription = PodcastSubscriptionFactory.create();
        final longTitle = 'This is an extremely long episode title that goes on and on and should be truncated properly in the UI';
        final episode = PodcastEpisodeFactory.create(title: longTitle);

        MockSetupHelpers.setupRepositorySuccess(mockRepository, 1, [episode]);

        // Act
        await tester.pumpWidgetWithProviders(
          PodcastEpisodesPage.withSubscription(subscription),
          container: container,
        );

        await tester.pumpAndSettle();

        // Assert - Title should be displayed (truncation is handled by UI)
        expect(find.byType(Text), findsWidgets);
        // Check that at least one text widget contains part of the title
        final textWidgets = tester.widgetList<Text>(find.byType(Text));
        final hasTitle = textWidgets.any((widget) =>
          widget.data?.toString().contains('extremely long') ?? false
        );
        expect(hasTitle, isTrue);
      });
    });
  });
}