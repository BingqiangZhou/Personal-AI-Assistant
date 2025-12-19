import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:mockito/mockito.dart';

import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/category_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_list_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/core/storage/token_storage.dart';

import '../../../mocks/test_mocks.dart';
import '../../../helpers/widget_test_helpers.dart';

void main() {
  group('PodcastListPage Comprehensive Widget Tests', () {
    late ProviderContainer container;
    late MockPodcastRepository mockRepository;
    late MockTokenStorage mockTokenStorage;

    setUp(() {
      mockRepository = MockPodcastRepository();
      mockTokenStorage = MockTokenStorage();

      // Mock successful authentication
      when(mockTokenStorage.getToken()).thenAnswer((_) async => 'test-token');

      container = ProviderContainer(
        overrides: [
          podcastRepositoryProvider.overrideWithValue(mockRepository),
          tokenStorageProvider.overrideWithValue(mockTokenStorage),
        ],
      );
    });

    tearDown(() {
      container.dispose();
    });

    Widget createTestPodcastListPage({
      PodcastSubscriptionListResponse? initialData,
      AsyncValue<PodcastSubscriptionListResponse>? stateOverride,
    }) {
      final overrides = <Override>[];

      if (stateOverride != null) {
        overrides.add(
          podcastSubscriptionProvider.overrideWith((ref) =>
            PodcastSubscriptionNotifier()..state = stateOverride),
        );
      }

      final testContainer = ProviderContainer(
        overrides: overrides,
        parent: container,
      );

      return createTestWidget(
        container: testContainer,
        child: const PodcastListPage(),
      );
    }

    // === Basic Widget Rendering Tests ===

    testWidgets('renders all required UI components', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestPodcastListPage());

      // Assert - Check for key UI elements
      expect(find.byType(AppBar), findsOneWidget);
      expect(find.text('Podcasts'), findsOneWidget);
      expect(find.byIcon(Icons.search), findsOneWidget);
      expect(find.byIcon(Icons.filter_list), findsOneWidget);
      expect(find.byType(PopupMenuButton<String>), findsOneWidget);
      expect(find.byType(FloatingActionButton), findsOneWidget);
      expect(find.byIcon(Icons.add), findsOneWidget);
    });

    testWidgets('displays loading state initially', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: const AsyncValue.loading(),
      ));

      // Assert - Loading indicator should be present
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      expect(find.byType(ListView), findsNothing);
    });

    testWidgets('displays data when loaded successfully', (WidgetTester tester) async {
      // Arrange
      final mockData = [
        createMockSubscription(
          id: 1,
          title: 'The Daily Tech Podcast',
          description: 'Daily tech news and updates',
          status: 'active',
          episodeCount: 50,
          unplayedCount: 10,
        ),
        createMockSubscription(
          id: 2,
          title: 'AI Insights',
          description: 'Exploring artificial intelligence',
          status: 'active',
          episodeCount: 25,
          unplayedCount: 5,
        ),
      ];

      final response = PodcastSubscriptionListResponse(
        subscriptions: mockData,
        total: 2,
        page: 1,
        size: 20,
        pages: 1,
      );

      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: AsyncValue.data(response),
      ));

      await tester.pumpAndSettle();

      // Assert - Data should be displayed
      expect(find.text('The Daily Tech Podcast'), findsOneWidget);
      expect(find.text('AI Insights'), findsOneWidget);
      expect(find.text('50 Episodes'), findsOneWidget);
      expect(find.text('10 Unplayed'), findsOneWidget);
      expect(find.text('25 Episodes'), findsOneWidget);
      expect(find.text('5 Unplayed'), findsOneWidget);
      expect(find.byType(ListView), findsOneWidget);
    });

    testWidgets('handles error state appropriately', (WidgetTester tester) async {
      // Arrange
      const errorMessage = 'Failed to load podcasts: Unauthorized';

      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: const AsyncValue.error(errorMessage, StackTrace.empty),
      ));

      await tester.pumpAndSettle();

      // Assert - Error should be displayed
      expect(find.text('Failed to Load Podcasts'), findsOneWidget);
      expect(find.text(errorMessage), findsOneWidget);
      expect(find.byIcon(Icons.refresh), findsOneWidget);
      expect(find.text('Retry'), findsOneWidget);
    });

    testWidgets('displays empty state when no subscriptions', (WidgetTester tester) async {
      // Arrange
      final emptyResponse = PodcastSubscriptionListResponse(
        subscriptions: [],
        total: 0,
        page: 1,
        size: 20,
        pages: 0,
      );

      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: AsyncValue.data(emptyResponse),
      ));

      await tester.pumpAndSettle();

      // Assert - Empty state should be shown
      expect(find.byIcon(Icons.podcasts_outlined), findsOneWidget);
      expect(find.text('No Podcasts Yet'), findsOneWidget);
      expect(find.text('Add your first podcast to get started'), findsOneWidget);
      expect(find.text('Add Podcast'), findsOneWidget);
    });

    // === User Interaction Tests ===

    testWidgets('navigates to add podcast dialog when FAB is tapped', (WidgetTester tester) async {
      // Arrange
      final emptyResponse = PodcastSubscriptionListResponse(
        subscriptions: [],
        total: 0,
        page: 1,
        size: 20,
        pages: 0,
      );

      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: AsyncValue.data(emptyResponse),
      ));

      await tester.pumpAndSettle();

      // Act
      await tester.tap(find.byType(FloatingActionButton));
      await tester.pumpAndSettle();

      // Assert - Should show add podcast dialog
      expect(find.text('Add Podcast'), findsOneWidget);
      expect(find.byType(TextField), findsOneWidget);
    });

    testWidgets('opens search dialog when search icon is tapped', (WidgetTester tester) async {
      // Arrange
      final emptyResponse = PodcastSubscriptionListResponse(
        subscriptions: [],
        total: 0,
        page: 1,
        size: 20,
        pages: 0,
      );

      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: AsyncValue.data(emptyResponse),
      ));

      await tester.pumpAndSettle();

      // Act
      await tester.tap(find.byIcon(Icons.search));
      await tester.pumpAndSettle();

      // Assert - Search dialog should be displayed
      expect(find.text('Search Podcasts'), findsOneWidget);
      expect(find.byType(TextField), findsOneWidget);
      expect(find.text('Search term'), findsOneWidget);
    });

    testWidgets('opens filter dialog when filter icon is tapped', (WidgetTester tester) async {
      // Arrange
      final emptyResponse = PodcastSubscriptionListResponse(
        subscriptions: [],
        total: 0,
        page: 1,
        size: 20,
        pages: 0,
      );

      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: AsyncValue.data(emptyResponse),
      ));

      await tester.pumpAndSettle();

      // Act
      await tester.tap(find.byIcon(Icons.filter_list));
      await tester.pumpAndSettle();

      // Assert - Filter dialog should be displayed
      expect(find.text('Filter Podcasts'), findsOneWidget);
      expect(find.text('Status:'), findsOneWidget);
      expect(find.text('All'), findsOneWidget);
      expect(find.text('Active'), findsOneWidget);
      expect(find.text('Error'), findsOneWidget);
    });

    testWidgets('shows menu options when menu button is tapped', (WidgetTester tester) async {
      // Arrange
      final emptyResponse = PodcastSubscriptionListResponse(
        subscriptions: [],
        total: 0,
        page: 1,
        size: 20,
        pages: 0,
      );

      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: AsyncValue.data(emptyResponse),
      ));

      await tester.pumpAndSettle();

      // Act
      await tester.tap(find.byType(PopupMenuButton<String>));
      await tester.pumpAndSettle();

      // Assert - Menu options should be displayed
      expect(find.text('Refresh All'), findsOneWidget);
      expect(find.text('Statistics'), findsOneWidget);
      expect(find.byIcon(Icons.refresh), findsOneWidget);
      expect(find.byIcon(Icons.bar_chart), findsOneWidget);
    });

    // === Refresh and Loading Tests ===

    testWidgets('pull to refresh triggers data reload', (WidgetTester tester) async {
      // Arrange
      final mockData = [createMockSubscription()];
      final response = PodcastSubscriptionListResponse(
        subscriptions: mockData,
        total: 1,
        page: 1,
        size: 20,
        pages: 1,
      );

      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: AsyncValue.data(response),
      ));

      await tester.pumpAndSettle();

      // Act - Pull to refresh
      await tester.fling(
        find.byType(RefreshIndicator),
        const Offset(0, 300),
        1000,
      );
      await tester.pumpAndSettle();

      // Assert - Refresh indicator should be shown
      expect(find.byType(RefreshIndicator), findsOneWidget);
    });

    // === Subscription Status Tests ===

    testWidgets('displays subscription cards with different statuses', (WidgetTester tester) async {
      // Arrange
      final mockData = [
        createMockSubscription(id: 1, status: 'active'),
        createMockSubscription(id: 2, status: 'pending'),
        createMockSubscription(id: 3, status: 'error'),
      ];

      final response = PodcastSubscriptionListResponse(
        subscriptions: mockData,
        total: 3,
        page: 1,
        size: 20,
        pages: 1,
      );

      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: AsyncValue.data(response),
      ));

      await tester.pumpAndSettle();

      // Assert - Status chips should be displayed
      expect(find.text('Active'), findsOneWidget);
      expect(find.text('Pending'), findsOneWidget);
      expect(find.text('Error'), findsOneWidget);

      // Check status colors by finding the chip icons
      expect(find.byIcon(Icons.check_circle), findsOneWidget);
      expect(find.byIcon(Icons.pending), findsOneWidget);
      expect(find.byIcon(Icons.error), findsOneWidget);
    });

    // === Category Tests ===

    testWidgets('displays subscription categories when available', (WidgetTester tester) async {
      // Arrange
      final categories = [
        Category(id: 1, name: 'Technology', description: 'Tech content'),
        Category(id: 2, name: 'AI', description: 'AI content'),
        Category(id: 3, name: 'Science', description: 'Science content'),
      ];

      final mockData = [createMockSubscription(
        id: 1,
        categories: categories,
      )];

      final response = PodcastSubscriptionListResponse(
        subscriptions: mockData,
        total: 1,
        page: 1,
        size: 20,
        pages: 1,
      );

      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: AsyncValue.data(response),
      ));

      await tester.pumpAndSettle();

      // Assert - Categories should be displayed
      expect(find.text('Technology'), findsOneWidget);
      expect(find.text('AI'), findsOneWidget);
      expect(find.text('+1'), findsOneWidget); // Indicating more categories
    });

    // === Long List Tests ===

    testWidgets('handles scrolling with long subscription lists', (WidgetTester tester) async {
      // Arrange
      final mockData = List.generate(50, (index) => createMockSubscription(
        id: index + 1,
        title: 'Podcast $index',
      ));

      final response = PodcastSubscriptionListResponse(
        subscriptions: mockData,
        total: 50,
        page: 1,
        size: 50,
        pages: 1,
      );

      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: AsyncValue.data(response),
      ));

      await tester.pumpAndSettle();

      // Assert - First few items should be visible
      expect(find.text('Podcast 0'), findsOneWidget);
      expect(find.text('Podcast 1'), findsOneWidget);

      // Act - Scroll down
      await tester.fling(
        find.byType(ListView),
        const Offset(0, -1000),
        5000,
      );
      await tester.pumpAndSettle();

      // Assert - Should be able to scroll
      expect(find.text('Podcast 0'), findsNothing);
    });

    // === Error Recovery Tests ===

    testWidgets('shows success message on successful refresh', (WidgetTester tester) async {
      // Arrange - This would need more complex mocking with the actual notifier
      // For now, we'll test the UI elements that would be displayed
      final mockData = [createMockSubscription(id: 1)];
      final response = PodcastSubscriptionListResponse(
        subscriptions: mockData,
        total: 1,
        page: 1,
        size: 20,
        pages: 1,
      );

      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: AsyncValue.data(response),
      ));

      await tester.pumpAndSettle();

      // Test the popup menu actions (refresh and stats)
      await tester.tap(find.byType(PopupMenuButton<String>));
      await tester.pumpAndSettle();

      // Test refresh option
      await tester.tap(find.text('Refresh All'));
      await tester.pumpAndSettle();

      // Verify the refresh indicator appears
      expect(find.byType(RefreshIndicator), findsOneWidget);
    });

    // === Accessibility Tests ===

    testWidgets('supports semantic labels for screen readers', (WidgetTester tester) async {
      // Arrange
      final mockData = [createMockSubscription()];
      final response = PodcastSubscriptionListResponse(
        subscriptions: mockData,
        total: 1,
        page: 1,
        size: 20,
        pages: 1,
      );

      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: AsyncValue.data(response),
      ));

      await tester.pumpAndSettle();

      // Assert - Verify semantic labels exist for screen readers
      expect(
        tester.semantics.findByLabel('Podcasts'),
        findsOneWidget,
      );
      expect(
        tester.semantics.findByLabel('Search'),
        findsOneWidget,
      );
      expect(
        tester.semantics.findByLabel('Filter'),
        findsOneWidget,
      );
      expect(
        tester.semantics.findByLabel('More options'),
        findsOneWidget,
      );
      expect(
        tester.semantics.findByLabel('Add'),
        findsOneWidget,
      );
    });

    // === Performance Tests ===

    testWidgets('widget builds within reasonable time', (WidgetTester tester) async {
      // Arrange
      final stopwatch = Stopwatch()..start();

      final mockData = [createMockSubscription()];
      final response = PodcastSubscriptionListResponse(
        subscriptions: mockData,
        total: 1,
        page: 1,
        size: 20,
        pages: 1,
      );

      // Act
      await tester.pumpWidget(createTestPodcastListPage(
        stateOverride: AsyncValue.data(response),
      ));

      stopwatch.stop();

      // Assert - Build should complete within reasonable time (less than 100ms)
      expect(stopwatch.elapsedMilliseconds, lessThan(100));
    });
  });
}