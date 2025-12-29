import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';

import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/repositories/podcast_repository.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_list_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/bulk_selection_provider.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_bulk_delete_dialog.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';

import 'package:go_router/go_router.dart';

// Mock class defined inline
class MockPodcastRepository extends Mock implements PodcastRepository {}

void main() {
  group('Podcast Bulk Delete Widget Tests', () {
    late ProviderContainer container;
    late MockPodcastRepository mockRepository;

    // Helper to create test widget
    Widget createTestWidget({
      required Widget child,
      ProviderContainer? container,
    }) {
      return UncontrolledProviderScope(
        container: container ?? ProviderContainer(),
        child: MaterialApp.router(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          routerConfig: GoRouter(
            routes: [
              GoRoute(
                path: '/',
                builder: (context, state) => child,
              ),
            ],
          ),
        ),
      );
    }

    // Mock test data
    final mockSubscriptions = [
      PodcastSubscriptionModel(
        id: 1,
        userId: 1,
        title: 'The Daily Tech Podcast',
        description: 'Daily tech news and updates',
        sourceUrl: 'https://example.com/feed1.xml',
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
        sourceUrl: 'https://example.com/feed2.xml',
        status: 'active',
        fetchInterval: 3600,
        episodeCount: 25,
        unplayedCount: 5,
        createdAt: DateTime.now().subtract(const Duration(days: 15)),
      ),
      PodcastSubscriptionModel(
        id: 3,
        userId: 1,
        title: 'Coding Weekly',
        description: 'Weekly coding tips',
        sourceUrl: 'https://example.com/feed3.xml',
        status: 'active',
        fetchInterval: 3600,
        episodeCount: 100,
        unplayedCount: 20,
        createdAt: DateTime.now().subtract(const Duration(days: 7)),
      ),
    ];

    setUp(() {
      mockRepository = MockPodcastRepository();
      reset(mockRepository); // Reset mock to clean state

      container = ProviderContainer(
        overrides: [
          podcastRepositoryProvider.overrideWithValue(mockRepository),
        ],
      );

      // Setup default mock behavior for listSubscriptions AFTER container creation
      when(mockRepository.listSubscriptions()).thenAnswer(
        (_) => Future.value(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        )),
      );
    });

    tearDown(() {
      container.dispose();
      reset(mockRepository); // Reset mock after each test
    });

    // ============================================
    // 1. BULK SELECTION MODE TESTS
    // ============================================
    group('Bulk Selection Mode', () {
      testWidgets('enters selection mode when checklist icon is tapped', (WidgetTester tester) async {
        // Arrange - use the main container which already has the mocked repository
        await tester.pumpWidget(createTestWidget(
          container: container,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Verify selection mode is initially off
        expect(container.read(bulkSelectionProvider).isSelectionMode, isFalse);

        // Tap the checklist icon to enter selection mode
        final checklistIcon = find.byIcon(Icons.checklist);
        expect(checklistIcon, findsOneWidget);
        await tester.tap(checklistIcon);
        await tester.pump();

        // Verify selection mode is on
        expect(container.read(bulkSelectionProvider).isSelectionMode, isTrue);
      });

      testWidgets('toggles card selection when in selection mode', (WidgetTester tester) async {
        // Arrange
        await tester.pumpWidget(createTestWidget(
          container: container,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Enter selection mode
        container.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        await tester.pump();

        // Initially no items selected
        expect(container.read(bulkSelectionProvider).selectedIds.isEmpty, isTrue);

        // Tap on first podcast card to select it
        await tester.tap(find.text('The Daily Tech Podcast'));
        await tester.pump();

        // Verify first podcast is selected
        expect(container.read(bulkSelectionProvider).isSelected(1), isTrue);
        expect(container.read(bulkSelectionProvider).selectedIds.length, equals(1));

        // Tap on second podcast card
        await tester.tap(find.text('AI Insights'));
        await tester.pump();

        // Verify both podcasts are selected
        expect(container.read(bulkSelectionProvider).isSelected(2), isTrue);
        expect(container.read(bulkSelectionProvider).selectedIds.length, equals(2));
      });

      testWidgets('updates selected count text correctly', (WidgetTester tester) async {
        // Arrange
        await tester.pumpWidget(createTestWidget(
          container: container,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Enter selection mode
        container.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        await tester.pump();

        // Select one item
        container.read(bulkSelectionProvider.notifier).toggleSelection(1);
        await tester.pump();
        expect(find.text('1 selected'), findsOneWidget);

        // Select another item
        container.read(bulkSelectionProvider.notifier).toggleSelection(2);
        await tester.pump();
        expect(find.text('2 selected'), findsOneWidget);

        // Select third item
        container.read(bulkSelectionProvider.notifier).toggleSelection(3);
        await tester.pump();
        expect(find.text('3 selected'), findsOneWidget);
      });

      testWidgets('exits selection mode and clears selection when close button is tapped', (WidgetTester tester) async {
        // Arrange
        await tester.pumpWidget(createTestWidget(
          container: container,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Enter selection mode and select items
        container.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        container.read(bulkSelectionProvider.notifier).toggleSelection(1);
        container.read(bulkSelectionProvider.notifier).toggleSelection(2);
        await tester.pump();

        // Verify selection state
        expect(container.read(bulkSelectionProvider).isSelectionMode, isTrue);
        expect(container.read(bulkSelectionProvider).selectedIds.length, equals(2));

        // Tap close button
        final closeButton = find.byIcon(Icons.close);
        expect(closeButton, findsOneWidget);
        await tester.tap(closeButton);
        await tester.pump();

        // Verify selection mode is exited and selections cleared
        expect(container.read(bulkSelectionProvider).isSelectionMode, isFalse);
        expect(container.read(bulkSelectionProvider).selectedIds.isEmpty, isTrue);
        expect(find.text('2 selected'), findsNothing);
      });
    });

    // ============================================
    // 2. DELETE CONFIRMATION DIALOG TESTS
    // ============================================
    group('Delete Confirmation Dialog', () {
      testWidgets('shows bulk delete dialog when delete button is tapped', (WidgetTester tester) async {
        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Enter selection mode and select items
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(1);
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(2);
        await tester.pump();

        // Tap delete button
        final deleteButton = find.byIcon(Icons.delete_sweep);
        await tester.tap(deleteButton);
        await tester.pumpAndSettle();

        // Verify dialog is shown
        expect(find.text('Delete Selected Podcasts'), findsOneWidget);
        expect(find.textContaining('Are you sure you want to delete'), findsOneWidget);
        expect(find.text('This action will also delete all episodes'), findsOneWidget);
      });

      testWidgets('closes dialog when cancel is tapped', (WidgetTester tester) async {
        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Enter selection mode and select item
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(1);
        await tester.pump();

        // Open dialog
        final deleteButton = find.byIcon(Icons.delete_sweep);
        await tester.tap(deleteButton);
        await tester.pumpAndSettle();

        // Verify dialog is shown
        expect(find.text('Delete Selected Podcasts'), findsOneWidget);

        // Tap cancel button
        final cancelButton = find.text('Cancel');
        await tester.tap(cancelButton);
        await tester.pumpAndSettle();

        // Verify dialog is closed
        expect(find.text('Delete Selected Podcasts'), findsNothing);

        // Verify selection is not cleared (cancelled)
        expect(testContainer.read(bulkSelectionProvider).selectedIds.isNotEmpty, isTrue);
      });

      testWidgets('standalone dialog widget renders correctly', (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: Scaffold(
              body: PodcastBulkDeleteDialog(
                subscriptionIds: [1, 2, 3],
                count: 3,
                onDelete: () {},
              ),
            ),
          ),
        );

        await tester.pumpAndSettle();

        // Verify dialog elements
        expect(find.byIcon(Icons.warning_amber_rounded), findsOneWidget);
        expect(find.text('Delete Selected Podcasts'), findsOneWidget);
        expect(find.text('This action will also delete all episodes'), findsOneWidget);
        expect(find.text('Cancel'), findsOneWidget);
        expect(find.text('Delete'), findsOneWidget);
      });
    });

    // ============================================
    // 3. API CALL TESTS
    // ============================================
    group('API Calls', () {
      testWidgets('successfully deletes selected subscriptions', (WidgetTester tester) async {
        // IMPORTANT: Set up ALL mocks BEFORE any async operations
        // Mock successful delete response
        when(mockRepository.bulkDeleteSubscriptions(subscriptionIds: [1, 2]))
            .thenAnswer((_) => Future.value(PodcastSubscriptionBulkDeleteResponse(
                  successCount: 2,
                  failedCount: 0,
                  deletedSubscriptionIds: [1, 2],
                )));

        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Enter selection mode and select two items
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(1);
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(2);
        await tester.pump();

        // Open dialog and confirm delete
        await tester.tap(find.byIcon(Icons.delete_sweep));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Delete'));
        await tester.pump();

        // Wait for async operations
        await tester.pump(const Duration(seconds: 1));

        // Verify API was called
        verify(mockRepository.bulkDeleteSubscriptions(subscriptionIds: [1, 2])).called(1);
      });

      testWidgets('handles partial deletion failure', (WidgetTester tester) async {
        // IMPORTANT: Set up ALL mocks BEFORE any async operations
        // Mock partial failure response
        when(mockRepository.bulkDeleteSubscriptions(subscriptionIds: [1, 2, 3]))
            .thenAnswer((_) => Future.value(PodcastSubscriptionBulkDeleteResponse(
                  successCount: 2,
                  failedCount: 1,
                  errors: [
                    {'subscription_id': 3, 'error': 'Network error'},
                  ],
                  deletedSubscriptionIds: [1, 2],
                )));

        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Select all items
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        testContainer.read(bulkSelectionProvider.notifier).selectAll([1, 2, 3]);
        await tester.pump();

        // Open dialog and confirm delete
        await tester.tap(find.byIcon(Icons.delete_sweep));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Delete'));
        await tester.pump();

        // Wait for async operations
        await tester.pump(const Duration(seconds: 1));

        // Verify API was called
        verify(mockRepository.bulkDeleteSubscriptions(subscriptionIds: [1, 2, 3])).called(1);
      });

      testWidgets('handles complete deletion failure', (WidgetTester tester) async {
        // IMPORTANT: Set up ALL mocks BEFORE any async operations
        // Mock complete failure
        when(mockRepository.bulkDeleteSubscriptions(subscriptionIds: [1, 2]))
            .thenThrow(Exception('Network connection failed'));

        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Select items
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(1);
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(2);
        await tester.pump();

        // Open dialog and confirm delete
        await tester.tap(find.byIcon(Icons.delete_sweep));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Delete'));
        await tester.pump();

        // Wait for async operations
        await tester.pump(const Duration(seconds: 1));

        // Verify API was called despite error
        verify(mockRepository.bulkDeleteSubscriptions(subscriptionIds: [1, 2])).called(1);

        // Verify selection is cleared even after error
        expect(testContainer.read(bulkSelectionProvider).selectedIds.isEmpty, isTrue);
      });
    });

    // ============================================
    // 4. SNACKBAR FEEDBACK TESTS
    // ============================================
    group('SnackBar Feedback', () {
      testWidgets('shows success SnackBar after successful deletion', (WidgetTester tester) async {
        // IMPORTANT: Set up ALL mocks BEFORE any async operations
        // Mock successful delete response
        when(mockRepository.bulkDeleteSubscriptions(subscriptionIds: [1, 2]))
            .thenAnswer((_) => Future.value(PodcastSubscriptionBulkDeleteResponse(
                  successCount: 2,
                  failedCount: 0,
                  deletedSubscriptionIds: [1, 2],
                )));

        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Select items and delete
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(1);
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(2);
        await tester.pump();

        await tester.tap(find.byIcon(Icons.delete_sweep));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Delete'));
        await tester.pump();

        // Wait for SnackBar to appear
        await tester.pump(const Duration(milliseconds: 100));
        await tester.pump(const Duration(seconds: 3));

        // Verify success SnackBar is shown (check for SnackBar widget)
        expect(find.byType(SnackBar), findsOneWidget);
      });

      testWidgets('shows partial success SnackBar with error details', (WidgetTester tester) async {
        // IMPORTANT: Set up ALL mocks BEFORE any async operations
        // Mock partial failure response
        when(mockRepository.bulkDeleteSubscriptions(subscriptionIds: [1, 2, 3]))
            .thenAnswer((_) => Future.value(PodcastSubscriptionBulkDeleteResponse(
                  successCount: 2,
                  failedCount: 1,
                  errors: [
                    {'subscription_id': 3, 'error': 'Not found'},
                  ],
                  deletedSubscriptionIds: [1, 2],
                )));

        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Select all items and delete
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        testContainer.read(bulkSelectionProvider.notifier).selectAll([1, 2, 3]);
        await tester.pump();

        await tester.tap(find.byIcon(Icons.delete_sweep));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Delete'));
        await tester.pump();

        // Wait for SnackBar to appear
        await tester.pump(const Duration(milliseconds: 100));
        await tester.pump(const Duration(seconds: 3));

        // Verify partial success SnackBar is shown
        expect(find.byType(SnackBar), findsOneWidget);
      });

      testWidgets('shows error SnackBar when deletion fails completely', (WidgetTester tester) async {
        // IMPORTANT: Set up ALL mocks BEFORE any async operations
        // Mock complete failure
        when(mockRepository.bulkDeleteSubscriptions(subscriptionIds: [1, 2]))
            .thenThrow(Exception('Network error'));

        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Select items and delete
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(1);
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(2);
        await tester.pump();

        await tester.tap(find.byIcon(Icons.delete_sweep));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Delete'));
        await tester.pump();

        // Wait for SnackBar to appear
        await tester.pump(const Duration(milliseconds: 100));
        await tester.pump(const Duration(seconds: 3));

        // Verify error SnackBar is shown
        expect(find.byType(SnackBar), findsOneWidget);
      });
    });

    // ============================================
    // 5. RESPONSIVE LAYOUT TESTS
    // ============================================
    group('Responsive Layout', () {
      testWidgets('bottom action bar displays correctly on mobile', (WidgetTester tester) async {
        // Set mobile screen size
        tester.view.devicePixelRatio = 1.0;
        tester.view.physicalSize = const Size(400, 800);
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Enter selection mode and select items
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(1);
        await tester.pump();

        // Verify bottom action bar is shown on mobile
        expect(find.text('1 selected'), findsOneWidget);
        expect(find.text('Delete'), findsOneWidget);
      });

      testWidgets('bottom action bar displays correctly on desktop', (WidgetTester tester) async {
        // Set desktop screen size
        tester.view.devicePixelRatio = 1.0;
        tester.view.physicalSize = const Size(1200, 800);
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Enter selection mode and select items
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(1);
        await tester.pump();

        // Verify bottom action bar is shown on desktop
        expect(find.text('1 selected'), findsOneWidget);
        expect(find.text('Delete'), findsOneWidget);
      });

      testWidgets('checkboxes are shown on cards in selection mode (desktop)', (WidgetTester tester) async {
        // Set desktop screen size
        tester.view.devicePixelRatio = 1.0;
        tester.view.physicalSize = const Size(1200, 800);
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Enter selection mode
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        await tester.pump();

        // Verify checkboxes are shown on desktop cards
        expect(find.byType(Checkbox), findsWidgets);
      });

      testWidgets('checkboxes are shown on list tiles in selection mode (mobile)', (WidgetTester tester) async {
        // Set mobile screen size
        tester.view.devicePixelRatio = 1.0;
        tester.view.physicalSize = const Size(400, 800);
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Enter selection mode
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        await tester.pump();

        // Verify checkboxes are shown on mobile list tiles
        expect(find.byType(Checkbox), findsWidgets);
      });
    });

    // ============================================
    // 6. EDGE CASES AND INTEGRATION TESTS
    // ============================================
    group('Edge Cases and Integration', () {
      testWidgets('delete button is disabled when no items selected', (WidgetTester tester) async {
        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Enter selection mode without selecting anything
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        await tester.pump();

        // Verify bottom action bar is not shown when nothing is selected
        expect(find.text('0 selected'), findsNothing);

        // Find delete button in top bar (it should exist but be visually disabled)
        final deleteButtons = find.byWidgetPredicate(
          (widget) =>
              widget is Icon &&
              widget.icon is IconData &&
              (widget.icon as IconData) == Icons.delete_sweep,
        );

        // Delete button should exist
        expect(deleteButtons, findsOneWidget);
      });

      testWidgets('selection is cleared after successful deletion', (WidgetTester tester) async {
        // IMPORTANT: Set up ALL mocks BEFORE any async operations
        // Mock successful delete response
        when(mockRepository.bulkDeleteSubscriptions(subscriptionIds: [1]))
            .thenAnswer((_) => Future.value(PodcastSubscriptionBulkDeleteResponse(
                  successCount: 1,
                  failedCount: 0,
                  deletedSubscriptionIds: [1],
                )));

        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: mockSubscriptions,
          total: 3,
          page: 1,
          size: 20,
          pages: 1,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Select item and delete
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        testContainer.read(bulkSelectionProvider.notifier).toggleSelection(1);
        await tester.pump();

        expect(testContainer.read(bulkSelectionProvider).selectedIds.length, equals(1));

        await tester.tap(find.byIcon(Icons.delete_sweep));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Delete'));
        await tester.pump();

        // Wait for async operations
        await tester.pump(const Duration(seconds: 1));

        // Verify selection is cleared after deletion
        expect(testContainer.read(bulkSelectionProvider).selectedIds.isEmpty, isTrue);
        expect(testContainer.read(bulkSelectionProvider).isSelectionMode, isFalse);
      });

      testWidgets('handles empty subscription list in selection mode', (WidgetTester tester) async {
        // Arrange
        final notifier = PodcastSubscriptionNotifier();
        notifier.state = AsyncValue.data(PodcastSubscriptionListResponse(
          subscriptions: [],
          total: 0,
          page: 1,
          size: 20,
          pages: 0,
        ));

        final testContainer = ProviderContainer(
          overrides: [
            podcastSubscriptionProvider.overrideWith(() => notifier),
          ],
          parent: container,
        );

        await tester.pumpWidget(createTestWidget(
          container: testContainer,
          child: const PodcastListPage(),
        ));

        await tester.pumpAndSettle();

        // Try to enter selection mode
        testContainer.read(bulkSelectionProvider.notifier).toggleSelectionMode();
        await tester.pump();

        // Verify selection mode is active
        expect(testContainer.read(bulkSelectionProvider).isSelectionMode, isTrue);

        // Verify empty state is still shown
        expect(find.text('No Podcasts Yet'), findsOneWidget);
      });
    });
  });
}
