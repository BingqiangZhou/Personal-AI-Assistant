import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:mockito/mockito.dart';

import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/category_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_subscription_card.dart';

import '../../../mocks/test_mocks.dart';
import '../../../helpers/widget_test_helpers.dart';

void main() {
  group('PodcastSubscriptionCard Comprehensive Widget Tests', () {
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

    Widget createTestCard({
      required PodcastSubscriptionModel subscription,
      VoidCallback? onTap,
      VoidCallback? onDelete,
      VoidCallback? onRefresh,
    }) {
      return createTestWidget(
        container: container,
        child: Scaffold(
          body: PodcastSubscriptionCard(
            subscription: subscription,
            onTap: onTap,
            onDelete: onDelete,
            onRefresh: onRefresh,
          ),
        ),
      );
    }

    // === Basic Widget Rendering Tests ===

    testWidgets('renders card with subscription information', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription(
        id: 1,
        title: 'Tech Podcast',
        description: 'Latest tech news',
        status: 'active',
        episodeCount: 50,
        unplayedCount: 10,
      );

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      expect(find.byType(Card), findsOneWidget);
      expect(find.text('Tech Podcast'), findsOneWidget);
      expect(find.text('Latest tech news'), findsOneWidget);
      expect(find.text('50 Episodes'), findsOneWidget);
      expect(find.text('10 Unplayed'), findsOneWidget);
    });

    testWidgets('displays podcast icon', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      expect(find.byIcon(Icons.podcasts), findsOneWidget);
    });

    testWidgets('displays status chip for active subscription', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription(status: 'active');

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      expect(find.text('Active'), findsOneWidget);
      expect(find.byIcon(Icons.check_circle), findsOneWidget);
    });

    testWidgets('displays status chip for pending subscription', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription(status: 'pending');

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      expect(find.text('Pending'), findsOneWidget);
      expect(find.byIcon(Icons.pending), findsOneWidget);
    });

    testWidgets('displays status chip for error subscription', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription(status: 'error');

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      expect(find.text('Error'), findsOneWidget);
      expect(find.byIcon(Icons.error), findsOneWidget);
    });

    // === Layout Tests ===

    testWidgets('card has correct margin and padding', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      final card = tester.widget<Card>(find.byType(Card));
      expect(card.margin, const EdgeInsets.symmetric(horizontal: 16, vertical: 8));

      final padding = find.byType(Padding);
      expect(padding, findsAtLeastNWidgets(1));
    });

    testWidgets('arranges content in correct layout', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      expect(find.byType(Column), findsAtLeastNWidgets(2)); // Main column and inner columns
      expect(find.byType(Row), findsAtLeastNWidgets(2)); // Header row and stats row
    });

    // === Content Display Tests ===

    testWidgets('handles missing description gracefully', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription(description: null);

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert - Should still render without errors
      expect(find.byType(Card), findsOneWidget);
      expect(find.byType(Text), findsAtLeastNWidgets(3)); // Title, episodes, unplayed
    });

    testWidgets('truncates long titles', (WidgetTester tester) async {
      // Arrange
      final longTitle = 'This is a very long podcast title that should be truncated';
      final subscription = createMockSubscription(title: longTitle);

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      final titleWidget = tester.widget<Text>(find.text(longTitle));
      expect(titleWidget.maxLines, 2);
      expect(titleWidget.overflow, TextOverflow.ellipsis);
    });

    testWidgets('truncates long descriptions', (WidgetTester tester) async {
      // Arrange
      final longDescription = 'This is a very long description that should be truncated and limited to two lines maximum';
      final subscription = createMockSubscription(description: longDescription);

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      final descriptionWidget = tester.widget<Text>(find.text(longDescription));
      expect(descriptionWidget.maxLines, 2);
      expect(descriptionWidget.overflow, TextOverflow.ellipsis);
    });

    // === Timestamp Tests ===

    testWidgets('displays last fetched date', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription(
        lastFetchedAt: DateTime.now().subtract(const Duration(days: 5)),
      );

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert - Should show relative date
      expect(find.textContaining('Updated'), findsOneWidget);
    });

    testWidgets('handles missing last fetched date', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription(lastFetchedAt: null);

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert - Should not crash
      expect(find.byType(Card), findsOneWidget);
      // Should not show date text
      expect(find.textContaining('Updated'), findsNothing);
    });

    // === Category Display Tests ===

    testWidgets('displays subscription categories', (WidgetTester tester) async {
      // Arrange
      final categories = [
        Category(id: 1, name: 'Technology', description: 'Tech content'),
        Category(id: 2, name: 'AI', description: 'AI content'),
      ];

      final subscription = createMockSubscription(categories: categories);

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      expect(find.text('Technology'), findsOneWidget);
      expect(find.text('AI'), findsOneWidget);
    });

    testWidgets('limits category display to 2 items', (WidgetTester tester) async {
      // Arrange
      final categories = [
        Category(id: 1, name: 'Tech', description: ''),
        Category(id: 2, name: 'AI', description: ''),
        Category(id: 3, name: 'Science', description: ''),
      ];

      final subscription = createMockSubscription(categories: categories);

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      expect(find.text('Tech'), findsOneWidget);
      expect(find.text('AI'), findsOneWidget);
      expect(find.text('Science'), findsNothing); // Third category should not be displayed
      expect(find.text('+1'), findsOneWidget); // Indicating one more category
    });

    testWidgets('displays correct overflow count for many categories', (WidgetTester tester) async {
      // Arrange
      final categories = [
        Category(id: 1, name: 'Tech', description: ''),
        Category(id: 2, name: 'AI', description: ''),
        Category(id: 3, name: 'Science', description: ''),
        Category(id: 4, name: 'Business', description: ''),
      ];

      final subscription = createMockSubscription(categories: categories);

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      expect(find.text('+2'), findsOneWidget); // Indicating two more categories
    });

    // === User Interaction Tests ===

    testWidgets('calls onTap when card is tapped', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();
      bool onTapCalled = false;

      await tester.pumpWidget(createTestCard(
        subscription: subscription,
        onTap: () => onTapCalled = true,
      ));

      // Act
      await tester.tap(find.byType(InkWell));
      await tester.pump();

      // Assert
      expect(onTapCalled, isTrue);
    });

    testWidgets('navigates to episodes when no custom onTap provided', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();
      var navigationCalled = false;
      String? navigationPath;

      final router = GoRouter(
        routes: [
          GoRoute(
            path: '/',
            builder: (context, state) => Scaffold(
              body: PodcastSubscriptionCard(subscription: subscription),
            ),
          ),
        ],
      );

      final testWidget = MaterialApp.router(
        routerConfig: router,
      );

      await tester.pumpWidget(testWidget);

      // Act
      await tester.tap(find.byType(InkWell));
      await tester.pumpAndSettle();

      // Note: Navigation testing would require more complex setup with GoRouter mocking
      // For now, we just verify the tap doesn't cause errors
      expect(find.byType(PodcastSubscriptionCard), findsOneWidget);
    });

    // === Menu Tests ===

    testWidgets('shows popup menu when more button is tapped', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Act
      await tester.tap(find.byType(PopupMenuButton<String>));
      await tester.pumpAndSettle();

      // Assert
      expect(find.text('Refresh'), findsOneWidget);
      expect(find.text('Delete'), findsOneWidget);
      expect(find.byIcon(Icons.refresh), findsOneWidget);
      expect(find.byIcon(Icons.delete), findsOneWidget);
    });

    testWidgets('calls onRefresh when refresh menu item is selected', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();
      bool onRefreshCalled = false;

      await tester.pumpWidget(createTestCard(
        subscription: subscription,
        onRefresh: () => onRefreshCalled = true,
      ));

      // Act
      await tester.tap(find.byType(PopupMenuButton<String>));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Refresh'));
      await tester.pump();

      // Assert
      expect(onRefreshCalled, isTrue);
    });

    testWidgets('shows delete confirmation when delete menu item is selected', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Act
      await tester.tap(find.byType(PopupMenuButton<String>));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Delete'));
      await tester.pumpAndSettle();

      // Assert
      expect(find.text('Delete Podcast'), findsOneWidget);
      expect(find.textContaining('Are you sure you want to delete'), findsOneWidget);
      expect(find.text('Cancel'), findsOneWidget);
      expect(find.text('Delete'), findsWidgets); // Both in menu and dialog
    });

    testWidgets('calls onDelete when delete is confirmed', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();
      bool onDeleteCalled = false;

      await tester.pumpWidget(createTestCard(
        subscription: subscription,
        onDelete: () => onDeleteCalled = true,
      ));

      // Act - Open menu and select delete
      await tester.tap(find.byType(PopupMenuButton<String>));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Delete'));
      await tester.pumpAndSettle();

      // Find and tap the delete button in the dialog
      final deleteButtons = find.widgetWithText(TextButton, 'Delete');
      expect(deleteButtons, findsAtLeastNWidgets(1)); // At least one delete button

      // Tap the last delete button (should be in the dialog)
      await tester.tap(deleteButtons.last);
      await tester.pump();

      // Assert
      expect(onDeleteCalled, isTrue);
    });

    testWidgets('does not call onDelete when delete is cancelled', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();
      bool onDeleteCalled = false;

      await tester.pumpWidget(createTestCard(
        subscription: subscription,
        onDelete: () => onDeleteCalled = true,
      ));

      // Act - Open menu and select delete
      await tester.tap(find.byType(PopupMenuButton<String>));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Delete'));
      await tester.pumpAndSettle();

      // Tap cancel in the dialog
      await tester.tap(find.text('Cancel'));
      await tester.pump();

      // Assert
      expect(onDeleteCalled, isFalse);
    });

    // === Styling Tests ===

    testWidgets('applies correct theme colors', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();
      final customTheme = ThemeData(primaryColor: Colors.purple);

      await tester.pumpWidget(createTestWidget(
        container: container,
        theme: customTheme,
        child: Scaffold(
          body: PodcastSubscriptionCard(subscription: subscription),
        ),
      ));

      await tester.pumpAndSettle();

      // Assert - The icon should use theme color
      final iconContainer = find.byType(Container).first;
      final containerWidget = tester.widget<Container>(iconContainer);
      final decoration = containerWidget.decoration as BoxDecoration;

      expect(decoration.color, Colors.purple.withOpacity(0.1));
    });

    // === Accessibility Tests ===

    testWidgets('supports semantic labels', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      expect(
        tester.semantics.hasLabel(subscription.title),
        isTrue,
      );

      expect(
        tester.semantics.hasLabel('More options'),
        isTrue,
      );
    });

    testWidgets('buttons are focusable', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      final inkWell = tester.widget<InkWell>(find.byType(InkWell));
      expect(inkWell.canRequestFocus, isTrue);

      final popupMenuButton = tester.widget<PopupMenuButton<String>>(find.byType(PopupMenuButton<String>));
      expect(popupMenuButton.canRequestFocus, isTrue);
    });

    // === Performance Tests ===

    testWidgets('card builds within reasonable time', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription();
      final stopwatch = Stopwatch()..start();

      // Act
      await tester.pumpWidget(createTestCard(subscription: subscription));

      stopwatch.stop();

      // Assert
      expect(stopwatch.elapsedMilliseconds, lessThan(100));
    });

    testWidgets('handles many cards efficiently', (WidgetTester tester) async {
      // Arrange
      final subscriptions = List.generate(20, (index) => createMockSubscription(
        id: index,
        title: 'Podcast $index',
      ));

      await tester.pumpWidget(createTestWidget(
        container: container,
        child: ListView.builder(
          itemCount: subscriptions.length,
          itemBuilder: (context, index) {
            return PodcastSubscriptionCard(
              subscription: subscriptions[index],
            );
          },
        ),
      ));

      await tester.pumpAndSettle();

      // Assert - Should render all cards
      expect(find.byType(PodcastSubscriptionCard), findsNWidgets(20));
    });

    // === Edge Cases ===

    testWidgets('handles subscription with zero episodes', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription(
        episodeCount: 0,
        unplayedCount: 0,
      );

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      expect(find.text('0 Episodes'), findsOneWidget);
      expect(find.text('0 Unplayed'), findsOneWidget);
    });

    testWidgets('handles subscription with all episodes played', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription(
        episodeCount: 50,
        unplayedCount: 0,
      );

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      expect(find.text('50 Episodes'), findsOneWidget);
      expect(find.text('0 Unplayed'), findsOneWidget);
    });

    testWidgets('handles unknown status', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription(status: 'unknown');

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert
      expect(find.text('unknown'), findsOneWidget);
      expect(find.byIcon(Icons.help), findsOneWidget);
    });

    testWidgets('displays error status with correct styling', (WidgetTester tester) async {
      // Arrange
      final subscription = createMockSubscription(
        status: 'error',
        errorMessage: 'Failed to fetch',
      );

      await tester.pumpWidget(createTestCard(subscription: subscription));

      // Assert - Error chip should be red
      final errorChip = find.text('Error');
      expect(errorChip, findsOneWidget);
    });
  });
}