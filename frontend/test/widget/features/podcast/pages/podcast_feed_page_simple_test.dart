import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_feed_page.dart';
import 'package:personal_ai_assistant/core/widgets/custom_adaptive_navigation.dart';

void main() {
  group('PodcastFeedPage Basic Widget Tests', () {
    testWidgets('renders with Feed title and page structure', (WidgetTester tester) async {
      // Arrange & Act
      await tester.pumpWidget(
        MaterialApp(
          home: PodcastFeedPage(),
        ),
      );

      // Assert - Should find "Feed" title text (as page title, not AppBar)
      expect(find.text('Feed'), findsOneWidget);

      // Should find the page structure
      expect(find.byType(PodcastFeedPage), findsOneWidget);
      expect(find.byType(ResponsiveContainer), findsOneWidget);
    });

    testWidgets('displays mock data on mobile screen', (WidgetTester tester) async {
      // Arrange - Set mobile screen size
      tester.view.physicalSize = const Size(360, 800);
      tester.view.devicePixelRatio = 1.0;

      // Act
      await tester.pumpWidget(
        MaterialApp(
          home: PodcastFeedPage(),
        ),
      );

      await tester.pumpAndSettle();

      // Assert - Should find mock episode titles
      expect(find.text('The Future of AI in Software Development'), findsOneWidget);
      expect(find.text('Building Scalable Microservices'), findsOneWidget);
      expect(find.text('The Psychology of Product Design'), findsOneWidget);

      // Should find mobile cards
      expect(find.byType(Card), findsWidgets);
    });

    testWidgets('displays mock data on desktop screen', (WidgetTester tester) async {
      // Arrange - Set desktop screen size
      tester.view.physicalSize = const Size(1200, 800);
      tester.view.devicePixelRatio = 1.0;

      // Act
      await tester.pumpWidget(
        MaterialApp(
          home: PodcastFeedPage(),
        ),
      );

      await tester.pumpAndSettle();

      // Assert - Should find mock episode titles
      expect(find.text('The Future of AI in Software Development'), findsOneWidget);
      expect(find.text('Building Scalable Microservices'), findsOneWidget);

      // Should find grid cards
      expect(find.byType(Card), findsWidgets);
    });

    testWidgets('has no overflow errors on small screens', (WidgetTester tester) async {
      // Arrange - Very small screen
      tester.view.physicalSize = const Size(320, 480);
      tester.view.devicePixelRatio = 1.0;

      // Act
      await tester.pumpWidget(
        MaterialApp(
          home: PodcastFeedPage(),
        ),
      );

      await tester.pumpAndSettle();

      // Assert - No overflow errors
      expect(tester.takeException(), isNull);

      // Should still render content
      expect(find.byType(Card), findsWidgets);
    });

    testWidgets('cards contain play buttons', (WidgetTester tester) async {
      // Arrange
      tester.view.physicalSize = const Size(800, 800);
      tester.view.devicePixelRatio = 1.0;

      // Act
      await tester.pumpWidget(
        MaterialApp(
          home: PodcastFeedPage(),
        ),
      );

      await tester.pumpAndSettle();

      // Assert - Should find Play buttons
      expect(find.text('Play'), findsWidgets);
    });

    testWidgets('cards contain metadata icons', (WidgetTester tester) async {
      // Arrange
      tester.view.physicalSize = const Size(800, 800);
      tester.view.devicePixelRatio = 1.0;

      // Act
      await tester.pumpWidget(
        MaterialApp(
          home: PodcastFeedPage(),
        ),
      );

      await tester.pumpAndSettle();

      // Assert - Should find time-related icons
      expect(find.byIcon(Icons.schedule), findsWidgets);
      expect(find.byIcon(Icons.access_time), findsWidgets);
    });
  });
}