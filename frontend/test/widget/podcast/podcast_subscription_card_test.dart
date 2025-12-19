import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/category_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_subscription_card.dart';

void main() {
  group('PodcastSubscriptionCard Widget Tests', () {
    late PodcastSubscriptionModel testSubscription;

    setUp(() {
      // Initialize date formatting for tests
      Intl.defaultLocale = 'en_US';

      testSubscription = PodcastSubscriptionModel(
        id: 1,
        userId: 1,
        title: 'The Tech Podcast',
        description: 'Weekly tech news and insights',
        sourceUrl: 'https://example.com/tech-podcast.xml',
        status: 'active',
        fetchInterval: 3600,
        episodeCount: 42,
        unplayedCount: 8,
        lastFetchedAt: DateTime.now().subtract(const Duration(hours: 2)),
        createdAt: DateTime.now().subtract(const Duration(days: 30)),
      );
    });

    testWidgets('renders subscription information correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp.router(
          routerConfig: GoRouter(
            routes: [
              GoRoute(
                path: '/',
                builder: (context, state) => Scaffold(
                  body: PodcastSubscriptionCard(
                    subscription: testSubscription,
                  ),
                ),
              ),
            ],
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Check title
      expect(find.text('The Tech Podcast'), findsOneWidget);

      // Check description
      expect(find.text('Weekly tech news and insights'), findsOneWidget);

      // Check stats
      expect(find.text('42 Episodes'), findsOneWidget);
      expect(find.text('8 Unplayed'), findsOneWidget);

      // Check status chip
      expect(find.text('Active'), findsOneWidget);
    });

    testWidgets('displays "Pending" status for pending subscriptions', (WidgetTester tester) async {
      final pendingSubscription = testSubscription.copyWith(status: 'pending');

      await tester.pumpWidget(
        MaterialApp.router(
          routerConfig: GoRouter(
            routes: [
              GoRoute(
                path: '/',
                builder: (context, state) => Scaffold(
                  body: PodcastSubscriptionCard(
                    subscription: pendingSubscription,
                  ),
                ),
              ),
            ],
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('Pending'), findsOneWidget);
    });

    testWidgets('displays "Error" status for failed subscriptions', (WidgetTester tester) async {
      final errorSubscription = testSubscription.copyWith(
        status: 'error',
        errorMessage: 'Failed to fetch feed',
      );

      await tester.pumpWidget(
        MaterialApp.router(
          routerConfig: GoRouter(
            routes: [
              GoRoute(
                path: '/',
                builder: (context, state) => Scaffold(
                  body: PodcastSubscriptionCard(
                    subscription: errorSubscription,
                  ),
                ),
              ),
            ],
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('Error'), findsOneWidget);
    });

    testWidgets('shows menu button with correct options', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp.router(
          routerConfig: GoRouter(
            routes: [
              GoRoute(
                path: '/',
                builder: (context, state) => Scaffold(
                  body: PodcastSubscriptionCard(
                    subscription: testSubscription,
                  ),
                ),
              ),
            ],
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Find and tap the more options button
      await tester.tap(find.byIcon(Icons.more_vert));
      await tester.pumpAndSettle();

      // Check menu options
      expect(find.text('Refresh'), findsOneWidget);
      expect(find.text('Delete'), findsOneWidget);
    });

    testWidgets('handles tap events', (WidgetTester tester) async {
      bool wasTapped = false;

      await tester.pumpWidget(
        MaterialApp.router(
          routerConfig: GoRouter(
            routes: [
              GoRoute(
                path: '/',
                builder: (context, state) => Scaffold(
                  body: PodcastSubscriptionCard(
                    subscription: testSubscription,
                    onTap: () => wasTapped = true,
                  ),
                ),
              ),
            ],
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Tap the card
      await tester.tap(find.byType(InkWell));
      await tester.pumpAndSettle();

      expect(wasTapped, isTrue);
    });

    testWidgets('displays categories when provided', (WidgetTester tester) async {
      final subscriptionWithCategories = testSubscription.copyWith(
        categories: [
          Category(
            id: 1,
            name: 'Technology',
            color: '#FF5722',
            createdAt: DateTime.now(),
            updatedAt: DateTime.now(),
          ),
          Category(
            id: 2,
            name: 'News',
            color: '#2196F3',
            createdAt: DateTime.now(),
            updatedAt: DateTime.now(),
          ),
        ],
      );

      await tester.pumpWidget(
        MaterialApp.router(
          routerConfig: GoRouter(
            routes: [
              GoRoute(
                path: '/',
                builder: (context, state) => Scaffold(
                  body: PodcastSubscriptionCard(
                    subscription: subscriptionWithCategories,
                  ),
                ),
              ),
            ],
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('Technology'), findsOneWidget);
      expect(find.text('News'), findsOneWidget);
    });

    testWidgets('displays subscription without description', (WidgetTester tester) async {
      final subscriptionWithoutDescription = testSubscription.copyWith(
        description: null,
      );

      await tester.pumpWidget(
        MaterialApp.router(
          routerConfig: GoRouter(
            routes: [
              GoRoute(
                path: '/',
                builder: (context, state) => Scaffold(
                  body: PodcastSubscriptionCard(
                    subscription: subscriptionWithoutDescription,
                  ),
                ),
              ),
            ],
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Title should still be visible
      expect(find.text('The Tech Podcast'), findsOneWidget);

      // Description should not be present
      expect(find.text('Weekly tech news and insights'), findsNothing);
    });

    testWidgets('displays correct last fetched time', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp.router(
          routerConfig: GoRouter(
            routes: [
              GoRoute(
                path: '/',
                builder: (context, state) => Scaffold(
                  body: PodcastSubscriptionCard(
                    subscription: testSubscription,
                  ),
                ),
              ),
            ],
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Should show "Updated X" where X is the formatted date
      expect(find.textContaining('Updated'), findsOneWidget);
    });
  });
}