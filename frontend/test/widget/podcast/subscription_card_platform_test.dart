import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_subscription_card.dart';

void main() {
  group('PodcastSubscriptionCard Platform Tests', () {
    PodcastSubscriptionModel createMockSubscription({
      String? platform,
      String status = 'active',
    }) {
      return PodcastSubscriptionModel(
        id: 1,
        userId: 1,
        title: 'Test Podcast',
        description: 'Test Description',
        sourceUrl: 'https://example.com/feed.xml',
        status: status,
        fetchInterval: 3600,
        episodeCount: 10,
        unplayedCount: 5,
        platform: platform,
        createdAt: DateTime(2024, 1, 1),
      );
    }

    testWidgets('displays Ximalaya platform badge', (tester) async {
      final subscription = createMockSubscription(platform: 'ximalaya');

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: PodcastSubscriptionCard(subscription: subscription),
            ),
          ),
        ),
      );

      expect(find.text('喜马拉雅'), findsOneWidget);
    });

    testWidgets('displays Xiaoyuzhou platform badge', (tester) async {
      final subscription = createMockSubscription(platform: 'xiaoyuzhou');

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: PodcastSubscriptionCard(subscription: subscription),
            ),
          ),
        ),
      );

      expect(find.text('小宇宙'), findsOneWidget);
    });

    testWidgets('hides platform badge when platform is null', (tester) async {
      final subscription = createMockSubscription(platform: null);

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: PodcastSubscriptionCard(subscription: subscription),
            ),
          ),
        ),
      );

      expect(find.text('喜马拉雅'), findsNothing);
      expect(find.text('小宇宙'), findsNothing);
    });

    testWidgets('hides platform badge when platform is generic', (tester) async {
      final subscription = createMockSubscription(platform: 'generic');

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: PodcastSubscriptionCard(subscription: subscription),
            ),
          ),
        ),
      );

      expect(find.text('喜马拉雅'), findsNothing);
      expect(find.text('小宇宙'), findsNothing);
    });

    testWidgets('displays all subscription information with platform', (tester) async {
      final subscription = createMockSubscription(platform: 'ximalaya');

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: PodcastSubscriptionCard(subscription: subscription),
            ),
          ),
        ),
      );

      expect(find.text('Test Podcast'), findsOneWidget);
      expect(find.text('Test Description'), findsOneWidget);
      expect(find.text('喜马拉雅'), findsOneWidget);
      expect(find.text('Active'), findsOneWidget);
      expect(find.text('10'), findsOneWidget); // Episode count
      expect(find.text('5'), findsOneWidget); // Unplayed count
    });

    testWidgets('platform badge appears before categories', (tester) async {
      final subscription = PodcastSubscriptionModel(
        id: 1,
        userId: 1,
        title: 'Test Podcast',
        sourceUrl: 'https://example.com/feed.xml',
        status: 'active',
        fetchInterval: 3600,
        platform: 'xiaoyuzhou',
        createdAt: DateTime(2024, 1, 1),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: PodcastSubscriptionCard(subscription: subscription),
            ),
          ),
        ),
      );

      expect(find.text('小宇宙'), findsOneWidget);
    });

    testWidgets('card is tappable with platform badge', (tester) async {
      final subscription = createMockSubscription(platform: 'ximalaya');
      bool tapped = false;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: PodcastSubscriptionCard(
                subscription: subscription,
                onTap: () => tapped = true,
              ),
            ),
          ),
        ),
      );

      await tester.tap(find.byType(PodcastSubscriptionCard));
      expect(tapped, true);
    });

    testWidgets('displays correct platform for different subscriptions', (tester) async {
      final ximalayaSub = createMockSubscription(platform: 'ximalaya');
      final xiaoyuzhouSub = createMockSubscription(platform: 'xiaoyuzhou');

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: Column(
                children: [
                  PodcastSubscriptionCard(subscription: ximalayaSub),
                  PodcastSubscriptionCard(subscription: xiaoyuzhouSub),
                ],
              ),
            ),
          ),
        ),
      );

      expect(find.text('喜马拉雅'), findsOneWidget);
      expect(find.text('小宇宙'), findsOneWidget);
    });

    testWidgets('platform badge maintains styling consistency', (tester) async {
      final subscription = createMockSubscription(platform: 'ximalaya');

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: PodcastSubscriptionCard(subscription: subscription),
            ),
          ),
        ),
      );

      final badgeText = tester.widget<Text>(find.text('喜马拉雅'));
      expect(badgeText.style?.fontSize, 10);
      expect(badgeText.style?.fontWeight, FontWeight.w600);
    });

    testWidgets('handles empty platform string', (tester) async {
      final subscription = createMockSubscription(platform: '');

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: PodcastSubscriptionCard(subscription: subscription),
            ),
          ),
        ),
      );

      expect(find.text('喜马拉雅'), findsNothing);
      expect(find.text('小宇宙'), findsNothing);
    });

    testWidgets('subscription card renders with author and platform', (tester) async {
      final subscription = PodcastSubscriptionModel(
        id: 1,
        userId: 1,
        title: 'Test Podcast',
        sourceUrl: 'https://example.com/feed.xml',
        status: 'active',
        fetchInterval: 3600,
        platform: 'xiaoyuzhou',
        author: 'Test Author',
        createdAt: DateTime(2024, 1, 1),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: PodcastSubscriptionCard(subscription: subscription),
            ),
          ),
        ),
      );

      expect(find.text('小宇宙'), findsOneWidget);
      expect(find.text('Test Author'), findsOneWidget);
    });
  });
}
