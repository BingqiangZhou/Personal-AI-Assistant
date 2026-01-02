import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations_en.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_search_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_search_result_card.dart';

void main() {
  group('PodcastSearchResultCard 订阅状态显示测试', () {
    late PodcastSearchResult testPodcast;

    setUp(() {
      testPodcast = const PodcastSearchResult(
        collectionId: 12345,
        collectionName: '测试播客',
        artistName: '测试作者',
        artworkUrl100: 'https://example.com/artwork.jpg',
        feedUrl: 'https://example.com/feed.xml',
        trackCount: 100,
        primaryGenreName: '科技',
      );
    });

    Widget createTestWidget({
      required bool isSubscribed,
      ValueChanged<PodcastSearchResult>? onSubscribe,
    }) {
      return MaterialApp(
        localizationsDelegates: const [
          AppLocalizations.delegate,
        ],
        supportedLocales: AppLocalizations.supportedLocales,
        locale: const Locale('en'),
        home: Scaffold(
          body: PodcastSearchResultCard(
            result: testPodcast,
            isSubscribed: isSubscribed,
            onSubscribe: onSubscribe,
          ),
        ),
      );
    }

    testWidgets('未订阅状态 - 显示加号图标', (WidgetTester tester) async {
      await tester.pumpWidget(createTestWidget(isSubscribed: false));

      // 验证显示加号图标
      expect(find.byIcon(Icons.add_circle_outline), findsOneWidget);
      expect(find.byIcon(Icons.check_circle), findsNothing);

      // 验证IconButton存在
      expect(find.byType(IconButton), findsOneWidget);
    });

    testWidgets('已订阅状态 - 显示打勾图标', (WidgetTester tester) async {
      await tester.pumpWidget(createTestWidget(isSubscribed: true));

      // 验证显示打勾图标
      expect(find.byIcon(Icons.check_circle), findsOneWidget);
      expect(find.byIcon(Icons.add_circle_outline), findsNothing);

      // 验证没有IconButton（已订阅状态不可点击）
      expect(find.byType(IconButton), findsNothing);

      // 验证背景容器存在
      final containerFinder = find.descendant(
        of: find.byType(Tooltip),
        matching: find.byType(Container),
      );
      expect(containerFinder, findsOneWidget);

      // 验证容器有装饰（背景色）
      final Container container = tester.widget(containerFinder.first);
      expect(container.decoration, isNotNull);
      expect(container.decoration, isA<BoxDecoration>());
    });

    testWidgets('未订阅状态 - 点击触发订阅回调', (WidgetTester tester) async {
      bool subscribeCallbackCalled = false;
      PodcastSearchResult? subscribedPodcast;

      await tester.pumpWidget(createTestWidget(
        isSubscribed: false,
        onSubscribe: (podcast) {
          subscribeCallbackCalled = true;
          subscribedPodcast = podcast;
        },
      ));

      // 点击订阅按钮
      await tester.tap(find.byType(IconButton));
      await tester.pump();

      // 验证回调被触发
      expect(subscribeCallbackCalled, true);
      expect(subscribedPodcast, testPodcast);
    });

    testWidgets('显示播客基本信息', (WidgetTester tester) async {
      await tester.pumpWidget(createTestWidget(isSubscribed: false));

      // 验证播客标题
      expect(find.text('测试播客'), findsOneWidget);

      // 验证播客作者
      expect(find.text('测试作者'), findsOneWidget);

      // 验证分类
      expect(find.text('科技'), findsOneWidget);
    });

    testWidgets('Tooltip 提示正确显示', (WidgetTester tester) async {
      // 测试未订阅状态的Tooltip
      await tester.pumpWidget(createTestWidget(isSubscribed: false));

      final tooltipFinder = find.byType(Tooltip);
      expect(tooltipFinder, findsOneWidget);

      final Tooltip tooltip = tester.widget(tooltipFinder);
      expect(tooltip.message, contains('Subscribe')); // 英文locale

      // 测试已订阅状态的Tooltip
      await tester.pumpWidget(createTestWidget(isSubscribed: true));
      await tester.pump();

      final tooltipFinderSubscribed = find.byType(Tooltip);
      expect(tooltipFinderSubscribed, findsOneWidget);

      final Tooltip tooltipSubscribed = tester.widget(tooltipFinderSubscribed);
      expect(tooltipSubscribed.message, contains('Subscribed')); // 英文locale
    });

    testWidgets('已订阅图标使用主题色', (WidgetTester tester) async {
      await tester.pumpWidget(createTestWidget(isSubscribed: true));

      // 找到打勾图标
      final iconFinder = find.byIcon(Icons.check_circle);
      expect(iconFinder, findsOneWidget);

      // 获取图标widget
      final Icon icon = tester.widget(iconFinder);

      // 验证图标大小
      expect(icon.size, 32);

      // 验证图标颜色使用了主题色（不是null）
      expect(icon.color, isNotNull);
    });

    testWidgets('未订阅图标使用灰色', (WidgetTester tester) async {
      await tester.pumpWidget(createTestWidget(isSubscribed: false));

      // 找到加号图标
      final iconButtonFinder = find.byType(IconButton);
      expect(iconButtonFinder, findsOneWidget);

      // 获取IconButton widget
      final IconButton iconButton = tester.widget(iconButtonFinder);

      // 验证图标大小
      expect(iconButton.iconSize, 32);

      // 验证图标颜色设置了
      expect(iconButton.color, isNotNull);
    });
  });
}
