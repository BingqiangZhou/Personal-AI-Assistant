import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_episode_detail_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';

void main() {
  group('PodcastEpisodeDetailPage Widget Tests', () {
    late PodcastEpisodeDetailResponse mockEpisodeDetail;

    setUp(() {
      final now = DateTime.now();

      // 创建测试用的分集详情响应（使用新的扁平结构）
      mockEpisodeDetail = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: '测试播客分集',
        description: '这是一个测试播客分集的详细描述，包含了丰富的内容和信息。',
        audioUrl: 'https://example.com/audio.mp3',
        audioDuration: 1800,
        publishedAt: now.subtract(const Duration(days: 1)),
        aiSummary: '这是一个AI生成的摘要，总结了播客的主要内容。',
        transcriptContent: '这是播客的完整文字稿内容...',
        season: 1,
        episodeNumber: 1,
        status: 'published',
        createdAt: now,
        updatedAt: now,
        subscription: {
          'id': 1,
          'title': '测试播客',
          'description': '测试播客描述',
        },
        relatedEpisodes: [],
      );
    });

    Widget createWidgetUnderTest({required int episodeId}) {
      return ProviderScope(
        overrides: [
          episodeDetailProvider.overrideWith((ref, episodeId) async {
            if (episodeId == 1) return mockEpisodeDetail;
            return null;
          }),
        ],
        child: MaterialApp(
          home: PodcastEpisodeDetailPage(episodeId: episodeId),
        ),
      );
    }

    testWidgets('页面应该正确加载并显示分集信息', (WidgetTester tester) async {
      // 构建Widget
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));

      // 等待异步加载完成
      await tester.pumpAndSettle();

      // 验证页面元素
      expect(find.text('测试播客分集'), findsOneWidget);
      expect(find.byType(SliverAppBar), findsOneWidget);
      expect(find.byType(TabBar), findsOneWidget);
      expect(find.byType(TabBarView), findsOneWidget);

      // 验证三个Tab都存在
      expect(find.text('Description'), findsOneWidget);
      expect(find.text('Summary'), findsOneWidget);
      expect(find.text('Transcript'), findsOneWidget);

      // 验证播放器控制区域
      expect(find.byType(SafeArea), findsOneWidget);
      expect(find.byType(Row), findsWidgets);
    });

    testWidgets('应该正确显示Description Tab内容', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // Description Tab应该是默认显示的
      expect(find.text('这是一个测试播客分集的详细描述'), findsOneWidget);
      expect(find.text('Description'), findsOneWidget);

      // 验证发布日期
      final yesterday = DateTime.now().subtract(const Duration(days: 1));
      final dateStr = '${yesterday.year}-${yesterday.month.toString().padLeft(2, '0')}-${yesterday.day.toString().padLeft(2, '0')}';
      expect(find.text(dateStr), findsOneWidget);
    });

    testWidgets('应该能够切换到Summary Tab', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 点击Summary Tab
      await tester.tap(find.text('Summary'));
      await tester.pumpAndSettle();

      // 验证Summary内容显示
      expect(find.text('这是一个AI生成的摘要'), findsOneWidget);
      expect(find.text('总结了播客的主要内容'), findsOneWidget);
    });

    testWidgets('应该能够切换到Transcript Tab', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 点击Transcript Tab
      await tester.tap(find.text('Transcript'));
      await tester.pumpAndSettle();

      // 验证Transcript内容显示
      expect(find.text('这是播客的完整文字稿内容'), findsOneWidget);
    });

    testWidgets('应该显示播放控制按钮', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证播放控制按钮存在
      expect(find.byIcon(Icons.skip_previous), findsOneWidget);
      expect(find.byIcon(Icons.fast_rewind), findsOneWidget);
      expect(find.byIcon(Icons.play_arrow), findsOneWidget);
      expect(find.byIcon(Icons.fast_forward), findsOneWidget);
      expect(find.byIcon(Icons.skip_next), findsOneWidget);

      // 验证倍速显示
      expect(find.text('1.0x'), findsOneWidget);

      // 验证收藏按钮
      expect(find.byIcon(Icons.favorite_border), findsOneWidget);
    });

    testWidgets('当分集不存在时应该显示错误页面', (WidgetTester tester) async {
      // 使用不存在的episodeId
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 999));
      await tester.pumpAndSettle();

      // 验证错误页面显示
      expect(find.text('Episode not found'), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsNothing);
      expect(find.text('Go Back'), findsOneWidget);
    });

    testWidgets('Tab切换应该平滑进行', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证默认在Description Tab
      expect(find.text('这是一个测试播客分集的详细描述'), findsOneWidget);

      // 从Description切换到Summary
      await tester.tap(find.text('Summary'));
      await tester.pumpAndSettle();
      expect(find.text('这是一个AI生成的摘要'), findsOneWidget);
      expect(find.text('这是一个测试播客分集的详细描述'), findsNothing);

      // 从Summary切换到Transcript
      await tester.tap(find.text('Transcript'));
      await tester.pumpAndSettle();
      expect(find.text('这是播客的完整文字稿内容'), findsOneWidget);
      expect(find.text('这是一个AI生成的摘要'), findsNothing);

      // 从Transcript切换回Description
      await tester.tap(find.text('Description'));
      await tester.pumpAndSettle();
      expect(find.text('这是一个测试播客分集的详细描述'), findsOneWidget);
      expect(find.text('这是播客的完整文字稿内容'), findsNothing);
    });

    testWidgets('应该正确显示分集元数据', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证分集标识
      expect(find.text('S01E01'), findsOneWidget);

      // 验证音频时长
      expect(find.text('30:00'), findsOneWidget); // 1800 seconds = 30:00

      // 验证发布日期图标
      expect(find.byIcon(Icons.calendar_today), findsOneWidget);
    });

    testWidgets('应该正确处理空数据', (WidgetTester tester) async {
      final now = DateTime.now();

      // 创建没有AI摘要和文字稿的分集（使用新的扁平结构）
      final detailMinimal = PodcastEpisodeDetailResponse(
        id: 4,
        subscriptionId: 1,
        title: '最小信息播客',
        description: '',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: now,
        status: 'published',
        createdAt: now,
        updatedAt: now,
        subscription: null,
        relatedEpisodes: [],
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            episodeDetailProvider.overrideWith((ref, episodeId) async {
              if (episodeId == 4) return detailMinimal;
              return null;
            }),
          ],
          child: MaterialApp(
            home: PodcastEpisodeDetailPage(episodeId: 4),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // 应该显示标题
      expect(find.text('最小信息播客'), findsOneWidget);

      // 切换到Summary Tab
      await tester.tap(find.text('Summary'));
      await tester.pumpAndSettle();

      // 验证无摘要消息
      expect(find.text('No summary available yet'), findsOneWidget);

      // 切换到Transcript Tab
      await tester.tap(find.text('Transcript'));
      await tester.pumpAndSettle();

      // 验证无文字稿消息
      expect(find.text('No transcript available'), findsOneWidget);
    });

    testWidgets('UI组件应该正确布局', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证主要UI组件存在
      expect(find.byType(Scaffold), findsOneWidget);
      expect(find.byType(CustomScrollView), findsOneWidget);
      expect(find.byType(SliverAppBar), findsOneWidget);
      expect(find.byType(TabBar), findsOneWidget);
      expect(find.byType(TabBarView), findsOneWidget);
      expect(find.byType(SafeArea), findsOneWidget);

      // 验证TabBar有3个Tab
      final tabBar = tester.widget<TabBar>(find.byType(TabBar));
      expect(tabBar.tabs.length, 3);

      // 验证TabBarView有3个Tab内容
      final tabBarView = tester.widget<TabBarView>(find.byType(TabBarView));
      expect(tabBarView.children.length, 3);
    });

    testWidgets('播放按钮应该可以点击', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证播放按钮存在并可点击
      final playButton = find.byIcon(Icons.play_arrow);
      expect(playButton, findsOneWidget);

      // 点击播放按钮（注意：实际的播放功能可能不会在测试中完全工作）
      await tester.tap(playButton);
      await tester.pump();

      // 按钮仍然存在
      expect(playButton, findsOneWidget);
    });

    testWidgets('应该能够点击倍速按钮', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证倍速显示
      expect(find.text('1.0x'), findsOneWidget);

      // 点击倍速显示区域
      await tester.tap(find.text('1.0x'));
      await tester.pump();

      // 验证倍速显示区域仍然存在
      expect(find.textContaining('x'), findsOneWidget);
    });
  });
}