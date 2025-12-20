import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_episode_detail_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';

void main() {
  group('PodcastEpisodeDetailPage - 基本功能验证', () {
    late PodcastEpisodeDetailResponse mockEpisodeDetail;

    setUp(() {
      final now = DateTime.now();

      // 创建测试用的分集详情响应
      mockEpisodeDetail = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: '测试播客分集',
        description: '这是一个测试播客分集的详细描述。',
        audioUrl: 'https://example.com/audio.mp3',
        audioDuration: 180,
        publishedAt: now.subtract(const Duration(days: 1)),
        aiSummary: '这是一个AI生成的摘要。',
        transcriptContent: '这是播客的完整文字稿内容...',
        season: 1,
        episodeNumber: 1,
        status: 'published',
        createdAt: now,
        updatedAt: now,
        subscription: null,
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

    testWidgets('页面应该正确加载并显示基础信息', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证页面标题
      expect(find.text('测试播客分集'), findsOneWidget);

      // 验证Header组件存在
      expect(find.byIcon(Icons.podcasts), findsOneWidget);

      // 验证Tabs存在
      expect(find.text('文字转录'), findsOneWidget);
      expect(find.text('节目简介'), findsOneWidget);

      // 验证底部播放条存在
      expect(find.byType(Slider), findsOneWidget);
      expect(find.byIcon(Icons.play_arrow), findsOneWidget);

      // 验证控制按钮存在
      expect(find.byIcon(Icons.replay_10), findsOneWidget);
      expect(find.byIcon(Icons.forward_30), findsOneWidget);
      expect(find.text('1.0x'), findsOneWidget);
    });

    testWidgets('Tab切换功能应该正常工作', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 默认显示文字转录
      expect(find.text('文字转录'), findsOneWidget);

      // 点击节目简介Tab
      await tester.tap(find.text('节目简介'));
      await tester.pumpAndSettle();

      // 应该显示节目简介内容（AI总结）
      // 注意：AI总结会同时出现在主内容区和侧边栏，所以是2个
      expect(find.textContaining('这是一个AI生成的摘要'), findsNWidgets(2));

      // 点击文字转录Tab
      await tester.tap(find.text('文字转录'));
      await tester.pumpAndSettle();

      // 应该重新显示文字转录（对话项）
      // 注意：对话项是模拟数据，不在mock中，所以检查是否存在即可
      expect(find.text('主持人'), findsWidgets);
    });

    testWidgets('播放控制按钮应该正常工作', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 初始状态应该是播放图标
      expect(find.byIcon(Icons.play_arrow), findsOneWidget);

      // 点击播放按钮
      await tester.tap(find.byIcon(Icons.play_arrow));
      await tester.pump();

      // 应该变成暂停图标
      expect(find.byIcon(Icons.pause), findsOneWidget);

      // 再次点击应该变回播放
      await tester.tap(find.byIcon(Icons.pause));
      await tester.pump();
      expect(find.byIcon(Icons.play_arrow), findsOneWidget);
    });

    testWidgets('倍速按钮应该循环切换', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 初始倍速应该是1.0x
      expect(find.text('1.0x'), findsOneWidget);

      // 点击切换倍速
      await tester.tap(find.text('1.0x'));
      await tester.pump();
      expect(find.text('1.5x'), findsOneWidget);

      // 再次点击
      await tester.tap(find.text('1.5x'));
      await tester.pump();
      expect(find.text('2.0x'), findsOneWidget);

      // 第三次点击应该回到1.0x
      await tester.tap(find.text('2.0x'));
      await tester.pump();
      expect(find.text('1.0x'), findsOneWidget);
    });

    testWidgets('进度条应该可以拖动', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证Slider存在
      expect(find.byType(Slider), findsOneWidget);

      // 拖动进度条（模拟用户交互）
      await tester.drag(find.byType(Slider), const Offset(100, 0));
      await tester.pump();

      // 验证进度条仍然存在（不崩溃）
      expect(find.byType(Slider), findsOneWidget);
    });

    testWidgets('回退和前进按钮应该可以点击', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 点击前进30s
      await tester.tap(find.byIcon(Icons.forward_30));
      await tester.pump();

      // 点击回退15s
      await tester.tap(find.byIcon(Icons.replay_10));
      await tester.pump();

      // 验证按钮可以点击（不崩溃）
      expect(find.byIcon(Icons.forward_30), findsOneWidget);
      expect(find.byIcon(Icons.replay_10), findsOneWidget);
    });

    testWidgets('当分集不存在时应该显示错误页面', (WidgetTester tester) async {
      // 使用不存在的episodeId
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 999));
      await tester.pumpAndSettle();

      // 验证错误页面显示
      expect(find.text('Episode not found'), findsOneWidget);
      expect(find.text('Go Back'), findsOneWidget);
    });

    testWidgets('整体UI布局结构应该正确', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证主要UI组件存在
      expect(find.byType(Scaffold), findsOneWidget);
      expect(find.byType(Column), findsWidgets);
      expect(find.byType(Row), findsWidgets);
      expect(find.byType(Expanded), findsWidgets);

      // 验证底部播放条
      expect(find.byType(Slider), findsOneWidget);
    });

    testWidgets('右侧侧边栏应该显示AI总结', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证侧边栏标题
      expect(find.text('节目AI总结'), findsOneWidget);

      // 验证AI总结内容（侧边栏）
      expect(find.textContaining('这是一个AI生成的摘要'), findsWidgets);
    });

    testWidgets('对话项应该正确显示说话人、时间和内容', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证对话项存在
      expect(find.text('主持人'), findsWidgets);
      expect(find.text('嘉宾A'), findsWidgets);
      expect(find.text('嘉宾B'), findsWidgets);

      // 验证时间戳
      expect(find.text('00:00'), findsOneWidget);
      expect(find.text('00:15'), findsOneWidget);

      // 验证对话内容（模拟数据）
      expect(find.textContaining('大家好，欢迎收听本期节目'), findsOneWidget);
    });

    testWidgets('Header应该正确显示Logo、标题、副标题和时长', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证Logo图标
      expect(find.byIcon(Icons.podcasts), findsOneWidget);

      // 验证标题
      expect(find.text('测试播客分集'), findsOneWidget);

      // 验证时长
      expect(find.text('3:00'), findsOneWidget);
    });

    testWidgets('三栏布局比例应该正确', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 找到包含70/30分割的Row
      // 这个Row应该有2个Expanded子组件，flex分别为7和3
      final rows = find.byType(Row);
      Row? targetRow;

      // 遍历所有Row，找到包含两个Expanded且flex为7和3的那个
      for (var i = 0; i < rows.evaluate().length; i++) {
        final row = tester.widget<Row>(rows.at(i));
        if (row.children.length == 2 &&
            row.children[0] is Expanded &&
            row.children[1] is Expanded) {
          final left = row.children[0] as Expanded;
          final right = row.children[1] as Expanded;
          if (left.flex == 7 && right.flex == 3) {
            targetRow = row;
            break;
          }
        }
      }

      expect(targetRow, isNotNull, reason: 'Should find a Row with 70/30 split');
    });
  });
}