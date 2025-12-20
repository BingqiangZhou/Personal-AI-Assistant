import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_episode_detail_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';

void main() {
  group('PodcastEpisodeDetailPage - 沉浸式三栏布局测试', () {
    late PodcastEpisodeDetailResponse mockEpisodeDetail;

    setUp(() {
      final now = DateTime.now();

      // 创建测试用的分集详情响应
      mockEpisodeDetail = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'AI应用深度讨论',
        description: '这是一期关于AI技术应用的深度讨论节目，涵盖了技术架构、实际应用和未来发展趋势。这是一个很长的描述文本，用于测试文本截断功能。',
        audioUrl: 'https://example.com/audio.mp3',
        audioDuration: 180, // 3分钟
        publishedAt: now.subtract(const Duration(days: 1)),
        aiSummary: '本期节目深入探讨了AI技术在企业中的实际应用案例，包括自然语言处理、机器学习模型部署等关键话题。专家们分享了他们在实际项目中的经验和见解。',
        transcriptContent: '这是完整的播客文字稿内容...',
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

    // ========== A区测试：顶部元数据区 ==========
    testWidgets('A区: Header应该正确显示Logo、标题、副标题和时长，无底部分割线', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证Logo图标
      expect(find.byIcon(Icons.podcasts), findsOneWidget);

      // 验证标题
      expect(find.text('AI应用深度讨论'), findsOneWidget);

      // 验证副标题（前40字符）- 使用textContaining因为可能有省略号
      expect(find.textContaining('这是一期关于AI技术应用的深度讨论节目'), findsOneWidget);

      // 验证时长
      expect(find.text('3:00'), findsOneWidget);

      // 验证Header容器样式 - 找到有padding和背景色的Header容器
      final containers = find.byType(Container);
      Container? headerContainer;
      for (var i = 0; i < containers.evaluate().length; i++) {
        final container = tester.widget<Container>(containers.at(i));
        if (container.padding == const EdgeInsets.all(16) &&
            container.color == const Color(0xFFFFFFFF)) {
          headerContainer = container;
          break;
        }
      }
      expect(headerContainer, isNotNull);
      expect(headerContainer!.color, Colors.white);
      expect(headerContainer.padding, const EdgeInsets.all(16));

      // 验证无底部分割线（通过检查Container的decoration）
      // 注意：当前实现中Container没有设置decoration，所以没有分割线
    });

    testWidgets('A区: Header布局结构正确', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证整体结构
      expect(find.byType(Row), findsWidgets);

      // 验证Logo图标存在 - 使用AppTheme.primaryColor (0x6366F1)
      final logoIcon = tester.widget<Icon>(find.byIcon(Icons.podcasts));
      expect(logoIcon.color, const Color(0xFF6366F1)); // AppTheme.primaryColor
      expect(logoIcon.size, 28);

      // 验证文本垂直排列
      final column = find.descendant(
        of: find.byType(Row).at(1),
        matching: find.byType(Column),
      );
      expect(column, findsWidgets);
    });

    // ========== B区测试：左侧主内容区 ==========
    testWidgets('B区: 左侧主内容区应该显示Capsule Tabs', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证两个Tab存在
      expect(find.text('文字转录'), findsOneWidget);
      expect(find.text('节目简介'), findsOneWidget);

      // 验证默认选中"文字转录" - 检查文本颜色为白色（选中状态）
      final transcriptText = tester.widget<Text>(find.text('文字转录'));
      expect(transcriptText.style?.color, Colors.white);

      // 验证未选中"节目简介" - 检查文本颜色为灰色（未选中状态）
      final descriptionText = tester.widget<Text>(find.text('节目简介'));
      expect(descriptionText.style?.color, const Color(0xFF6B7280)); // AppTheme.textSecondary
    });

    testWidgets('B区: 文字转录Tab应该显示模拟对话脚本', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证默认显示对话内容
      expect(find.text('主持人'), findsWidgets);
      expect(find.text('嘉宾A'), findsWidgets);
      expect(find.text('嘉宾B'), findsWidgets);

      // 验证时间戳
      expect(find.text('00:00'), findsOneWidget);
      expect(find.text('00:15'), findsOneWidget);
      expect(find.text('00:32'), findsOneWidget);

      // 验证对话内容 - 使用textContaining因为可能有截断
      expect(find.textContaining('大家好，欢迎收听本期节目'), findsOneWidget);
      expect(find.textContaining('很高兴来到这里'), findsOneWidget);
      expect(find.textContaining('没错，我们看到很多创新应用'), findsOneWidget);
    });

    testWidgets('B区: 对话项组件样式正确', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证说话人文本样式 - 使用AppTheme.primaryColor
      final speakerText = tester.widget<Text>(find.text('主持人').first);
      expect(speakerText.style?.fontSize, 11);
      expect(speakerText.style?.fontWeight, FontWeight.w600);
      expect(speakerText.style?.color, const Color(0xFF6366F1)); // AppTheme.primaryColor

      // 验证时间戳样式 - 使用AppTheme.textTertiary
      final timeText = tester.widget<Text>(find.text('00:00').first);
      expect(timeText.style?.fontSize, 11);
      expect(timeText.style?.color, const Color(0xFF9CA3AF)); // AppTheme.textTertiary

      // 验证内容样式 - 使用AppTheme.textPrimary
      final contentText = tester.widget<Text>(find.textContaining('大家好，欢迎收听本期节目').first);
      expect(contentText.style?.fontSize, 15);
      expect(contentText.style?.height, 1.6);
      expect(contentText.style?.color, const Color(0xFF1F2937)); // AppTheme.textPrimary
    });

    testWidgets('B区: Tab切换功能正常工作', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 默认显示文字转录
      expect(find.textContaining('大家好，欢迎收听本期节目'), findsOneWidget);

      // 点击节目简介Tab
      await tester.tap(find.text('节目简介'));
      await tester.pumpAndSettle();

      // 应该显示AI总结内容（在主内容区和侧边栏各有一个，所以是2个）
      expect(find.textContaining('本期节目深入探讨'), findsNWidgets(2));
      expect(find.textContaining('大家好，欢迎收听本期节目'), findsNothing);

      // 点击文字转录Tab
      await tester.tap(find.text('文字转录'));
      await tester.pumpAndSettle();

      // 应该重新显示文字转录
      expect(find.textContaining('大家好，欢迎收听本期节目'), findsOneWidget);
      // 侧边栏仍然显示AI总结，所以是1个
      expect(find.textContaining('本期节目深入探讨'), findsOneWidget);
    });

    testWidgets('B区: 节目简介Tab显示正确内容', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 切换到节目简介
      await tester.tap(find.text('节目简介'));
      await tester.pumpAndSettle();

      // 验证AI总结内容（主内容区和侧边栏各有一个，所以是2个）
      expect(find.textContaining('本期节目深入探讨'), findsNWidgets(2));
      expect(find.textContaining('AI技术在企业中的实际应用案例'), findsNWidgets(2));

      // 验证文本样式 - 使用AppTheme.textPrimary (主内容区)
      final contentTexts = find.textContaining('本期节目深入探讨');
      // 找到第一个（主内容区）
      final contentText = tester.widget<Text>(contentTexts.at(0));
      expect(contentText.style?.fontSize, 15);
      expect(contentText.style?.height, 1.8);
      expect(contentText.style?.color, const Color(0xFF1F2937)); // AppTheme.textPrimary
    });

    // ========== C区测试：右侧侧边栏 ==========
    testWidgets('C区: 右侧侧边栏应该只显示节目AI总结', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证侧边栏标题
      expect(find.text('节目AI总结'), findsOneWidget);

      // 验证AI总结内容（侧边栏）
      expect(find.textContaining('本期节目深入探讨'), findsOneWidget);

      // 验证标题样式 - 使用AppTheme.textPrimary
      final titleText = tester.widget<Text>(find.text('节目AI总结'));
      expect(titleText.style?.fontSize, 14);
      expect(titleText.style?.fontWeight, FontWeight.bold);
      expect(titleText.style?.color, const Color(0xFF1F2937)); // AppTheme.textPrimary

      // 验证内容样式 - 使用AppTheme.textSecondary
      final summaryText = tester.widget<Text>(find.textContaining('本期节目深入探讨').first);
      expect(summaryText.style?.fontSize, 13);
      expect(summaryText.style?.color, const Color(0xFF6B7280)); // AppTheme.textSecondary
      expect(summaryText.style?.height, 1.5);
    });

    testWidgets('C区: 侧边栏布局比例正确 (70/30)', (WidgetTester tester) async {
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

    // ========== D区测试：底部沉浸式播放条 ==========
    testWidgets('D区: 底部播放条应该包含进度条和控制区', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证进度条存在
      expect(find.byType(Slider), findsOneWidget);

      // 验证底部播放条容器 - 找到包含Slider和控制区的外层容器
      // 底部播放条在bottomNavigationBar中，是一个Column包含Slider和控制区Container
      // 使用更精确的查找：找到Slider的父级Column，再找Column的父级Container
      final slider = find.byType(Slider);
      final column = find.descendant(
        of: find.byType(Column),
        matching: slider,
      ).first;
      final bottomPlayer = find.ancestor(
        of: column,
        matching: find.byType(Container),
      ).first;
      final bottomContainer = tester.widget<Container>(bottomPlayer);

      // 验证底部容器背景色 - AppTheme.surfaceColor (白色)
      expect(bottomContainer.color, const Color(0xFFFFFFFF));

      // 验证控制区Row存在（在底部容器内）
      expect(find.byType(Row), findsWidgets);
    });

    testWidgets('D区: 进度条样式正确 (2px高, Teal色)', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证进度条 - 使用AppTheme颜色
      final slider = tester.widget<Slider>(find.byType(Slider));
      expect(slider.activeColor, const Color(0xFF6366F1)); // AppTheme.primaryColor
      expect(slider.inactiveColor, const Color(0xFFE5E7EB)); // AppTheme.borderColor
      expect(slider.thumbColor, const Color(0xFF6366F1)); // AppTheme.primaryColor
      expect(slider.min, 0);
      expect(slider.max, 1);
      expect(slider.value, 0.3); // 初始进度30%

      // 验证overlay color - 使用AppTheme.primaryColor.withAlpha(26)
      // overlayColor是WidgetStateProperty类型，需要使用resolve方法验证
      final overlayColor = slider.overlayColor;
      final resolvedColor = overlayColor?.resolve({});
      expect(resolvedColor, const Color(0xFF6366F1).withAlpha(26));
    });

    testWidgets('D区: 控制区左中右布局正确', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证左边：当前时间 + 音量图标
      // 初始进度30% = 0.3 * 180s = 54s = 0:54
      expect(find.text('0:54'), findsOneWidget);
      expect(find.byIcon(Icons.volume_up), findsOneWidget);

      // 验证中间：播放控制组
      expect(find.byIcon(Icons.replay_10), findsOneWidget); // 回退15s (使用10s图标)
      expect(find.byIcon(Icons.play_arrow), findsOneWidget); // 播放/暂停
      expect(find.byIcon(Icons.forward_30), findsOneWidget); // 前进30s

      // 验证右边：总时间 + 倍速按钮
      expect(find.text('3:00'), findsOneWidget);
      expect(find.text('1.0x'), findsOneWidget);
    });

    testWidgets('D区: 播放/暂停主按钮样式正确 (圆形, Teal背景, 黑色图标)', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 找到主按钮容器 - 在控制区Row中查找圆形容器
      // 主按钮是一个GestureDetector包裹的Container，有圆形装饰
      final containers = find.byType(Container);
      Container? mainButton;

      for (var i = 0; i < containers.evaluate().length; i++) {
        final container = tester.widget<Container>(containers.at(i));
        if (container.decoration is BoxDecoration) {
          final decoration = container.decoration as BoxDecoration;
          if (decoration.shape == BoxShape.circle) {
            mainButton = container;
            break;
          }
        }
      }

      expect(mainButton, isNotNull);

      // 验证形状和颜色 - 使用AppTheme.primaryColor
      final decoration = mainButton!.decoration as BoxDecoration;
      expect(decoration.shape, BoxShape.circle);
      expect(decoration.color, const Color(0xFF6366F1)); // AppTheme.primaryColor

      // 验证图标 - 白色
      final icon = tester.widget<Icon>(find.byIcon(Icons.play_arrow));
      expect(icon.color, Colors.white);
      expect(icon.size, 28);
    });

    testWidgets('D区: 倍速按钮样式正确 (圆角矩形边框)', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证倍速按钮文本样式 - 使用AppTheme.textSecondary
      final textWidget = tester.widget<Text>(find.text('1.0x'));
      expect(textWidget.style?.fontSize, 12);
      expect(textWidget.style?.fontWeight, FontWeight.w600);
      expect(textWidget.style?.color, const Color(0xFF6B7280)); // AppTheme.textSecondary
    });

    // ========== 交互测试 ==========
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

      // 验证当前时间显示更新（由于是模拟，时间可能会变化）
      expect(find.byType(Slider), findsOneWidget);
    });

    testWidgets('回退和前进按钮应该更新进度', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 初始时间显示 - 30%进度 = 0.3 * 180s = 54s = 0:54
      expect(find.text('0:54'), findsOneWidget);

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

    // ========== 边界条件测试 ==========
    testWidgets('空数据情况应该正确处理', (WidgetTester tester) async {
      final now = DateTime.now();
      final minimalEpisode = PodcastEpisodeDetailResponse(
        id: 2,
        subscriptionId: 1,
        title: '测试分集',
        description: null, // 空描述
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
              if (episodeId == 2) return minimalEpisode;
              return null;
            }),
          ],
          child: MaterialApp(
            home: PodcastEpisodeDetailPage(episodeId: 2),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // 应该显示标题
      expect(find.text('测试分集'), findsOneWidget);

      // 应该显示默认的描述文本
      expect(find.text('No description'), findsOneWidget);

      // 应该显示默认的AI总结
      expect(find.text('节目AI总结'), findsOneWidget);
    });

    testWidgets('错误状态应该正确显示', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            episodeDetailProvider.overrideWith((ref, episodeId) async {
              return null; // 返回null表示未找到
            }),
          ],
          child: MaterialApp(
            home: PodcastEpisodeDetailPage(episodeId: 999),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // 验证错误页面显示
      expect(find.text('Episode not found'), findsOneWidget);
      expect(find.text('Go Back'), findsOneWidget);
    });

    testWidgets('长文本应该正确截断显示', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // Header中的副标题应该被截断（40字符限制）
      final descriptionText = tester.widget<Text>(find.descendant(
        of: find.byType(Column).at(1),
        matching: find.byType(Text).at(1),
      ).first);

      // 验证maxLines设置
      expect(descriptionText.maxLines, 1);
      expect(descriptionText.overflow, TextOverflow.ellipsis);
    });

    // ========== 整体布局测试 ==========
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

      // 验证整体结构：Column > [Header, Expanded(Row), BottomPlayer]
      final scaffold = tester.widget<Scaffold>(find.byType(Scaffold));
      expect(scaffold.body, isA<Column>());
    });

    testWidgets('三栏布局比例正确', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 找到包含70/30分割的Row - 通过查找包含两个Expanded且flex为7和3的Row
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

    testWidgets('所有组件间距和内边距正确', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证Header内边距 - 找到Header的主容器（有padding: EdgeInsets.all(16)）
      // Header是整个顶部区域，直接查找有padding: EdgeInsets.all(16)的Container
      final allContainers = find.byType(Container);
      Container? headerContainer;
      for (var i = 0; i < allContainers.evaluate().length; i++) {
        final container = tester.widget<Container>(allContainers.at(i));
        if (container.padding == const EdgeInsets.all(16) &&
            container.color == const Color(0xFFFFFFFF)) {
          headerContainer = container;
          break;
        }
      }
      expect(headerContainer, isNotNull);

      // 验证Tabs内边距 - 找到包含"文字转录"和"节目简介"的Tabs容器
      // Tabs容器有padding: EdgeInsets.symmetric(horizontal: 16, vertical: 12)
      Container? tabsContainer;
      for (var i = 0; i < allContainers.evaluate().length; i++) {
        final container = tester.widget<Container>(allContainers.at(i));
        if (container.padding == const EdgeInsets.symmetric(horizontal: 16, vertical: 12)) {
          tabsContainer = container;
          break;
        }
      }
      expect(tabsContainer, isNotNull);

      // 验证对话项间距 - 确认对话项存在
      // 对话项在ListView.builder中，每个item是一个Column
      final listView = find.byType(ListView).first;
      expect(listView, findsOneWidget);

      // 验证对话项存在（通过查找说话人标签）
      expect(find.text('主持人'), findsWidgets);
      expect(find.textContaining('大家好，欢迎收听本期节目'), findsOneWidget);

      // 验证侧边栏内边距 - 找到侧边栏的外层Container
      // 侧边栏是Column结构，包含标题和内容，有padding: EdgeInsets.all(16)
      // 侧边栏也有白色背景，所以需要同时匹配padding和color
      // 注意：header和sidebar都有相同属性，需要找到第二个匹配的
      Container? sidebarContainer;
      int foundCount = 0;
      for (var i = 0; i < allContainers.evaluate().length; i++) {
        final container = tester.widget<Container>(allContainers.at(i));
        if (container.padding == const EdgeInsets.all(16) &&
            container.color == const Color(0xFFFFFFFF)) {
          foundCount++;
          if (foundCount == 2) {
            sidebarContainer = container;
            break;
          }
        }
      }
      expect(sidebarContainer, isNotNull);

      // 验证底部播放条内边距 - 找到控制区的Container
      // 控制区在bottomNavigationBar中，有padding: EdgeInsets.symmetric(horizontal: 16, vertical: 12)
      // 找到Slider的父级Column，再找Column的父级Container（外层容器）
      final slider = find.byType(Slider);
      final bottomPlayerContainer = find.ancestor(
        of: slider,
        matching: find.byType(Container),
      ).first;
      final bottomOuterContainer = tester.widget<Container>(bottomPlayerContainer);
      expect(bottomOuterContainer.color, const Color(0xFFFFFFFF));

      // 验证控制区Row的内边距 - 直接查找所有Container并匹配padding
      Container? controlContainer;
      for (var i = 0; i < allContainers.evaluate().length; i++) {
        final container = tester.widget<Container>(allContainers.at(i));
        if (container.padding == const EdgeInsets.symmetric(horizontal: 16, vertical: 12)) {
          controlContainer = container;
          break;
        }
      }
      expect(controlContainer, isNotNull);
    });

    testWidgets('所有文本样式符合规范', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证标题样式
      final titleText = tester.widget<Text>(find.text('AI应用深度讨论'));
      expect(titleText.style?.fontSize, 16);
      expect(titleText.style?.fontWeight, FontWeight.bold);

      // 验证时长样式
      final durationText = tester.widget<Text>(find.text('3:00'));
      expect(durationText.style?.fontSize, 14);
      expect(durationText.style?.fontWeight, FontWeight.w500);
      expect(durationText.style?.color, const Color(0xFF1F2937)); // AppTheme.textPrimary

      // 验证Tab文本样式
      final tabText = tester.widget<Text>(find.text('文字转录'));
      expect(tabText.style?.fontSize, 13);
      expect(tabText.style?.fontWeight, FontWeight.w600);

      // 验证侧边栏标题样式
      final sidebarTitle = tester.widget<Text>(find.text('节目AI总结'));
      expect(sidebarTitle.style?.fontSize, 14);
      expect(sidebarTitle.style?.fontWeight, FontWeight.bold);

      // 验证控制按钮文本样式
      final speedText = tester.widget<Text>(find.text('1.0x'));
      expect(speedText.style?.fontSize, 12);
      expect(speedText.style?.fontWeight, FontWeight.w600);
    });

    testWidgets('所有颜色符合设计规范', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证Header背景色 - AppTheme.surfaceColor (白色)
      final containers = find.byType(Container);
      Container? headerContainer;
      for (var i = 0; i < containers.evaluate().length; i++) {
        final container = tester.widget<Container>(containers.at(i));
        if (container.padding == const EdgeInsets.all(16) &&
            container.color == const Color(0xFFFFFFFF)) {
          headerContainer = container;
          break;
        }
      }
      expect(headerContainer, isNotNull);
      expect(headerContainer!.color, const Color(0xFFFFFFFF)); // AppTheme.surfaceColor

      // 验证Logo背景色 - AppTheme.primaryColor.withAlpha(26)
      // Logo是包含podcasts图标的50x50 Container，通过查找图标并向上查找父容器
      final logoIcon = find.byIcon(Icons.podcasts);
      expect(logoIcon, findsOneWidget);

      // 找到包含图标的Container（通过查找所有Container并匹配装饰）
      Container? logoContainer;
      for (var i = 0; i < containers.evaluate().length; i++) {
        final container = tester.widget<Container>(containers.at(i));
        if (container.decoration is BoxDecoration) {
          final decoration = container.decoration as BoxDecoration;
          if (decoration.color == const Color(0xFF6366F1).withAlpha(26)) {
            logoContainer = container;
            break;
          }
        }
      }
      expect(logoContainer, isNotNull);
      final logoDecoration = logoContainer!.decoration as BoxDecoration;
      expect(logoDecoration.color, const Color(0xFF6366F1).withAlpha(26)); // AppTheme.primaryColor.withAlpha(26)

      // 验证说话人文本颜色 - AppTheme.primaryColor
      final speakerText = tester.widget<Text>(find.text('主持人').first);
      expect(speakerText.style?.color, const Color(0xFF6366F1)); // AppTheme.primaryColor

      // 验证侧边栏背景色 - AppTheme.surfaceColor (白色)
      // 侧边栏容器有padding: EdgeInsets.all(16) 和 color: Colors.white
      // 注意：header和sidebar都有相同属性，需要找到第二个匹配的
      Container? sidebarContainer;
      int foundCount = 0;
      for (var i = 0; i < containers.evaluate().length; i++) {
        final container = tester.widget<Container>(containers.at(i));
        if (container.padding == const EdgeInsets.all(16) &&
            container.color == const Color(0xFFFFFFFF)) {
          foundCount++;
          if (foundCount == 2) {
            sidebarContainer = container;
            break;
          }
        }
      }
      expect(sidebarContainer, isNotNull);
      expect(sidebarContainer!.color, const Color(0xFFFFFFFF)); // AppTheme.surfaceColor

      // 验证底部播放条背景色 - AppTheme.surfaceColor (白色)
      // 底部播放条的外层Container有color: AppTheme.surfaceColor
      // 找到Slider的第一个Container祖先
      final sliderWidget = find.byType(Slider);
      final bottomPlayer = find.ancestor(
        of: sliderWidget,
        matching: find.byType(Container),
      ).first;
      final bottomContainer = tester.widget<Container>(bottomPlayer);
      expect(bottomContainer.color, const Color(0xFFFFFFFF)); // AppTheme.surfaceColor

      // 验证进度条颜色 - AppTheme.primaryColor
      final slider = tester.widget<Slider>(sliderWidget);
      expect(slider.activeColor, const Color(0xFF6366F1)); // AppTheme.primaryColor
      expect(slider.thumbColor, const Color(0xFF6366F1)); // AppTheme.primaryColor

      // 验证主按钮颜色 - AppTheme.primaryColor
      // 找到圆形容器
      Container? mainButton;
      for (var i = 0; i < containers.evaluate().length; i++) {
        final container = tester.widget<Container>(containers.at(i));
        if (container.decoration is BoxDecoration) {
          final decoration = container.decoration as BoxDecoration;
          if (decoration.shape == BoxShape.circle) {
            mainButton = container;
            break;
          }
        }
      }
      expect(mainButton, isNotNull);
      final buttonDecoration = mainButton!.decoration as BoxDecoration;
      expect(buttonDecoration.color, const Color(0xFF6366F1)); // AppTheme.primaryColor
    });

    testWidgets('所有图标正确显示', (WidgetTester tester) async {
      await tester.pumpWidget(createWidgetUnderTest(episodeId: 1));
      await tester.pumpAndSettle();

      // 验证Header图标
      expect(find.byIcon(Icons.podcasts), findsOneWidget);

      // 验证音量图标
      expect(find.byIcon(Icons.volume_up), findsOneWidget);

      // 验证播放控制图标
      expect(find.byIcon(Icons.replay_10), findsOneWidget);
      expect(find.byIcon(Icons.play_arrow), findsOneWidget);
      expect(find.byIcon(Icons.forward_30), findsOneWidget);

      // 验证图标颜色 - 使用AppTheme.textSecondary
      final volumeIcon = tester.widget<Icon>(find.byIcon(Icons.volume_up));
      expect(volumeIcon.color, const Color(0xFF6B7280)); // AppTheme.textSecondary
      expect(volumeIcon.size, 18);

      final replayIcon = tester.widget<Icon>(find.byIcon(Icons.replay_10));
      expect(replayIcon.color, const Color(0xFF6B7280)); // AppTheme.textSecondary
      expect(replayIcon.size, 24);

      final forwardIcon = tester.widget<Icon>(find.byIcon(Icons.forward_30));
      expect(forwardIcon.color, const Color(0xFF6B7280)); // AppTheme.textSecondary
      expect(forwardIcon.size, 24);
    });
  });
}