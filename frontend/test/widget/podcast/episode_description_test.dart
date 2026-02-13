import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/podcast/core/utils/episode_description_helper.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/feed_style_episode_card.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/simplified_episode_card.dart';

void main() {
  group('EpisodeDescriptionHelper', () {
    group('extractMainTopicsFromAiSummary', () {
      test('extracts main topics from Chinese AI summary', () {
        const aiSummary = '''
## 主要话题
- 探讨了AI技术在医疗领域的应用
- 分析了大型语言模型的发展趋势
- 讨论了数据隐私保护的重要性

## 关键见解
深入洞察内容...
''';

        final result = EpisodeDescriptionHelper.extractMainTopicsFromAiSummary(
          aiSummary,
        );
        expect(result, isNotNull);
        expect(result!.contains('AI'), isTrue);
        expect(result.contains('医疗'), isTrue);
      });

      test('extracts main topics from English AI summary', () {
        const aiSummary = '''
## Main Topics
- AI applications in healthcare
- Large language model trends
- Data privacy importance

## Key Insights
Deep insights...
''';

        final result = EpisodeDescriptionHelper.extractMainTopicsFromAiSummary(
          aiSummary,
        );
        expect(result, isNotNull);
        expect(result!.contains('AI'), isTrue);
        expect(result.contains('healthcare'), isTrue);
      });

      test('returns null when AI summary is empty', () {
        final result = EpisodeDescriptionHelper.extractMainTopicsFromAiSummary(
          null,
        );
        expect(result, isNull);
      });

      test('returns null when AI summary has no main topics section', () {
        const aiSummary = '''
## 关键见解
一些见解内容...

## 行动建议
一些建议...
''';

        final result = EpisodeDescriptionHelper.extractMainTopicsFromAiSummary(
          aiSummary,
        );
        expect(result, isNull);
      });
    });

    group('stripHtmlTags', () {
      test('removes HTML tags from content', () {
        const html =
            '<p>This is <strong>bold</strong> text with <a href="#">link</a>.</p>';
        final result = EpisodeDescriptionHelper.stripHtmlTags(html);
        expect(result, contains('This is'));
        expect(result, contains('bold'));
        expect(result, contains('text'));
        expect(result, isNot(contains('<')));
        expect(result, isNot(contains('>')));
      });

      test('handles empty input', () {
        final result = EpisodeDescriptionHelper.stripHtmlTags(null);
        expect(result, isEmpty);
      });

      test('handles plain text input', () {
        const plainText = 'This is plain text without HTML';
        final result = EpisodeDescriptionHelper.stripHtmlTags(plainText);
        expect(result, equals(plainText));
      });

      test('cleans up whitespace', () {
        const html = '<p>Paragraph 1</p>  <p>Paragraph 2</p>';
        final result = EpisodeDescriptionHelper.stripHtmlTags(html);
        expect(result, isNot(contains('  ')));
      });

      test('decodes HTML entities', () {
        const html = '<p>This &amp; that &nbsp; here &quot;quoted&quot;</p>';
        final result = EpisodeDescriptionHelper.stripHtmlTags(html);
        expect(result, contains('This & that'));
        expect(result, contains(' here '));
        expect(result, contains('"quoted"'));
        expect(result, isNot(contains('&amp;')));
        expect(result, isNot(contains('&nbsp;')));
        expect(result, isNot(contains('&quot;')));
      });

      test('decodes numeric HTML entities', () {
        const html = '<p>Price: &#36;100 or &#8364;50</p>';
        final result = EpisodeDescriptionHelper.stripHtmlTags(html);
        expect(result, contains('\$100'));
        expect(result, contains('€50'));
      });

      test('handles complex HTML with lists and formatting', () {
        const html = '''
          <div>
            <h1>Title</h1>
            <ul>
              <li>Item 1</li>
              <li>Item 2</li>
            </ul>
            <p>Paragraph with <strong>bold</strong> and <em>italic</em>.</p>
          </div>
        ''';
        final result = EpisodeDescriptionHelper.stripHtmlTags(html);
        expect(result, contains('Title'));
        expect(result, contains('Item 1'));
        expect(result, contains('Item 2'));
        expect(result, contains('bold'));
        expect(result, contains('italic'));
        expect(result, isNot(contains('<')));
        expect(result, isNot(contains('>')));
      });

      test('handles HTML with line breaks and paragraphs', () {
        const html = '<p>Line 1</p><p>Line 2</p><p>Line 3</p>';
        final result = EpisodeDescriptionHelper.stripHtmlTags(html);
        expect(result, contains('Line 1'));
        expect(result, contains('Line 2'));
        expect(result, contains('Line 3'));
        // Should have reasonable spacing, not too many newlines
        expect(result, isNot(contains('\n\n\n')));
      });

      test('handles HTML with special characters and symbols', () {
        const html =
            '<p>Copyright &copy; 2024 &mdash; All rights reserved &reg;</p>';
        final result = EpisodeDescriptionHelper.stripHtmlTags(html);
        expect(result, contains('©'));
        expect(result, contains('—'));
        expect(result, contains('®'));
        expect(result, isNot(contains('&copy;')));
        expect(result, isNot(contains('&mdash;')));
        expect(result, isNot(contains('&reg;')));
      });
    });

    group('getDisplayDescription', () {
      test('returns plain text from description regardless of AI summary', () {
        const aiSummary = '''
## 主要话题
- AI技术讨论
- 医疗应用分析

## 其他部分
其他内容...
''';
        const description = '<p>This is the original shownotes content.</p>';

        final result = EpisodeDescriptionHelper.getDisplayDescription(
          aiSummary: aiSummary,
          description: description,
        );

        // Should return description text, not AI summary
        expect(result, contains('shownotes'));
        expect(result, isNot(contains('AI')));
      });

      test('returns plain text description when no AI summary', () {
        const description =
            '<p>This is the <strong>original</strong> shownotes content.</p>';

        final result = EpisodeDescriptionHelper.getDisplayDescription(
          aiSummary: null,
          description: description,
        );

        expect(result, contains('original'));
        expect(result, contains('shownotes'));
        expect(result, isNot(contains('<')));
      });

      test('returns empty string when description is null', () {
        final result = EpisodeDescriptionHelper.getDisplayDescription(
          aiSummary: null,
          description: null,
        );

        expect(result, isEmpty);
      });

      test('returns empty string when description is empty', () {
        final result = EpisodeDescriptionHelper.getDisplayDescription(
          aiSummary: '',
          description: '',
        );

        expect(result, isEmpty);
      });
    });
  });

  group('FeedStyleEpisodeCard', () {
    testWidgets('displays plain shownotes regardless of AI summary', (
      tester,
    ) async {
      final episode = PodcastEpisodeModel(
        id: 1,
        subscriptionId: 1,
        subscriptionTitle: 'Test Podcast',
        title: 'Test Episode',
        description: '<p>Original shownotes content</p>',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
        aiSummary: '''
## 主要话题
- AI技术讨论
- 医疗应用分析
''',
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: Scaffold(body: FeedStyleEpisodeCard(episode: episode)),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Should display description text, not AI summary
      expect(find.textContaining('shownotes'), findsWidgets);
      expect(find.textContaining('Original'), findsWidgets);
    });

    testWidgets('displays plain shownotes without HTML tags', (tester) async {
      final episode = PodcastEpisodeModel(
        id: 1,
        subscriptionId: 1,
        subscriptionTitle: 'Test Podcast',
        title: 'Test Episode',
        description:
            '<p>This is the <strong>original</strong> shownotes content.</p>',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: Scaffold(body: FeedStyleEpisodeCard(episode: episode)),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Should display plain shownotes (without HTML tags)
      expect(find.textContaining('original'), findsWidgets);
      expect(find.textContaining('shownotes'), findsWidgets);
      // Should not contain HTML tags
      expect(find.textContaining('<'), findsNothing);
    });

    testWidgets('does not display description when null', (tester) async {
      final episode = PodcastEpisodeModel(
        id: 1,
        subscriptionId: 1,
        subscriptionTitle: 'Test Podcast',
        title: 'Test Episode',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: Scaffold(body: FeedStyleEpisodeCard(episode: episode)),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Should not have description text (only title and metadata)
      expect(find.byType(FeedStyleEpisodeCard), findsOneWidget);
    });
  });

  group('SimplifiedEpisodeCard', () {
    testWidgets('displays plain shownotes regardless of AI summary', (
      tester,
    ) async {
      final episode = PodcastEpisodeModel(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: '<p>Original shownotes content</p>',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
        aiSummary: '''
## 主要话题
- AI技术讨论
- 医疗应用分析
''',
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: Scaffold(body: SimplifiedEpisodeCard(episode: episode)),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Should display description text, not AI summary
      expect(find.textContaining('shownotes'), findsWidgets);
      expect(find.textContaining('Original'), findsWidgets);
    });

    testWidgets('displays plain shownotes without HTML tags', (tester) async {
      final episode = PodcastEpisodeModel(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description:
            '<p>This is the <strong>original</strong> shownotes content.</p>',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: Scaffold(body: SimplifiedEpisodeCard(episode: episode)),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Should display plain shownotes (without HTML tags)
      expect(find.textContaining('original'), findsWidgets);
      expect(find.textContaining('shownotes'), findsWidgets);
    });

    testWidgets('does not display description when null', (tester) async {
      final episode = PodcastEpisodeModel(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: Scaffold(body: SimplifiedEpisodeCard(episode: episode)),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Card should still render (title + metadata only)
      expect(find.byType(SimplifiedEpisodeCard), findsOneWidget);
    });
  });
}
