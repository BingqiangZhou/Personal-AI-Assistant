import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/src/core/themes/app_theme.dart';
import 'package:personal_ai_assistant/src/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/src/features/podcast/presentation/widgets/shownotes_display_widget.dart';

void main() {
  group('ShownotesDisplayWidget', () {
    late PodcastEpisodeDetailResponse mockEpisode;

    setUp(() {
      mockEpisode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: 'This is a test episode description',
        audioUrl: 'https://example.com/audio.mp3',
        audioDuration: 3600,
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
        aiSummary: 'This is the AI summary of the episode',
        season: 1,
        episodeNumber: 1,
      );
    });

    testWidgets('renders empty state when no content', (WidgetTester tester) async {
      final emptyEpisode = PodcastEpisodeDetailResponse(
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
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: emptyEpisode),
            ),
          ),
        ),
      );

      expect(find.text('暂无节目简介'), findsOneWidget);
      expect(find.byIcon(Icons.description_outlined), findsOneWidget);
    });

    testWidgets('renders AI summary when available', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: mockEpisode),
            ),
          ),
        ),
      );

      // Should prefer AI summary over description
      expect(find.text('This is the AI summary of the episode'), findsOneWidget);
      expect(find.text('This is a test episode description'), findsNothing);
      expect(find.text('节目简介'), findsOneWidget);
    });

    testWidgets('falls back to description when no AI summary', (WidgetTester tester) async {
      final episodeWithoutSummary = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: 'This is the description only episode',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episodeWithoutSummary),
            ),
          ),
        ),
      );

      expect(find.text('This is the description only episode'), findsOneWidget);
      expect(find.text('节目简介'), findsOneWidget);
    });

    testWidgets('renders episode metadata correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: mockEpisode),
            ),
          ),
        ),
      );

      // Check episode identifier
      expect(find.text('S01E01'), findsOneWidget);

      // Check published date
      expect(find.byIcon(Icons.calendar_today_outlined), findsOneWidget);
      expect(find.textContaining(RegExp(r'\d{4}年\d{2}月\d{2}日')), findsOneWidget);

      // Check duration
      expect(find.byIcon(Icons.schedule_outlined), findsOneWidget);
      expect(find.text('01:00:00'), findsOneWidget);
    });

    testWidgets('renders explicit content warning', (WidgetTester tester) async {
      final explicitEpisode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Explicit Episode',
        description: 'This episode has explicit content',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
        explicit: true,
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: explicitEpisode),
            ),
          ),
        ),
      );

      expect(find.text('包含成人内容'), findsOneWidget);
      expect(find.byIcon(Icons.warning_amber_outlined), findsOneWidget);
    });

    testWidgets('parses markdown-like formatting', (WidgetTester tester) async {
      final markdownEpisode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Markdown Episode',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
        aiSummary: '''# Main Title
## Subtitle
This is a paragraph.
- Item 1
- Item 2
1. Numbered item 1
2. Numbered item 2
Visit https://example.com for more info''',
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: markdownEpisode),
            ),
          ),
        ),
      );

      // Should render formatted content
      expect(find.text('Main Title'), findsOneWidget);
      expect(find.text('Subtitle'), findsOneWidget);
      expect(find.text('This is a paragraph.'), findsOneWidget);
      expect(find.text('Item 1'), findsOneWidget);
      expect(find.text('Item 2'), findsOneWidget);
      expect(find.text('Numbered item 1'), findsOneWidget);
      expect(find.text('Numbered item 2'), findsOneWidget);

      // URL should be clickable
      expect(find.text('https://example.com'), findsOneWidget);
    });

    testWidgets('renders links as clickable', (WidgetTester tester) async {
      final linkEpisode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Link Episode',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
        aiSummary: 'Check out this link: https://example.com/page',
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: linkEpisode),
            ),
          ),
        ),
      );

      final linkWidget = find.text('https://example.com/page');
      expect(linkWidget, findsOneWidget);

      // Should have underline decoration
      final textWidget = tester.widget<Text>(linkWidget);
      expect(textWidget.style?.decoration, contains(TextDecoration.underline));
    });

    testWidgets('handles timestamps in transcripts', (WidgetTester tester) async {
      final timestampEpisode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Timestamp Episode',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
        aiSummary: '''[00:00] Welcome to the show
[00:30] First topic
[01:45] Second topic''',
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: timestampEpisode),
            ),
          ),
        ),
      );

      expect(find.text('00:00'), findsOneWidget);
      expect(find.text('00:30'), findsOneWidget);
      expect(find.text('01:45'), findsOneWidget);
      expect(find.text('Welcome to the show'), findsOneWidget);
      expect(find.text('First topic'), findsOneWidget);
      expect(find.text('Second topic'), findsOneWidget);
    });

    testWidgets('uses metadata shownotes when available', (WidgetTester tester) async {
      final metadataEpisode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Metadata Episode',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
        metadata: {
          'shownotes': 'This is from metadata',
        },
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: metadataEpisode),
            ),
          ),
        ),
      );

      expect(find.text('This is from metadata'), findsOneWidget);
    });

    testWidgets('scrollable content for long shownotes', (WidgetTester tester) async {
      final longEpisode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Long Episode',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: DateTime.now(),
        createdAt: DateTime.now(),
        aiSummary: 'Paragraph 1\nParagraph 2\nParagraph 3\nParagraph 4\nParagraph 5\nParagraph 6\nParagraph 7\nParagraph 8\nParagraph 9\nParagraph 10',
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: SizedBox(
                height: 200,
                child: ShownotesDisplayWidget(episode: longEpisode),
              ),
            ),
          ),
        ),
      );

      // Should be scrollable
      expect(find.byType(SingleChildScrollView), findsOneWidget);
      expect(find.text('Paragraph 1'), findsOneWidget);
      expect(find.text('Paragraph 10'), findsOneWidget);
    });
  });
}