import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/core/theme/app_theme.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_transcription_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/transcript_display_widget.dart';

void main() {
  group('TranscriptDisplayWidget', () {
    late ProviderContainer container;
    late PodcastTranscriptionResponse mockTranscription;

    setUp(() {
      mockTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'completed',
        transcriptContent: 'This is a sample transcript content.\nLine 2 of the transcript.',
        wordCount: 10,
        durationSeconds: 120,
        processingProgress: 1.0,
        createdAt: DateTime.now(),
        completedAt: DateTime.now(),
      );
    });

    testWidgets('renders empty state when no transcription provided', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptDisplayWidget(
                episodeId: 1,
                transcription: null,
              ),
            ),
          ),
        ),
      );

      expect(find.text('暂无转录内容'), findsOneWidget);
      expect(find.text('点击"开始转录"按钮生成转录文本'), findsOneWidget);
      expect(find.byIcon(Icons.article_outlined), findsOneWidget);
    });

    testWidgets('renders empty state when transcription content is empty', (WidgetTester tester) async {
      final emptyTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'completed',
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptDisplayWidget(
                episodeId: 1,
                transcription: emptyTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('暂无转录内容'), findsOneWidget);
    });

    testWidgets('renders transcript content when provided', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptDisplayWidget(
                episodeId: 1,
                transcription: mockTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('This is a sample transcript content.'), findsOneWidget);
      expect(find.text('Line 2 of the transcript.'), findsOneWidget);
      expect(find.byType(SelectableText), findsOneWidget);
    });

    testWidgets('search bar is rendered', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptDisplayWidget(
                episodeId: 1,
                transcription: mockTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.byType(TextField), findsOneWidget);
      expect(find.byIcon(Icons.search), findsOneWidget);
      expect(find.text('搜索转录内容...'), findsOneWidget);
    });

    testWidgets('search functionality works', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptDisplayWidget(
                episodeId: 1,
                transcription: mockTranscription,
              ),
            ),
          ),
        ),
      );

      // Type in search field
      await tester.enterText(find.byType(TextField), 'sample');
      await tester.pump();

      // Should show search results
      expect(find.text('匹配 1'), findsOneWidget);
      expect(find.text('This is a sample transcript content.'), findsOneWidget);

      // Clear search
      await tester.tap(find.byIcon(Icons.clear));
      await tester.pump();

      // Should return to full transcript view
      expect(find.text('This is a sample transcript content.'), findsOneWidget);
      expect(find.text('Line 2 of the transcript.'), findsOneWidget);
    });

    testWidgets('search shows no results when no match', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptDisplayWidget(
                episodeId: 1,
                transcription: mockTranscription,
              ),
            ),
          ),
        ),
      );

      // Search for something that doesn't exist
      await tester.enterText(find.byType(TextField), 'nonexistent');
      await tester.pump();

      expect(find.text('未找到匹配内容'), findsOneWidget);
      expect(find.byIcon(Icons.search_off), findsOneWidget);
    });

    testWidgets('onSearchChanged callback is called', (WidgetTester tester) async {
      String? lastSearchQuery;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptDisplayWidget(
                episodeId: 1,
                transcription: mockTranscription,
                onSearchChanged: (query) {
                  lastSearchQuery = query;
                },
              ),
            ),
          ),
        ),
      );

      // Type in search field
      await tester.enterText(find.byType(TextField), 'test');
      await tester.pump();

      expect(lastSearchQuery, equals('test'));

      // Clear search
      await tester.tap(find.byIcon(Icons.clear));
      await tester.pump();

      expect(lastSearchQuery, equals(''));
    });

    testWidgets('formatted transcript is displayed correctly', (WidgetTester tester) async {
      final formattedTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'completed',
        transcriptContent: '[主持人] 欢迎来到本期节目\n[嘉宾A] 很高兴来到这里\n00:30 重要内容',
        wordCount: 10,
        durationSeconds: 120,
        processingProgress: 1.0,
        createdAt: DateTime.now(),
        completedAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: FormattedTranscriptWidget(
                transcription: formattedTranscription,
              ),
            ),
          ),
        ),
      );

      // Should parse and display formatted segments
      expect(find.text('主持人'), findsOneWidget);
      expect(find.text('嘉宾A'), findsOneWidget);
      expect(find.text('00:30'), findsOneWidget);
      expect(find.text('欢迎来到本期节目'), findsOneWidget);
      expect(find.text('很高兴来到这里'), findsOneWidget);
      expect(find.text('重要内容'), findsOneWidget);
    });

    testWidgets('falls back to plain text display when parsing fails', (WidgetTester tester) async {
      final plainTextTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'completed',
        transcriptContent: 'This is plain text\nWithout any special format',
        wordCount: 10,
        durationSeconds: 120,
        processingProgress: 1.0,
        createdAt: DateTime.now(),
        completedAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: FormattedTranscriptWidget(
                transcription: plainTextTranscription,
              ),
            ),
          ),
        ),
      );

      // Should display as plain text
      expect(find.text('This is plain text'), findsOneWidget);
      expect(find.text('Without any special format'), findsOneWidget);
      expect(find.byType(TranscriptDisplayWidget), findsOneWidget);
    });

    testWidgets('handles speaker labels correctly', (WidgetTester tester) async {
      final speakerTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'completed',
        transcriptContent: 'Host: Welcome to the show\nGuest: Thanks for having me',
        wordCount: 10,
        durationSeconds: 120,
        processingProgress: 1.0,
        createdAt: DateTime.now(),
        completedAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: FormattedTranscriptWidget(
                transcription: speakerTranscription,
              ),
            ),
          ),
        ),
      );

      // Should parse speaker: text format
      expect(find.text('Host'), findsOneWidget);
      expect(find.text('Guest'), findsOneWidget);
      expect(find.text('Welcome to the show'), findsOneWidget);
      expect(find.text('Thanks for having me'), findsOneWidget);
    });
  });
}