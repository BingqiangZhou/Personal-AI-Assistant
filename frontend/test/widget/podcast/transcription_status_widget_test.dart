import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/src/core/themes/app_theme.dart';
import 'package:personal_ai_assistant/src/features/podcast/data/models/podcast_transcription_model.dart';
import 'package:personal_ai_assistant/src/features/podcast/presentation/providers/transcription_providers.dart';
import 'package:personal_ai_assistant/src/features/podcast/presentation/widgets/transcription_status_widget.dart';

void main() {
  group('TranscriptionStatusWidget', () {
    late ProviderContainer container;

    setUp(() {
      container = ProviderContainer();
    });

    tearDown(() {
      container.dispose();
    });

    testWidgets('renders not started state when transcription is null', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptionStatusWidget(
                episodeId: 1,
                transcription: null,
              ),
            ),
          ),
        ),
      );

      expect(find.text('开始转录'), findsOneWidget);
      expect(find.text('为这个播客分集生成完整的文字转录\n支持多语言识别和高精度转录'), findsOneWidget);
      expect(find.byIcon(Icons.transcribe), findsOneWidget);
      expect(find.text('开始转录'), findsOneWidget);
    });

    testWidgets('renders pending state correctly', (WidgetTester tester) async {
      final pendingTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'pending',
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptionStatusWidget(
                episodeId: 1,
                transcription: pendingTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('等待开始'), findsOneWidget);
      expect(find.text('转录任务已添加到队列中\n将尽快开始处理'), findsOneWidget);
      expect(find.byIcon(Icons.pending_actions), findsOneWidget);
    });

    testWidgets('renders processing state with progress', (WidgetTester tester) async {
      final processingTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'transcribing',
        processingProgress: 0.65,
        wordCount: 1000,
        durationSeconds: 300,
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptionStatusWidget(
                episodeId: 1,
                transcription: processingTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('转录中...'), findsOneWidget);
      expect(find.text('65.0% 完成'), findsOneWidget);
      expect(find.text('预计字数: 1000'), findsOneWidget);
      expect(find.text('音频时长: 05:00'), findsOneWidget);
      expect(find.byIcon(Icons.autorenew), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      expect(find.byType(LinearProgressIndicator), findsOneWidget);
    });

    testWidgets('renders completed state with stats', (WidgetTester tester) async {
      final completedTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'completed',
        processingProgress: 1.0,
        wordCount: 5000,
        durationSeconds: 1800,
        aiConfidenceScore: 0.95,
        completedAt: DateTime.now(),
        createdAt: DateTime.now().subtract(const Duration(minutes: 30)),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptionStatusWidget(
                episodeId: 1,
                transcription: completedTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('转录完成'), findsOneWidget);
      expect(find.text('转录文本已生成完成\n可以开始阅读和搜索内容'), findsOneWidget);
      expect(find.text('5.0K'), findsOneWidget);
      expect(find.text('转录字数'), findsOneWidget);
      expect(find.text('30:00'), findsOneWidget);
      expect(find.text('音频时长'), findsOneWidget);
      expect(find.text('95%'), findsOneWidget);
      expect(find.text('准确率'), findsOneWidget);
      expect(find.byIcon(Icons.check_circle), findsOneWidget);
      expect(find.text('删除转录'), findsOneWidget);
      expect(find.text('查看转录'), findsOneWidget);
    });

    testWidgets('renders failed state with error message', (WidgetTester tester) async {
      final failedTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'failed',
        errorMessage: 'Audio format not supported',
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptionStatusWidget(
                episodeId: 1,
                transcription: failedTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('转录失败'), findsOneWidget);
      expect(find.text('错误信息'), findsOneWidget);
      expect(find.text('Audio format not supported'), findsOneWidget);
      expect(find.byIcon(Icons.error_outline), findsOneWidget);
      expect(find.text('重新尝试'), findsOneWidget);
    });

    testWidgets('renders different processing states correctly', (WidgetTester tester) async {
      final downloadingTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'downloading',
        processingProgress: 0.2,
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptionStatusWidget(
                episodeId: 1,
                transcription: downloadingTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('下载音频中...'), findsOneWidget);
      expect(find.text('20.0% 完成'), findsOneWidget);
    });

    testWidgets('handles missing confidence score in completed state', (WidgetTester tester) async {
      final completedTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'completed',
        processingProgress: 1.0,
        wordCount: 1000,
        durationSeconds: 300,
        completedAt: DateTime.now(),
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptionStatusWidget(
                episodeId: 1,
                transcription: completedTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('--'), findsOneWidget); // Should show -- for missing accuracy
    });

    testWidgets('handles missing stats in completed state', (WidgetTester tester) async {
      final completedTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'completed',
        processingProgress: 1.0,
        completedAt: DateTime.now(),
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptionStatusWidget(
                episodeId: 1,
                transcription: completedTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('转录完成'), findsOneWidget);
      // Should not show word count or duration if missing
      expect(find.text('预计字数:'), findsNothing);
      expect(find.text('音频时长:'), findsNothing);
    });

    testWidgets('displays completion time correctly', (WidgetTester tester) async {
      final completedAt = DateTime(2024, 1, 15, 10, 30);
      final completedTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'completed',
        processingProgress: 1.0,
        completedAt: completedAt,
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptionStatusWidget(
                episodeId: 1,
                transcription: completedTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('完成时间: 2024-01-15 10:30'), findsOneWidget);
    });

    testWidgets('shows correct progress for different processing stages', (WidgetTester tester) async {
      final stages = ['downloading', 'converting', 'transcribing', 'processing'];
      final statusTexts = ['下载音频中...', '转换格式中...', '转录中...', '处理文本中...'];

      for (var i = 0; i < stages.length; i++) {
        final transcription = PodcastTranscriptionResponse(
          id: 1,
          episodeId: 1,
          status: stages[i],
          processingProgress: 0.5,
          createdAt: DateTime.now(),
        );

        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              theme: AppTheme.lightTheme,
              home: Scaffold(
                body: TranscriptionStatusWidget(
                  episodeId: 1,
                  transcription: transcription,
                ),
              ),
            ),
          ),
        );

        expect(find.text(statusTexts[i]), findsOneWidget);
        expect(find.text('50.0% 完成'), findsOneWidget);

        await tester.pumpWidget(Container()); // Clean up for next iteration
      }
    });

    testWidgets('renders converting status correctly', (WidgetTester tester) async {
      final convertingTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'converting',
        processingProgress: 0.4,
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptionStatusWidget(
                episodeId: 1,
                transcription: convertingTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('转换格式中...'), findsOneWidget);
      expect(find.text('40.0% 完成'), findsOneWidget);
    });

    testWidgets('renders processing status correctly', (WidgetTester tester) async {
      final processingTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'processing',
        processingProgress: 0.8,
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptionStatusWidget(
                episodeId: 1,
                transcription: processingTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('处理文本中...'), findsOneWidget);
      expect(find.text('80.0% 完成'), findsOneWidget);
    });
  });
}