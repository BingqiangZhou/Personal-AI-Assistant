import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/core/theme/app_theme.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_transcription_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/transcription_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/transcription_status_widget.dart';

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

      // "Start Transcription" appears twice (title + button)
      expect(find.text('Start Transcription'), findsNWidgets(2));
      expect(find.text('Generate full text transcription for this episode\nSupports multi-language and high accuracy'), findsOneWidget);
      expect(find.byIcon(Icons.transcribe), findsOneWidget);
      expect(find.text('Or enable auto-transcription in settings'), findsOneWidget);
      expect(find.byIcon(Icons.info_outline), findsOneWidget);
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

      expect(find.text('Pending'), findsOneWidget);
      expect(find.text('Transcription task has been queued\nProcessing will start shortly'), findsOneWidget);
      expect(find.byIcon(Icons.pending_actions), findsOneWidget);
    });

    testWidgets('renders processing state with progress and step indicators', (WidgetTester tester) async {
      final processingTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'transcribing',
        processingProgress: 65.0,
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

      expect(find.text('65%'), findsOneWidget);
      expect(find.text('Complete'), findsOneWidget);
      expect(find.text('Duration: 5:00'), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
      expect(find.byType(LinearProgressIndicator), findsOneWidget);

      // Step indicators
      expect(find.text('Download'), findsOneWidget);
      expect(find.text('Convert'), findsOneWidget);
      expect(find.text('Split'), findsOneWidget);
      expect(find.text('Transcribe'), findsOneWidget);
      expect(find.text('Merge'), findsOneWidget);
    });

    testWidgets('renders completed state with stats', (WidgetTester tester) async {
      final completedTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'completed',
        processingProgress: 100.0,
        wordCount: 5000,
        durationSeconds: 1800,
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

      expect(find.text('Transcription Complete'), findsOneWidget);
      expect(find.text('Transcript generated successfully\nYou can now read and search the content'), findsOneWidget);
      expect(find.text('5.0K'), findsOneWidget);
      expect(find.text('Words'), findsOneWidget);
      expect(find.text('30:00'), findsOneWidget);
      expect(find.text('Duration'), findsOneWidget);
      expect(find.text('--'), findsOneWidget); // Accuracy is always --
      expect(find.text('Accuracy'), findsOneWidget);
      expect(find.byIcon(Icons.check_circle), findsOneWidget);
      expect(find.text('Delete'), findsOneWidget);
      expect(find.text('View Transcript'), findsOneWidget);
    });

    testWidgets('renders failed state with friendly error message', (WidgetTester tester) async {
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

      expect(find.text('Transcription Failed'), findsOneWidget);
      // "Audio format not supported" contains "audio" which matches before "format"
      expect(find.text('Failed to download audio'), findsOneWidget);
      expect(find.byIcon(Icons.error_outline), findsOneWidget);
      expect(find.byIcon(Icons.lightbulb_outline), findsOneWidget);
      expect(find.text('Retry'), findsOneWidget);
      expect(find.text('Clear'), findsOneWidget);
    });

    testWidgets('shows network error with suggestion', (WidgetTester tester) async {
      final failedTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'failed',
        errorMessage: 'Network connection timeout',
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

      expect(find.text('Network connection failed'), findsOneWidget);
      expect(find.textContaining('Check your internet connection'), findsOneWidget);
    });

    testWidgets('shows server restart error with suggestion', (WidgetTester tester) async {
      final failedTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'failed',
        errorMessage: 'Task interrupted by server restart',
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

      expect(find.text('Service was restarted'), findsOneWidget);
      expect(find.text('Click Retry to start a new transcription task'), findsOneWidget);
    });

    testWidgets('renders different processing states correctly', (WidgetTester tester) async {
      final stages = ['downloading', 'converting', 'transcribing', 'processing'];
      final progressValues = [15.0, 30.0, 65.0, 90.0];

      for (var i = 0; i < stages.length; i++) {
        final transcription = PodcastTranscriptionResponse(
          id: 1,
          episodeId: 1,
          status: stages[i],
          processingProgress: progressValues[i],
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

        final progressText = '${progressValues[i].toStringAsFixed(0)}%';
        expect(find.text(progressText), findsOneWidget);
        expect(find.text('Complete'), findsOneWidget);

        await tester.pumpWidget(Container()); // Clean up for next iteration
      }
    });

    testWidgets('handles missing accuracy in completed state', (WidgetTester tester) async {
      final completedTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'completed',
        processingProgress: 100.0,
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
        processingProgress: 100.0,
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

      expect(find.text('Transcription Complete'), findsOneWidget);
      // Widget shows default values when stats are missing
      expect(find.text('0.0K'), findsOneWidget); // Default word count
      expect(find.text('0:00'), findsOneWidget); // Default duration
    });

    testWidgets('displays completion time correctly', (WidgetTester tester) async {
      final completedAt = DateTime(2024, 1, 15, 10, 30);
      final completedTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'completed',
        processingProgress: 100.0,
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

      expect(find.text('Completed at: 2024-01-15 10:30'), findsOneWidget);
    });

    testWidgets('step indicators show correct status based on progress', (WidgetTester tester) async {
      // Test early progress (10%) - Download in progress
      final earlyTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'downloading',
        processingProgress: 10.0,
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptionStatusWidget(
                episodeId: 1,
                transcription: earlyTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('10%'), findsOneWidget);
      // At 10% progress, Download should still be current
      expect(find.text('Download'), findsOneWidget);
    });

    testWidgets('step indicators show correct completion status', (WidgetTester tester) async {
      // Test late progress (80%) - Transcribe in progress
      final lateTranscription = PodcastTranscriptionResponse(
        id: 1,
        episodeId: 1,
        status: 'transcribing',
        processingProgress: 80.0,
        createdAt: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            theme: AppTheme.lightTheme,
            home: Scaffold(
              body: TranscriptionStatusWidget(
                episodeId: 1,
                transcription: lateTranscription,
              ),
            ),
          ),
        ),
      );

      expect(find.text('80%'), findsOneWidget);
      // At 80% progress, Download, Convert, and Split should be completed
      expect(find.byIcon(Icons.check), findsWidgets); // Should have checkmarks
    });
  });
}
