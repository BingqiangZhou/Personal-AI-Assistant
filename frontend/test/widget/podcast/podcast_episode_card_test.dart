import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:intl/intl.dart';

import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_episode_card.dart';

import '../../mocks/test_mocks.dart';

void main() {
  group('PodcastEpisodeCard Widget Tests', () {
    late PodcastEpisodeModel testEpisode;
    late MockAudioPlayerNotifier mockAudioPlayerNotifier;

    setUp(() {
      // Initialize date formatting for tests
      Intl.defaultLocale = 'en_US';

      testEpisode = PodcastEpisodeModel(
        id: 1,
        subscriptionId: 1,
        title: 'Introduction to AI',
        description: 'A comprehensive introduction to artificial intelligence',
        audioUrl: 'https://example.com/episode1.mp3',
        audioDuration: 3600, // 1 hour
        publishedAt: DateTime.now().subtract(const Duration(days: 7)),
        playCount: 5,
        lastPlayedAt: DateTime.now().subtract(const Duration(days: 1)),
        episodeNumber: 1,
        season: 1,
        explicit: false,
        status: 'published',
        createdAt: DateTime.now().subtract(const Duration(days: 10)),
      );

      mockAudioPlayerNotifier = MockAudioPlayerNotifier();
    });

    testWidgets('renders episode information correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              audioPlayerProvider.overrideWith((ref) => mockAudioPlayerNotifier),
            ],
          ),
          child: MaterialApp(
            home: Scaffold(
              body: PodcastEpisodeCard(
                episode: testEpisode,
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Check title
      expect(find.text('Introduction to AI'), findsOneWidget);

      // Check description
      expect(find.text('A comprehensive introduction to artificial intelligence'), findsOneWidget);

      // Check duration
      expect(find.text('1:00:00'), findsOneWidget);

      // Check play count
      expect(find.text('5 plays'), findsOneWidget);

      // Check episode identifier
      expect(find.text('S01E01'), findsOneWidget);

      // Check published date
      expect(find.textContaining(DateFormat('MMM d, yyyy').format(testEpisode.publishedAt)), findsOneWidget);
    });

    testWidgets('shows play button for unplayed episode', (WidgetTester tester) async {
      // Mock audio player state with no current episode
      when(mockAudioPlayerNotifier.state).thenReturn(const AudioPlayerState());

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              audioPlayerProvider.overrideWith((ref) => mockAudioPlayerNotifier),
            ],
          ),
          child: MaterialApp(
            home: Scaffold(
              body: PodcastEpisodeCard(
                episode: testEpisode,
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.byIcon(Icons.play_arrow), findsOneWidget);
    });

    testWidgets('shows pause button for currently playing episode', (WidgetTester tester) async {
      // Mock audio player state with current episode playing
      when(mockAudioPlayerNotifier.state).thenReturn(
        AudioPlayerState(
          currentEpisode: testEpisode,
          isPlaying: true,
        ),
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              audioPlayerProvider.overrideWith((ref) => mockAudioPlayerNotifier),
            ],
          ),
          child: MaterialApp(
            home: Scaffold(
              body: PodcastEpisodeCard(
                episode: testEpisode,
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.byIcon(Icons.pause), findsOneWidget);
    });

    testWidgets('shows resume button for paused episode', (WidgetTester tester) async {
      // Mock audio player state with current episode paused
      when(mockAudioPlayerNotifier.state).thenReturn(
        AudioPlayerState(
          currentEpisode: testEpisode,
          isPlaying: false,
        ),
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              audioPlayerProvider.overrideWith((ref) => mockAudioPlayerNotifier),
            ],
          ),
          child: MaterialApp(
            home: Scaffold(
              body: PodcastEpisodeCard(
                episode: testEpisode,
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.byIcon(Icons.play_arrow), findsOneWidget);
    });

    testWidgets('displays progress bar for partially played episode', (WidgetTester tester) async {
      final partiallyPlayedEpisode = testEpisode.copyWith(
        playbackPosition: 1800, // 30 minutes played
        audioDuration: 3600, // 1 hour total
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              audioPlayerProvider.overrideWith((ref) => mockAudioPlayerNotifier),
            ],
          ),
          child: MaterialApp(
            home: Scaffold(
              body: PodcastEpisodeCard(
                episode: partiallyPlayedEpisode,
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Check for progress bar
      expect(find.byType(LinearProgressIndicator), findsOneWidget);

      // Check time display
      expect(find.text('30:00'), findsOneWidget); // Current position
      expect(find.text('1:00:00'), findsOneWidget); // Total duration
    });

    testWidgets('displays AI summary badge when summary is available', (WidgetTester tester) async {
      final episodeWithSummary = testEpisode.copyWith(
        aiSummary: 'This episode covers the basics of AI...',
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              audioPlayerProvider.overrideWith((ref) => mockAudioPlayerNotifier),
            ],
          ),
          child: MaterialApp(
            home: Scaffold(
              body: PodcastEpisodeCard(
                episode: episodeWithSummary,
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('AI Summary'), findsOneWidget);
      expect(find.byIcon(Icons.summarize), findsOneWidget);
    });

    testWidgets('displays transcript badge when transcript is available', (WidgetTester tester) async {
      final episodeWithTranscript = testEpisode.copyWith(
        transcriptContent: 'Welcome to our podcast...',
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              audioPlayerProvider.overrideWith((ref) => mockAudioPlayerNotifier),
            ],
          ),
          child: MaterialApp(
            home: Scaffold(
              body: PodcastEpisodeCard(
                episode: episodeWithTranscript,
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('Transcript'), findsOneWidget);
      expect(find.byIcon(Icons.transcript), findsOneWidget);
    });

    testWidgets('displays explicit content badge', (WidgetTester tester) async {
      final explicitEpisode = testEpisode.copyWith(
        explicit: true,
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              audioPlayerProvider.overrideWith((ref) => mockAudioPlayerNotifier),
            ],
          ),
          child: MaterialApp(
            home: Scaffold(
              body: PodcastEpisodeCard(
                episode: explicitEpisode,
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('E'), findsOneWidget);
    });

    testWidgets('displays played badge for played episodes', (WidgetTester tester) async {
      final playedEpisode = testEpisode.copyWith(
        isPlayed: true,
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              audioPlayerProvider.overrideWith((ref) => mockAudioPlayerNotifier),
            ],
          ),
          child: MaterialApp(
            home: Scaffold(
              body: PodcastEpisodeCard(
                episode: playedEpisode,
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('Played'), findsOneWidget);
    });

    testWidgets('handles play button tap', (WidgetTester tester) async {
      bool wasPlayCalled = false;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: PodcastEpisodeCard(
              episode: testEpisode,
              onPlay: () => wasPlayCalled = true,
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Tap the play button
      await tester.tap(find.byType(IconButton.filled));
      await tester.pumpAndSettle();

      expect(wasPlayCalled, isTrue);
    });

    testWidgets('handles card tap for navigation', (WidgetTester tester) async {
      bool wasTapped = false;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: PodcastEpisodeCard(
              episode: testEpisode,
              onTap: () => wasTapped = true,
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Tap the card
      await tester.tap(find.byType(InkWell));
      await tester.pumpAndSettle();

      expect(wasTapped, isTrue);
    });

    testWidgets('formats duration correctly for different lengths', (WidgetTester tester) async {
      // Test less than 1 hour
      final shortEpisode = testEpisode.copyWith(
        audioDuration: 1800, // 30 minutes
        title: 'Short Episode',
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              audioPlayerProvider.overrideWith((ref) => mockAudioPlayerNotifier),
            ],
          ),
          child: MaterialApp(
            home: Scaffold(
              body: PodcastEpisodeCard(
                episode: shortEpisode,
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.text('30:00'), findsOneWidget);
      expect(find.text('Short Episode'), findsOneWidget);
    });

    testWidgets('displays episode without episode number', (WidgetTester tester) async {
      final episodeWithoutNumber = testEpisode.copyWith(
        episodeNumber: null,
        season: null,
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: ProviderContainer(
            overrides: [
              audioPlayerProvider.overrideWith((ref) => mockAudioPlayerNotifier),
            ],
          ),
          child: MaterialApp(
            home: Scaffold(
              body: PodcastEpisodeCard(
                episode: episodeWithoutNumber,
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Should not show episode identifier
      expect(find.text('S01E01'), findsNothing);
    });
  });
}