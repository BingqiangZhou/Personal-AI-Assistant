import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';

import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_playback_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_player_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';

import '../../../mocks/test_mocks.dart';
import 'podcast_player_page_test.mocks.dart';

@GenerateMocks([PodcastRepository])
void main() {
  group('PodcastPlayerPage Widget Tests', () {
    late ProviderContainer container;
    late MockPodcastRepository mockRepository;

    setUp(() {
      mockRepository = MockPodcastRepository();
      container = ProviderContainer(
        overrides: [
          podcastRepositoryProvider.overrideWithValue(mockRepository),
        ],
      );
    });

    tearDown(() {
      container.dispose();
    });

    testWidgets('renders player with episode details', (WidgetTester tester) async {
      // Arrange
      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode: Understanding AI',
        description: 'A deep dive into artificial intelligence concepts and applications',
        publishedAt: DateTime.now().subtract(Duration(days: 1)),
        audioUrl: 'https://example.com/episode.mp3',
        audioDuration: 2700, // 45 minutes
        audioFileSize: 45000000,
        transcriptUrl: 'https://example.com/transcript.txt',
        transcriptContent: 'Full transcript content here...',
        aiSummary: 'This episode explores the fundamental concepts of AI, including machine learning, neural networks, and practical applications in various industries.',
        summaryVersion: '1.0',
        aiConfidenceScore: 0.95,
        playCount: 25,
        lastPlayedAt: DateTime.now().subtract(Duration(hours: 2)),
        season: 1,
        episodeNumber: 5,
        explicit: false,
        status: 'summarized',
        metadata: {
          'author': 'Dr. Jane Smith',
          'guests': ['Prof. John Doe'],
        },
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final playbackState = PodcastPlaybackState(
        id: 1,
        userId: 1,
        episodeId: 1,
        currentPosition: 900, // 15 minutes
        isPlaying: false,
        playbackRate: 1.0,
        lastUpdatedAt: DateTime.now(),
        playCount: 25,
      );

      when(mockRepository.getEpisodeDetail(1))
          .thenAnswer((_) async => episode);
      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => playbackState);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastPlayerPage(episodeId: '1'),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert
      expect(find.text('Test Episode: Understanding AI'), findsOneWidget);
      expect(find.text('S1 E5'), findsOneWidget);
      expect(find.text('45 min'), findsOneWidget);
      expect(find.byIcon(Icons.play_arrow), findsOneWidget);
      expect(find.text('15:00 / 45:00'), findsOneWidget);
    });

    testWidgets('displays AI summary when available', (WidgetTester tester) async {
      // Arrange
      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Episode with Summary',
        description: 'Description',
        publishedAt: DateTime.now(),
        audioUrl: 'https://example.com/episode.mp3',
        audioDuration: 1800,
        audioFileSize: 30000000,
        transcriptUrl: null,
        transcriptContent: null,
        aiSummary: 'This is an AI-generated summary of the episode, providing key insights and takeaways from the discussion.',
        summaryVersion: '2.0',
        aiConfidenceScore: 0.92,
        playCount: 0,
        lastPlayedAt: null,
        season: null,
        episodeNumber: null,
        explicit: false,
        status: 'summarized',
        metadata: {},
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final playbackState = PodcastPlaybackState(
        id: 1,
        userId: 1,
        episodeId: 1,
        currentPosition: 0,
        isPlaying: false,
        playbackRate: 1.0,
        lastUpdatedAt: DateTime.now(),
        playCount: 0,
      );

      when(mockRepository.getEpisodeDetail(1))
          .thenAnswer((_) async => episode);
      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => playbackState);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastPlayerPage(episodeId: '1'),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Scroll to summary section
      await tester.fling(
        find.byType(SingleChildScrollView),
        const Offset(0, -500),
        1000,
      );
      await tester.pumpAndSettle();

      // Assert
      expect(find.text('AI Summary'), findsOneWidget);
      expect(find.textContaining('This is an AI-generated summary'), findsOneWidget);
      expect(find.text('Confidence: 92%'), findsOneWidget);
    });

    testWidgets('shows transcript when available', (WidgetTester tester) async {
      // Arrange
      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Episode with Transcript',
        description: 'Description',
        publishedAt: DateTime.now(),
        audioUrl: 'https://example.com/episode.mp3',
        audioDuration: 1800,
        audioFileSize: 30000000,
        transcriptUrl: 'https://example.com/transcript.txt',
        transcriptContent: '[00:00] Host: Welcome to our show.\n[00:05] Guest: Thank you for having me.\n[00:10] Host: Today we\'ll discuss...',
        aiSummary: null,
        summaryVersion: null,
        aiConfidenceScore: null,
        playCount: 0,
        lastPlayedAt: null,
        season: null,
        episodeNumber: null,
        explicit: false,
        status: 'pending',
        metadata: {},
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final playbackState = PodcastPlaybackState(
        id: 1,
        userId: 1,
        episodeId: 1,
        currentPosition: 0,
        isPlaying: false,
        playbackRate: 1.0,
        lastUpdatedAt: DateTime.now(),
        playCount: 0,
      );

      when(mockRepository.getEpisodeDetail(1))
          .thenAnswer((_) async => episode);
      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => playbackState);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastPlayerPage(episodeId: '1'),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Tap on transcript tab
      await tester.tap(find.text('Transcript'));
      await tester.pumpAndSettle();

      // Assert
      expect(find.textContaining('[00:00] Host:'), findsOneWidget);
      expect(find.textContaining('[00:05] Guest:'), findsOneWidget);
    });

    testWidgets('play/pause functionality works', (WidgetTester tester) async {
      // Arrange
      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Play Test Episode',
        description: 'Testing play functionality',
        publishedAt: DateTime.now(),
        audioUrl: 'https://example.com/episode.mp3',
        audioDuration: 1800,
        audioFileSize: 30000000,
        transcriptUrl: null,
        transcriptContent: null,
        aiSummary: null,
        summaryVersion: null,
        aiConfidenceScore: null,
        playCount: 0,
        lastPlayedAt: null,
        season: null,
        episodeNumber: null,
        explicit: false,
        status: 'pending',
        metadata: {},
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final playbackState = PodcastPlaybackState(
        id: 1,
        userId: 1,
        episodeId: 1,
        currentPosition: 0,
        isPlaying: false,
        playbackRate: 1.0,
        lastUpdatedAt: DateTime.now(),
        playCount: 0,
      );

      when(mockRepository.getEpisodeDetail(1))
          .thenAnswer((_) async => episode);
      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => playbackState);

      // Mock update playback state
      when(mockRepository.updatePlaybackState(any, any))
          .thenAnswer((_) async => playbackState);

      // Act - Initial state
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastPlayerPage(episodeId: '1'),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Verify initial state - should show play button
      expect(find.byIcon(Icons.play_arrow), findsOneWidget);
      expect(find.byIcon(Icons.pause), findsNothing);

      // Tap play button
      await tester.tap(find.byIcon(Icons.play_arrow));
      await tester.pump();

      // Verify update was called
      verify(mockRepository.updatePlaybackState(
        1,
        argThat(predicate((state) => state.isPlaying == true))
      )).called(1);

      // Mock updated state with playing true
      final playingState = PodcastPlaybackState(
        id: 1,
        userId: 1,
        episodeId: 1,
        currentPosition: 0,
        isPlaying: true,
        playbackRate: 1.0,
        lastUpdatedAt: DateTime.now(),
        playCount: 1,
      );

      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => playingState);

      await tester.pumpAndSettle();

      // Now should show pause button
      expect(find.byIcon(Icons.pause), findsOneWidget);
      expect(find.byIcon(Icons.play_arrow), findsNothing);

      // Tap pause button
      await tester.tap(find.byIcon(Icons.pause));
      await tester.pump();

      // Verify update was called
      verify(mockRepository.updatePlaybackState(
        1,
        argThat(predicate((state) => state.isPlaying == false))
      )).called(1);
    });

    testWidgets('playback speed controls work', (WidgetTester tester) async {
      // Arrange
      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Speed Test Episode',
        description: 'Testing playback speed',
        publishedAt: DateTime.now(),
        audioUrl: 'https://example.com/episode.mp3',
        audioDuration: 1800,
        audioFileSize: 30000000,
        transcriptUrl: null,
        transcriptContent: null,
        aiSummary: null,
        summaryVersion: null,
        aiConfidenceScore: null,
        playCount: 0,
        lastPlayedAt: null,
        season: null,
        episodeNumber: null,
        explicit: false,
        status: 'pending',
        metadata: {},
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final playbackState = PodcastPlaybackState(
        id: 1,
        userId: 1,
        episodeId: 1,
        currentPosition: 300, // 5 minutes
        isPlaying: false,
        playbackRate: 1.0,
        lastUpdatedAt: DateTime.now(),
        playCount: 0,
      );

      when(mockRepository.getEpisodeDetail(1))
          .thenAnswer((_) async => episode);
      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => playbackState);

      when(mockRepository.updatePlaybackState(any, any))
          .thenAnswer((_) async => playbackState);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastPlayerPage(episodeId: '1'),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Tap on speed control button
      await tester.tap(find.text('1.0x'));
      await tester.pump();

      // Select 1.5x speed
      await tester.tap(find.text('1.5x'));
      await tester.pump();

      // Verify speed update
      verify(mockRepository.updatePlaybackState(
        1,
        argThat(predicate((state) => state.playbackRate == 1.5))
      )).called(1);
    });

    testWidgets('seek bar functionality works', (WidgetTester tester) async {
      // Arrange
      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Seek Test Episode',
        description: 'Testing seek functionality',
        publishedAt: DateTime.now(),
        audioUrl: 'https://example.com/episode.mp3',
        audioDuration: 1800, // 30 minutes
        audioFileSize: 30000000,
        transcriptUrl: null,
        transcriptContent: null,
        aiSummary: null,
        summaryVersion: null,
        aiConfidenceScore: null,
        playCount: 0,
        lastPlayedAt: null,
        season: null,
        episodeNumber: null,
        explicit: false,
        status: 'pending',
        metadata: {},
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final playbackState = PodcastPlaybackState(
        id: 1,
        userId: 1,
        episodeId: 1,
        currentPosition: 300, // 5 minutes
        isPlaying: false,
        playbackRate: 1.0,
        lastUpdatedAt: DateTime.now(),
        playCount: 0,
      );

      when(mockRepository.getEpisodeDetail(1))
          .thenAnswer((_) async => episode);
      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => playbackState);

      when(mockRepository.updatePlaybackState(any, any))
          .thenAnswer((_) async => playbackState);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastPlayerPage(episodeId: '1'),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Find and tap on the seek bar (at halfway point)
      final sliderFinder = find.byType(Slider);
      expect(sliderFinder, findsOneWidget);

      // Get slider dimensions
      final slider = tester.widget<Slider>(sliderFinder);
      final sliderRect = tester.getRect(sliderFinder);

      // Tap at 50% position
      await tester.tapAt(sliderRect.center);
      await tester.pump();

      // Verify seek was called (approximately 900 seconds = 15 minutes)
      verify(mockRepository.updatePlaybackState(
        1,
        argThat(predicate((state) =>
            state.currentPosition >= 800 && state.currentPosition <= 1000
        ))
      )).called(1);
    });

    testWidgets('skip forward/backward buttons work', (WidgetTester tester) async {
      // Arrange
      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Skip Test Episode',
        description: 'Testing skip functionality',
        publishedAt: DateTime.now(),
        audioUrl: 'https://example.com/episode.mp3',
        audioDuration: 3600, // 1 hour
        audioFileSize: 60000000,
        transcriptUrl: null,
        transcriptContent: null,
        aiSummary: null,
        summaryVersion: null,
        aiConfidenceScore: null,
        playCount: 0,
        lastPlayedAt: null,
        season: null,
        episodeNumber: null,
        explicit: false,
        status: 'pending',
        metadata: {},
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final playbackState = PodcastPlaybackState(
        id: 1,
        userId: 1,
        episodeId: 1,
        currentPosition: 900, // 15 minutes
        isPlaying: false,
        playbackRate: 1.0,
        lastUpdatedAt: DateTime.now(),
        playCount: 0,
      );

      when(mockRepository.getEpisodeDetail(1))
          .thenAnswer((_) async => episode);
      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => playbackState);

      when(mockRepository.updatePlaybackState(any, any))
          .thenAnswer((_) async => playbackState);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastPlayerPage(episodeId: '1'),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Test skip forward (30 seconds)
      await tester.tap(find.byIcon(Icons.forward_30));
      await tester.pump();

      verify(mockRepository.updatePlaybackState(
        1,
        argThat(predicate((state) => state.currentPosition == 930)) // 15 minutes + 30 seconds
      )).called(1);

      // Test skip backward (15 seconds)
      await tester.tap(find.byIcon(Icons.replay_15));
      await tester.pump();

      verify(mockRepository.updatePlaybackState(
        1,
        argThat(predicate((state) => state.currentPosition == 915)) // 930 - 15 seconds
      )).called(1);
    });

    testWidgets('shows loading state while fetching episode', (WidgetTester tester) async {
      // Arrange - Delay the response
      when(mockRepository.getEpisodeDetail(1))
          .thenAnswer((_) async {
        await Future.delayed(Duration(seconds: 1));
        return PodcastEpisode(
          id: 1,
          subscriptionId: 1,
          title: 'Delayed Episode',
          description: 'Loading...',
          publishedAt: DateTime.now(),
          audioUrl: 'https://example.com/episode.mp3',
          audioDuration: 1800,
          audioFileSize: 30000000,
          transcriptUrl: null,
          transcriptContent: null,
          aiSummary: null,
          summaryVersion: null,
          aiConfidenceScore: null,
          playCount: 0,
          lastPlayedAt: null,
          season: null,
          episodeNumber: null,
          explicit: false,
          status: 'pending',
          metadata: {},
          createdAt: DateTime.now(),
          updatedAt: DateTime.now(),
        );
      });

      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => PodcastPlaybackState(
            id: 1,
            userId: 1,
            episodeId: 1,
            currentPosition: 0,
            isPlaying: false,
            playbackRate: 1.0,
            lastUpdatedAt: DateTime.now(),
            playCount: 0,
          ));

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastPlayerPage(episodeId: '1'),
          ),
        ),
      );

      // Initially should show loading
      expect(find.byType(CircularProgressIndicator), findsOneWidget);

      // Wait for loading to complete
      await tester.pump(Duration(seconds: 1));
      await tester.pumpAndSettle();

      // Assert - Episode details should be loaded
      expect(find.text('Delayed Episode'), findsOneWidget);
    });

    testWidgets('handles error when loading episode fails', (WidgetTester tester) async {
      // Arrange
      when(mockRepository.getEpisodeDetail(1))
          .thenThrow(Exception('Failed to load episode'));

      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => PodcastPlaybackState(
            id: 1,
            userId: 1,
            episodeId: 1,
            currentPosition: 0,
            isPlaying: false,
            playbackRate: 1.0,
            lastUpdatedAt: DateTime.now(),
            playCount: 0,
          ));

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastPlayerPage(episodeId: '1'),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert - Should show error state
      expect(find.text('Failed to load episode'), findsOneWidget);
      expect(find.byIcon(Icons.error_outline), findsOneWidget);
      expect(find.text('Retry'), findsOneWidget);
    });

    testWidgets('shows explicit content warning', (WidgetTester tester) async {
      // Arrange
      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Explicit Episode',
        description: 'Contains explicit content',
        publishedAt: DateTime.now(),
        audioUrl: 'https://example.com/explicit.mp3',
        audioDuration: 1800,
        audioFileSize: 30000000,
        transcriptUrl: null,
        transcriptContent: null,
        aiSummary: null,
        summaryVersion: null,
        aiConfidenceScore: null,
        playCount: 0,
        lastPlayedAt: null,
        season: null,
        episodeNumber: null,
        explicit: true,
        status: 'pending',
        metadata: {},
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final playbackState = PodcastPlaybackState(
        id: 1,
        userId: 1,
        episodeId: 1,
        currentPosition: 0,
        isPlaying: false,
        playbackRate: 1.0,
        lastUpdatedAt: DateTime.now(),
        playCount: 0,
      );

      when(mockRepository.getEpisodeDetail(1))
          .thenAnswer((_) async => episode);
      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => playbackState);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastPlayerPage(episodeId: '1'),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert
      expect(find.byIcon(Icons.explicit), findsOneWidget);
      expect(find.text('Explicit'), findsOneWidget);
    });

    testWidgets('handles episode completion', (WidgetTester tester) async {
      // Arrange
      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Almost Complete Episode',
        description: 'Testing episode completion',
        publishedAt: DateTime.now(),
        audioUrl: 'https://example.com/episode.mp3',
        audioDuration: 1800, // 30 minutes
        audioFileSize: 30000000,
        transcriptUrl: null,
        transcriptContent: null,
        aiSummary: null,
        summaryVersion: null,
        aiConfidenceScore: null,
        playCount: 0,
        lastPlayedAt: null,
        season: null,
        episodeNumber: null,
        explicit: false,
        status: 'pending',
        metadata: {},
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final playbackState = PodcastPlaybackState(
        id: 1,
        userId: 1,
        episodeId: 1,
        currentPosition: 1750, // Almost at the end (29:10)
        isPlaying: true,
        playbackRate: 1.0,
        lastUpdatedAt: DateTime.now(),
        playCount: 0,
      );

      when(mockRepository.getEpisodeDetail(1))
          .thenAnswer((_) async => episode);
      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => playbackState);

      when(mockRepository.updatePlaybackState(any, any))
          .thenAnswer((_) async => playbackState);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastPlayerPage(episodeId: '1'),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Mock playing to completion
      final completedState = PodcastPlaybackState(
        id: 1,
        userId: 1,
        episodeId: 1,
        currentPosition: 1800, // At the end
        isPlaying: false,
        playbackRate: 1.0,
        lastUpdatedAt: DateTime.now(),
        playCount: 1,
      );

      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => completedState);

      await tester.pumpAndSettle();

      // Assert
      expect(find.text('Completed'), findsOneWidget);
      expect(find.byIcon(Icons.check_circle), findsOneWidget);
    });

    testWidgets('supports keyboard shortcuts', (WidgetTester tester) async {
      // Arrange
      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Keyboard Test Episode',
        description: 'Testing keyboard shortcuts',
        publishedAt: DateTime.now(),
        audioUrl: 'https://example.com/episode.mp3',
        audioDuration: 1800,
        audioFileSize: 30000000,
        transcriptUrl: null,
        transcriptContent: null,
        aiSummary: null,
        summaryVersion: null,
        aiConfidenceScore: null,
        playCount: 0,
        lastPlayedAt: null,
        season: null,
        episodeNumber: null,
        explicit: false,
        status: 'pending',
        metadata: {},
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final playbackState = PodcastPlaybackState(
        id: 1,
        userId: 1,
        episodeId: 1,
        currentPosition: 0,
        isPlaying: false,
        playbackRate: 1.0,
        lastUpdatedAt: DateTime.now(),
        playCount: 0,
      );

      when(mockRepository.getEpisodeDetail(1))
          .thenAnswer((_) async => episode);
      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => playbackState);

      when(mockRepository.updatePlaybackState(any, any))
          .thenAnswer((_) async => playbackState);

      // Act
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastPlayerPage(episodeId: '1'),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Test spacebar for play/pause
      await tester.sendKeyDownEvent(LogicalKeyboardKey.space);
      await tester.pump();
      await tester.sendKeyUpEvent(LogicalKeyboardKey.space);
      await tester.pump();

      // Verify play was triggered
      verify(mockRepository.updatePlaybackState(
        1,
        argThat(predicate((state) => state.isPlaying == true))
      )).called(1);

      // Test arrow keys for seeking
      await tester.sendKeyDownEvent(LogicalKeyboardKey.arrowRight);
      await tester.pump();
      await tester.sendKeyUpEvent(LogicalKeyboardKey.arrowRight);
      await tester.pump();

      // Verify forward seek
      verify(mockRepository.updatePlaybackState(
        1,
        argThat(predicate((state) => state.currentPosition == 15))
      )).called(1);
    });

    testWidgets('maintains playback state on app resume', (WidgetTester tester) async {
      // Arrange
      final episode = PodcastEpisode(
        id: 1,
        subscriptionId: 1,
        title: 'Resume Test Episode',
        description: 'Testing app resume',
        publishedAt: DateTime.now(),
        audioUrl: 'https://example.com/episode.mp3',
        audioDuration: 1800,
        audioFileSize: 30000000,
        transcriptUrl: null,
        transcriptContent: null,
        aiSummary: null,
        summaryVersion: null,
        aiConfidenceScore: null,
        playCount: 0,
        lastPlayedAt: null,
        season: null,
        episodeNumber: null,
        explicit: false,
        status: 'pending',
        metadata: {},
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final playbackState = PodcastPlaybackState(
        id: 1,
        userId: 1,
        episodeId: 1,
        currentPosition: 600, // 10 minutes
        isPlaying: true,
        playbackRate: 1.25,
        lastUpdatedAt: DateTime.now(),
        playCount: 1,
      );

      when(mockRepository.getEpisodeDetail(1))
          .thenAnswer((_) async => episode);
      when(mockRepository.getPlaybackState(1, 1))
          .thenAnswer((_) async => playbackState);

      // Act
      await tester.binding.defaultBinaryMessenger.handlePlatformMessage(
        'flutter/lifecycle',
        StringCodec().encodeMessage('AppLifecycleState.resumed'),
            (data) {},
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: MaterialApp(
            home: PodcastPlayerPage(episodeId: '1'),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Assert - State should be restored
      expect(find.text('10:00 / 30:00'), findsOneWidget);
      expect(find.text('1.25x'), findsOneWidget);
      expect(find.byIcon(Icons.pause), findsOneWidget); // Should be playing
    });
  });
}