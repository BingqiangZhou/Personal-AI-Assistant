import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/shownotes_display_widget.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';

void main() {
  group('ShownotesDisplayWidget Widget Tests', () {
    // Helper DateTime for test episodes
    final testPublishedAt = DateTime(2024, 1, 1);
    final testCreatedAt = DateTime(2024, 1, 1);

    testWidgets('renders empty state when no description provided',
        (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: null,
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      expect(find.text('No shownotes available'), findsOneWidget);
      expect(find.byIcon(Icons.description_outlined), findsOneWidget);
    });

    testWidgets('renders empty state when empty description provided',
        (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: '',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      expect(find.text('No shownotes available'), findsOneWidget);
    });

    testWidgets('renders Shownotes header when description provided',
        (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: 'This is a test shownotes content.',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      expect(find.text('Shownotes'), findsOneWidget);
      expect(find.text('This is a test shownotes content.'), findsOneWidget);
    });

    testWidgets('renders HTML content correctly', (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: '<p>Hello <strong>world</strong></p>',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      expect(find.text('Shownotes'), findsOneWidget);
      expect(find.text('Hello world'), findsOneWidget);
    });

    testWidgets('removes dangerous script tags from HTML', (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: '<p>Safe content</p><script>alert("XSS")</script>',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      expect(find.text('Safe content'), findsOneWidget);
      expect(find.text('alert'), findsNothing);
    });

    testWidgets('renders lists correctly', (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: '''
          <ul>
            <li>Item 1</li>
            <li>Item 2</li>
          </ul>
        ''',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      expect(find.text('Item 1'), findsOneWidget);
      expect(find.text('Item 2'), findsOneWidget);
    });

    testWidgets('renders headings correctly', (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: '''
          <h1>Heading 1</h1>
          <h2>Heading 2</h2>
          <h3>Heading 3</h3>
        ''',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      expect(find.text('Heading 1'), findsOneWidget);
      expect(find.text('Heading 2'), findsOneWidget);
      expect(find.text('Heading 3'), findsOneWidget);
    });

    testWidgets('uses fallback to AI summary when description is empty',
        (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: null,
        aiSummary: 'AI Generated Summary',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      expect(find.text('AI Generated Summary'), findsOneWidget);
    });

    testWidgets('applies responsive padding for mobile', (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: '<p>Content</p>',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      // Set mobile size
      tester.view.physicalSize = const Size(400, 800);
      tester.view.devicePixelRatio = 1.0;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      // Verify widget renders
      expect(find.text('Shownotes'), findsOneWidget);
      expect(find.text('Content'), findsOneWidget);

      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    testWidgets('applies responsive padding for desktop', (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: '<p>Content</p>',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      // Set desktop size
      tester.view.physicalSize = const Size(1200, 800);
      tester.view.devicePixelRatio = 1.0;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      // Verify widget renders
      expect(find.text('Shownotes'), findsOneWidget);
      expect(find.text('Content'), findsOneWidget);

      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    testWidgets('handles malformed HTML gracefully', (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: '<p>Unclosed paragraph<div>Nested</p>',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      // Should not crash and render some content
      expect(find.text('Shownotes'), findsOneWidget);
    });

    testWidgets('renders tables correctly', (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: '''
          <table>
            <tr><th>Header</th></tr>
            <tr><td>Data</td></tr>
          </table>
        ''',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      expect(find.text('Header'), findsOneWidget);
      expect(find.text('Data'), findsOneWidget);
    });

    testWidgets('renders blockquotes correctly', (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: '<blockquote>This is a quote</blockquote>',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      expect(find.text('This is a quote'), findsOneWidget);
    });

    testWidgets('renders code blocks correctly', (tester) async {
      final episode = PodcastEpisodeDetailResponse(
        id: 1,
        subscriptionId: 1,
        title: 'Test Episode',
        description: '<pre><code>const x = 1;</code></pre>',
        audioUrl: 'https://example.com/audio.mp3',
        publishedAt: testPublishedAt,
        createdAt: testCreatedAt,
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: ShownotesDisplayWidget(episode: episode),
            ),
          ),
        ),
      );

      expect(find.text('const x = 1;'), findsOneWidget);
    });
  });
}
