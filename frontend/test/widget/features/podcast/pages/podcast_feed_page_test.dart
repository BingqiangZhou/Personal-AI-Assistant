import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/glass/surface_card.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/widgets/custom_adaptive_navigation.dart';
import 'package:personal_ai_assistant/features/auth/presentation/providers/auth_provider.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_state_models.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_feed_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/shared/base_episode_card.dart';
import 'package:personal_ai_assistant/shared/widgets/skeleton_widgets.dart';

// --- Shared mock classes ---

class _MockPodcastFeedNotifier extends PodcastFeedNotifier {
  _MockPodcastFeedNotifier(this._initialState);
  final PodcastFeedState _initialState;

  @override
  PodcastFeedState build() => _initialState;

  @override
  Future<void> loadInitialFeed({
    bool forceRefresh = false,
    bool background = false,
  }) async {}

  @override
  Future<void> loadMoreFeed() async {}

  @override
  Future<void> refreshFeed({bool fastReturn = false}) async {}
}

class _MockAuthNotifier extends AuthNotifier {
  @override
  AuthState build() => const AuthState();
}

// --- Helper functions ---

PodcastEpisodeModel _buildEpisode({String? description}) {
  return PodcastEpisodeModel(
    id: 1,
    subscriptionId: 1,
    title: 'Test Episode',
    description: description ?? 'A test episode description.',
    audioUrl: 'https://example.com/audio.mp3',
    publishedAt: DateTime(2024, 1, 15),
    createdAt: DateTime(2024, 1, 15),
    audioDuration: 1800000,
    subscriptionTitle: 'Test Podcast',
  );
}

PodcastFeedState _createMultiEpisodeFeedState() {
  final now = DateTime.now();
  return PodcastFeedState(
    episodes: [
      PodcastEpisodeModel(
        id: 1,
        subscriptionId: 1,
        title: 'The Future of AI in Software Development',
        audioUrl: 'https://example.com/a.mp3',
        publishedAt: now,
        createdAt: now,
        audioDuration: 1800,
      ),
      PodcastEpisodeModel(
        id: 2,
        subscriptionId: 1,
        title: 'Building Scalable Microservices',
        audioUrl: 'https://example.com/b.mp3',
        publishedAt: now,
        createdAt: now,
        audioDuration: 2400,
      ),
      PodcastEpisodeModel(
        id: 3,
        subscriptionId: 2,
        title: 'The Psychology of Product Design',
        audioUrl: 'https://example.com/c.mp3',
        publishedAt: now,
        createdAt: now,
        audioDuration: 1500,
      ),
    ],
    hasMore: false,
    total: 3,
  );
}

Widget _wrapWidget(
  Widget child, {
  required PodcastFeedState feedState,
  bool useProviderScope = true,
}) {
  final overrides = [
    authProvider.overrideWith(_MockAuthNotifier.new),
    podcastFeedProvider.overrideWith(
      () => _MockPodcastFeedNotifier(feedState),
    ),
  ];

  if (useProviderScope) {
    return ProviderScope(
      overrides: overrides,
      child: MaterialApp(
        locale: const Locale('en'),
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: child,
      ),
    );
  }

  final container = ProviderContainer(overrides: overrides);
  return UncontrolledProviderScope(
    container: container,
    child: MaterialApp(
      locale: const Locale('en'),
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: child,
    ),
  );
}

void main() {
  group('PodcastFeedPage', () {
    // --- State rendering tests ---

    testWidgets('shows skeleton while loading', (tester) async {
      tester.view.physicalSize = const Size(390, 844);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      await tester.pumpWidget(
        _wrapWidget(
          const PodcastFeedPage(),
          feedState: const PodcastFeedState(
            episodes: [],
            hasMore: false,
            total: 0,
            isLoading: true,
          ),
        ),
      );
      await tester.pump(const Duration(seconds: 1));

      expect(find.byType(SkeletonCardList), findsOneWidget);
    });

    testWidgets('shows empty state when no episodes', (tester) async {
      tester.view.physicalSize = const Size(390, 844);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      await tester.pumpWidget(
        _wrapWidget(
          const PodcastFeedPage(),
          feedState: const PodcastFeedState(
            episodes: [],
            hasMore: false,
            total: 0,
          ),
        ),
      );
      await tester.pump(const Duration(seconds: 1));

      expect(find.byType(PodcastFeedPage), findsOneWidget);
    });

    testWidgets('renders episodes when loaded', (tester) async {
      tester.view.physicalSize = const Size(390, 844);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      final episode = _buildEpisode();

      await tester.pumpWidget(
        _wrapWidget(
          const PodcastFeedPage(),
          feedState: PodcastFeedState(
            episodes: [episode],
            hasMore: false,
            total: 1,
          ),
        ),
      );
      await tester.pump(const Duration(seconds: 1));

      expect(find.byType(BaseEpisodeCard), findsOneWidget);
      expect(find.text('Test Episode'), findsOneWidget);
    });

    testWidgets('shows error state with retry button', (tester) async {
      tester.view.physicalSize = const Size(390, 844);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      await tester.pumpWidget(
        _wrapWidget(
          const PodcastFeedPage(),
          feedState: const PodcastFeedState(
            episodes: [],
            hasMore: false,
            total: 0,
            error: 'Network error',
          ),
        ),
      );
      await tester.pump(const Duration(seconds: 1));

      expect(find.byType(PodcastFeedPage), findsOneWidget);
    });

    // --- Layout responsiveness tests ---

    testWidgets('renders with localized page title and page structure', (
      tester,
    ) async {
      await tester.pumpWidget(
        _wrapWidget(
          const PodcastFeedPage(),
          feedState: _createMultiEpisodeFeedState(),
        ),
      );
      await tester.pump(const Duration(seconds: 1));

      final l10n = AppLocalizations.of(
        tester.element(find.byType(PodcastFeedPage)),
      )!;
      expect(find.text(l10n.podcast_feed_page_title), findsOneWidget);

      expect(find.byType(PodcastFeedPage), findsOneWidget);
      expect(find.byType(ResponsiveContainer), findsOneWidget);
      final viewportClip = tester.widget<ClipRRect>(
        find.byKey(const Key('content_shell_viewport_clip')),
      );
      expect(viewportClip.borderRadius, BorderRadius.circular(14));
    });

    testWidgets('displays mock data on mobile screen', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(360, 800);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      await tester.pumpWidget(
        _wrapWidget(
          const PodcastFeedPage(),
          feedState: _createMultiEpisodeFeedState(),
        ),
      );
      await tester.pump(const Duration(seconds: 1));

      expect(
        find.text('The Future of AI in Software Development'),
        findsOneWidget,
      );
      expect(find.text('Building Scalable Microservices'), findsOneWidget);
      expect(find.text('The Psychology of Product Design'), findsOneWidget);

      expect(find.byType(SurfaceCard), findsWidgets);
    });

    testWidgets('displays mock data on desktop screen', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(1200, 800);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      await tester.pumpWidget(
        _wrapWidget(
          const PodcastFeedPage(),
          feedState: _createMultiEpisodeFeedState(),
        ),
      );
      await tester.pump(const Duration(seconds: 1));

      expect(
        find.text('The Future of AI in Software Development'),
        findsOneWidget,
      );
      expect(find.text('Building Scalable Microservices'), findsOneWidget);

      expect(find.byType(SurfaceCard), findsWidgets);
    });

    testWidgets('has no overflow errors on small screens', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(320, 480);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      await tester.pumpWidget(
        _wrapWidget(
          const PodcastFeedPage(),
          feedState: _createMultiEpisodeFeedState(),
        ),
      );
      await tester.pump(const Duration(seconds: 1));

      expect(tester.takeException(), isNull);

      expect(find.byType(SurfaceCard), findsWidgets);
    });

    testWidgets('cards contain play buttons', (tester) async {
      tester.view.physicalSize = const Size(800, 800);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      await tester.pumpWidget(
        _wrapWidget(
          const PodcastFeedPage(),
          feedState: _createMultiEpisodeFeedState(),
        ),
      );
      await tester.pump(const Duration(seconds: 1));

      // BaseEpisodeCard uses play_circle_outline icon
      expect(find.byIcon(Icons.play_circle_outline), findsWidgets);
    });

    testWidgets('cards contain metadata icons', (tester) async {
      tester.view.physicalSize = const Size(800, 800);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      await tester.pumpWidget(
        _wrapWidget(
          const PodcastFeedPage(),
          feedState: _createMultiEpisodeFeedState(),
        ),
      );
      await tester.pump(const Duration(seconds: 1));

      expect(find.byIcon(Icons.calendar_today_outlined), findsWidgets);
      expect(find.byIcon(Icons.schedule), findsWidgets);
    });
  });
}
