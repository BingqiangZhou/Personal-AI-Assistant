import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/audio_player_state_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_queue_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_bottom_player_widget.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_queue_sheet.dart';

void main() {
  group('PodcastBottomPlayerWidget playlist behavior', () {
    testWidgets('mini playlist button opens queue sheet', (tester) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          isExpanded: false,
        ),
      );
      final queueController = TestPodcastQueueController();

      await tester.pumpWidget(
        _createWidget(notifier: notifier, queueController: queueController),
      );
      await tester.pumpAndSettle();

      await tester.tap(
        find.byKey(const Key('podcast_bottom_player_mini_playlist')),
      );
      await tester.pumpAndSettle();

      expect(find.byType(PodcastQueueSheet), findsOneWidget);
      expect(queueController.loadQueueCalls, 1);
      await _closeQueueSheet(tester);
    });
  });

  group('PodcastBottomPlayerWidget interaction updates', () {
    testWidgets('mini info tap expands player and does not navigate', (
      tester,
    ) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          isExpanded: false,
        ),
      );
      final queueController = TestPodcastQueueController();

      await tester.pumpWidget(
        _createRouterWidget(
          notifier: notifier,
          queueController: queueController,
          initialLocation: '/',
        ),
      );
      await tester.pumpAndSettle();

      await tester.tap(
        find.byKey(const Key('podcast_bottom_player_mini_info')),
      );
      await tester.pumpAndSettle();

      expect(notifier.state.isExpanded, isTrue);
      expect(find.text('Episode Detail Page'), findsNothing);
      expect(find.byKey(const Key('podcast_bottom_player_expanded')), findsOne);
    });

    testWidgets('expanded title tap navigates to episode detail', (
      tester,
    ) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          isExpanded: true,
        ),
      );
      final queueController = TestPodcastQueueController();

      await tester.pumpWidget(
        _createRouterWidget(
          notifier: notifier,
          queueController: queueController,
          initialLocation: '/',
        ),
      );
      await tester.pumpAndSettle();

      await tester.tap(
        find.byKey(const Key('podcast_bottom_player_expanded_title')),
      );
      await tester.pumpAndSettle();

      expect(find.text('Episode Detail Page'), findsOneWidget);
    });

    testWidgets('expanded title tap no-ops when already on same detail route', (
      tester,
    ) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          isExpanded: true,
        ),
      );
      final queueController = TestPodcastQueueController();
      final observer = _TestNavigatorObserver();

      await tester.pumpWidget(
        _createRouterWidget(
          notifier: notifier,
          queueController: queueController,
          initialLocation: '/podcast/episodes/1/1',
          observers: [observer],
        ),
      );
      await tester.pumpAndSettle();

      final pushCountBeforeTap = observer.didPushCount;

      await tester.tap(
        find.byKey(const Key('podcast_bottom_player_expanded_title')),
      );
      await tester.pumpAndSettle();

      expect(observer.didPushCount, pushCountBeforeTap);
      expect(find.text('Episode Detail Page'), findsOneWidget);
    });

    testWidgets('expanded header removes close and keeps top playlist', (
      tester,
    ) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          isExpanded: true,
        ),
      );
      final queueController = TestPodcastQueueController();

      await tester.pumpWidget(
        _createWidget(notifier: notifier, queueController: queueController),
      );
      await tester.pumpAndSettle();

      expect(find.byIcon(Icons.close), findsNothing);
      expect(
        find.byKey(const Key('podcast_bottom_player_playlist')),
        findsOneWidget,
      );
    });

    testWidgets('expanded top playlist button opens queue sheet', (
      tester,
    ) async {
      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          isExpanded: true,
        ),
      );
      final queueController = TestPodcastQueueController();

      await tester.pumpWidget(
        _createWidget(notifier: notifier, queueController: queueController),
      );
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('podcast_bottom_player_playlist')));
      await tester.pumpAndSettle();

      expect(find.byType(PodcastQueueSheet), findsOneWidget);
      expect(queueController.loadQueueCalls, 1);
      await _closeQueueSheet(tester);
    });

    testWidgets(
      'expanded controls show speed and sleep, and now playing has no rate',
      (tester) async {
        final notifier = TestAudioPlayerNotifier(
          AudioPlayerState(
            currentEpisode: _testEpisode(),
            duration: 180000,
            isExpanded: true,
            playbackRate: 1.75,
          ),
        );
        final queueController = TestPodcastQueueController();

        await tester.pumpWidget(
          _createWidget(notifier: notifier, queueController: queueController),
        );
        await tester.pumpAndSettle();

        expect(find.byKey(const Key('podcast_bottom_player_speed')), findsOne);
        expect(find.text('1.75x'), findsOneWidget);
        expect(find.byKey(const Key('podcast_bottom_player_sleep')), findsOne);
        expect(
          find.byKey(const Key('podcast_bottom_player_settings')),
          findsNothing,
        );
        expect(find.text('Now Playing (1.75x)'), findsNothing);
      },
    );

    testWidgets('expanded play button stays horizontally centered', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(390, 844);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          isExpanded: true,
        ),
      );
      final queueController = TestPodcastQueueController();

      await tester.pumpWidget(
        _createWidget(notifier: notifier, queueController: queueController),
      );
      await tester.pumpAndSettle();

      final playCenter = tester.getCenter(
        find.byKey(const Key('podcast_bottom_player_play_pause')),
      );
      expect(playCenter.dx, closeTo(390 / 2, 1));
    });
  });

  group('PodcastBottomPlayerWidget mini styling', () {
    testWidgets(
      'mobile mini width matches feed card width and has rounded border',
      (tester) async {
        tester.view.physicalSize = const Size(390, 844);
        tester.view.devicePixelRatio = 1.0;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        final notifier = TestAudioPlayerNotifier(
          AudioPlayerState(
            currentEpisode: _testEpisode(),
            duration: 180000,
            isExpanded: false,
          ),
        );
        final queueController = TestPodcastQueueController();

        await tester.pumpWidget(
          _createWidget(notifier: notifier, queueController: queueController),
        );
        await tester.pumpAndSettle();

        final miniFinder = find.byKey(const Key('podcast_bottom_player_mini'));
        expect(miniFinder, findsOneWidget);

        final miniRect = tester.getRect(miniFinder);
        expect(miniRect.width, closeTo(350, 1));

        final miniMaterial = tester.widget<Material>(miniFinder);
        expect(miniMaterial.shape, isA<RoundedRectangleBorder>());
        final theme = Theme.of(tester.element(miniFinder));
        expect(miniMaterial.color, theme.colorScheme.surface);
        expect(miniMaterial.elevation, 0);
        final roundedShape = miniMaterial.shape! as RoundedRectangleBorder;
        final borderRadius = roundedShape.borderRadius.resolve(
          TextDirection.ltr,
        );
        expect(borderRadius.topLeft.x, 12);
        expect(borderRadius.topRight.x, 12);
        expect(borderRadius.bottomLeft.x, 12);
        expect(borderRadius.bottomRight.x, 12);
        expect(roundedShape.side.width, 1);
      },
    );

    testWidgets('desktop mini keeps wide layout width', (tester) async {
      tester.view.physicalSize = const Size(1200, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          duration: 180000,
          isExpanded: false,
        ),
      );
      final queueController = TestPodcastQueueController();

      await tester.pumpWidget(
        _createWidget(notifier: notifier, queueController: queueController),
      );
      await tester.pumpAndSettle();

      final miniRect = tester.getRect(
        find.byKey(const Key('podcast_bottom_player_mini')),
      );
      expect(miniRect.width, greaterThan(1100));
    });

    testWidgets('mini shows progress before time with state progress value', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(390, 844);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      final notifier = TestAudioPlayerNotifier(
        AudioPlayerState(
          currentEpisode: _testEpisode(),
          position: 45000,
          duration: 180000,
          isExpanded: false,
        ),
      );
      final queueController = TestPodcastQueueController();

      await tester.pumpWidget(
        _createWidget(notifier: notifier, queueController: queueController),
      );
      await tester.pumpAndSettle();

      final progressFinder = find.byKey(
        const Key('podcast_bottom_player_mini_progress'),
      );
      final timeFinder = find.byKey(
        const Key('podcast_bottom_player_mini_time'),
      );
      expect(progressFinder, findsOneWidget);
      expect(timeFinder, findsOneWidget);

      final progressWidget = tester.widget<LinearProgressIndicator>(
        progressFinder,
      );
      expect(progressWidget.value, closeTo(0.25, 0.0001));
      expect(find.text('00:45 / 03:00'), findsOneWidget);

      final progressRect = tester.getRect(progressFinder);
      final timeRect = tester.getRect(timeFinder);
      expect(progressRect.center.dx, lessThan(timeRect.center.dx));
    });
  });
}

Widget _createWidget({
  required TestAudioPlayerNotifier notifier,
  required TestPodcastQueueController queueController,
}) {
  return ProviderScope(
    overrides: [
      audioPlayerProvider.overrideWith(() => notifier),
      podcastQueueControllerProvider.overrideWith(() => queueController),
    ],
    child: MaterialApp(
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: const Scaffold(
        body: SizedBox.shrink(),
        bottomNavigationBar: PodcastBottomPlayerWidget(),
      ),
    ),
  );
}

Widget _createRouterWidget({
  required TestAudioPlayerNotifier notifier,
  required TestPodcastQueueController queueController,
  required String initialLocation,
  List<NavigatorObserver> observers = const [],
}) {
  final router = GoRouter(
    initialLocation: initialLocation,
    observers: observers,
    routes: [
      GoRoute(
        path: '/',
        builder: (context, state) => const Scaffold(
          body: Text('Home Page'),
          bottomNavigationBar: PodcastBottomPlayerWidget(),
        ),
      ),
      GoRoute(
        name: 'episodeDetail',
        path: '/podcast/episodes/:subscriptionId/:episodeId',
        builder: (context, state) => const Scaffold(
          body: Text('Episode Detail Page'),
          bottomNavigationBar: PodcastBottomPlayerWidget(),
        ),
      ),
    ],
  );

  return ProviderScope(
    overrides: [
      audioPlayerProvider.overrideWith(() => notifier),
      podcastQueueControllerProvider.overrideWith(() => queueController),
    ],
    child: MaterialApp.router(
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      routerConfig: router,
    ),
  );
}

PodcastEpisodeModel _testEpisode() {
  final now = DateTime.now();
  return PodcastEpisodeModel(
    id: 1,
    subscriptionId: 1,
    title: 'Test Episode',
    description: 'Description',
    audioUrl: 'https://example.com/audio.mp3',
    publishedAt: now,
    createdAt: now,
  );
}

class TestAudioPlayerNotifier extends AudioPlayerNotifier {
  TestAudioPlayerNotifier(this._initialState);

  final AudioPlayerState _initialState;

  @override
  AudioPlayerState build() {
    return _initialState;
  }

  @override
  void setExpanded(bool expanded) {
    state = state.copyWith(isExpanded: expanded);
  }
}

class TestPodcastQueueController extends PodcastQueueController {
  TestPodcastQueueController({this.loadDelay = Duration.zero});

  final Duration loadDelay;
  int loadQueueCalls = 0;

  @override
  Future<PodcastQueueModel> build() async {
    return PodcastQueueModel.empty();
  }

  @override
  Future<PodcastQueueModel> loadQueue() async {
    loadQueueCalls += 1;
    if (loadDelay > Duration.zero) {
      await Future<void>.delayed(loadDelay);
    }
    state = const AsyncValue.data(PodcastQueueModel());
    return PodcastQueueModel.empty();
  }
}

class _TestNavigatorObserver extends NavigatorObserver {
  int didPushCount = 0;

  @override
  void didPush(Route<dynamic> route, Route<dynamic>? previousRoute) {
    super.didPush(route, previousRoute);
    didPushCount += 1;
  }
}

Future<void> _closeQueueSheet(WidgetTester tester) async {
  final closeButton = find.descendant(
    of: find.byType(PodcastQueueSheet),
    matching: find.byIcon(Icons.close),
  );
  if (closeButton.evaluate().isNotEmpty) {
    await tester.tap(closeButton.first);
    await tester.pumpAndSettle();
  }
}
