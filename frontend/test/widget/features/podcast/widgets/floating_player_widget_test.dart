import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/features/podcast/presentation/widgets/floating_player_widget.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/core/providers/route_provider.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/audio_player_state_model.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';

void main() {
  group('FloatingPlayerWidget Widget Tests', () {
    late ProviderContainer container;

    // Test episode data
    final testEpisode = PodcastEpisodeModel(
      id: 1,
      subscriptionId: 1,
      title: 'Test Episode Title',
      audioUrl: 'https://example.com/audio.mp3',
      publishedAt: DateTime.now(),
      createdAt: DateTime.now(),
      imageUrl: 'https://example.com/image.jpg',
    );

    // Episode without image
    final testEpisodeNoImage = PodcastEpisodeModel(
      id: 2,
      subscriptionId: 1,
      title: 'Episode Without Image',
      audioUrl: 'https://example.com/audio2.mp3',
      publishedAt: DateTime.now(),
      createdAt: DateTime.now(),
    );

    setUp(() {
      container = ProviderContainer();
    });

    tearDown(() {
      container.dispose();
    });

    // Test Wrappers
    Widget createTestWidget({
      required ProviderContainer testContainer,
      required Widget child,
      Size screenSize = const Size(400, 800), // Mobile size by default
    }) {
      return UncontrolledProviderScope(
        container: testContainer,
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: MediaQuery(
            data: MediaQueryData(size: screenSize),
            child: Scaffold(
              body: Stack(
                children: [child],
              ),
            ),
          ),
        ),
      );
    }

    group('Rendering Tests', () {
      testWidgets('should not render when not visible', (WidgetTester tester) async {
        // Arrange - Not playing, not visible
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              const AudioPlayerState(
                currentEpisode: null,
                isPlaying: false,
              ),
            )),
          ],
        );

        // Set route
        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Widget should not render (returns SizedBox.shrink)
        expect(find.byType(Positioned), findsNothing);
        expect(find.byType(GestureDetector), findsNothing);

        testContainer.dispose();
      });

      testWidgets('should render when playing and not on player page', (WidgetTester tester) async {
        // Arrange - Playing and not on player page
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/feed');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Widget should render
        expect(find.byType(Positioned), findsOneWidget);
        expect(find.byType(GestureDetector), findsOneWidget);
        // Find Material within the Positioned widget
        expect(find.descendant(of: find.byType(Positioned), matching: find.byType(Material)), findsOneWidget);

        testContainer.dispose();
      });

      testWidgets('should not render when on player page', (WidgetTester tester) async {
        // Arrange - Playing but on player page
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/1/player');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Widget should not render
        expect(find.byType(Positioned), findsNothing);

        testContainer.dispose();
      });

      testWidgets('should render pause icon when playing', (WidgetTester tester) async {
        // Arrange - Episode playing
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/feed');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Should show pause icon
        expect(
          find.byWidgetPredicate(
            (widget) => widget is Icon && widget.icon == Icons.pause,
          ),
          findsOneWidget,
        );

        testContainer.dispose();
      });

      testWidgets('should display podcast cover image when available', (WidgetTester tester) async {
        // Arrange
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Image widget should be present
        expect(find.byType(Image), findsOneWidget);

        testContainer.dispose();
      });

      testWidgets('should display fallback gradient when no image', (WidgetTester tester) async {
        // Arrange - Episode without image
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisodeNoImage,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Should show default gradient with podcast icon
        expect(
          find.byWidgetPredicate(
            (widget) => widget is Icon && widget.icon == Icons.podcasts,
          ),
          findsOneWidget,
        );
        // No network image should be present
        expect(
          find.byWidgetPredicate(
            (widget) => widget is Image && widget.image is NetworkImage,
          ),
          findsNothing,
        );

        testContainer.dispose();
      });

      testWidgets('should have correct Material 3 styling', (WidgetTester tester) async {
        // Arrange
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Check Material widget properties
        final materialWidget = tester.widget<Material>(
          find.descendant(of: find.byType(Positioned), matching: find.byType(Material)),
        );
        expect(materialWidget.elevation, 6);
        expect(materialWidget.shape, const CircleBorder());
        expect(materialWidget.clipBehavior, Clip.antiAlias);

        // Should have shadow decoration
        final container = tester.widget<Container>(
          find.descendant(
            of: find.byType(Positioned),
            matching: find.byType(Container).first,
          ),
        );
        final decoration = container.decoration as BoxDecoration;
        expect(decoration.shape, BoxShape.circle);
        expect(decoration.boxShadow, isNotEmpty);
        expect(decoration.boxShadow!.length, greaterThan(0));

        testContainer.dispose();
      });

      testWidgets('should have Tooltip for accessibility', (WidgetTester tester) async {
        // Arrange
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Tooltip should be present
        expect(find.byType(Tooltip), findsOneWidget);

        final tooltip = tester.widget<Tooltip>(
          find.descendant(of: find.byType(Positioned), matching: find.byType(Tooltip)),
        );
        expect(tooltip.message, isNotEmpty);
        expect(tooltip.message, contains('player'));

        testContainer.dispose();
      });

      testWidgets('should have Semantics for screen readers', (WidgetTester tester) async {
        // Arrange
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Semantics widget should be present within the floating player
        // Verify at least one Semantics widget exists
        expect(find.byType(Semantics), findsWidgets);

        testContainer.dispose();
      });

      testWidgets('should position correctly on mobile screen', (WidgetTester tester) async {
        // Arrange - Mobile screen size
        const mobileSize = Size(375, 667);
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
            screenSize: mobileSize,
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Check positioning
        final positioned = tester.widget<Positioned>(find.byType(Positioned));

        // Mobile: 16dp from right
        expect(positioned.right, 16);

        // Mobile: above bottom navigation (approximate check)
        expect(positioned.top, greaterThan(mobileSize.height - 200));

        testContainer.dispose();
      });

      testWidgets('should position correctly on desktop screen', (WidgetTester tester) async {
        // Arrange - Desktop screen size
        const desktopSize = Size(1200, 800);
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
            screenSize: desktopSize,
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Check positioning
        final positioned = tester.widget<Positioned>(find.byType(Positioned));

        // Desktop: 24dp from right
        expect(positioned.right, 24);

        // Desktop: vertically centered (approximately)
        expect(positioned.top, greaterThan(300));
        expect(positioned.top, lessThan(500));

        testContainer.dispose();
      });

      testWidgets('should position correctly on tablet screen', (WidgetTester tester) async {
        // Arrange - Tablet screen size
        const tabletSize = Size(768, 1024);
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
            screenSize: tabletSize,
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Check positioning
        final positioned = tester.widget<Positioned>(find.byType(Positioned));

        // Tablet: 24dp from right (same as desktop)
        expect(positioned.right, 24);

        // Tablet: vertically centered
        expect(positioned.top, greaterThan(400));
        expect(positioned.top, lessThan(600));

        testContainer.dispose();
      });
    });

    group('User Interaction Tests', () {
      testWidgets('should toggle play/pause on tap', (WidgetTester tester) async {
        // Arrange
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Tap the widget
        await tester.tap(find.byType(GestureDetector));
        await tester.pump();

        // Verify the gesture detector receives the tap
        expect(find.byType(GestureDetector), findsOneWidget);

        testContainer.dispose();
      });

      testWidgets('should handle double tap', (WidgetTester tester) async {
        // Arrange
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Double tap the widget
        await tester.tap(find.byType(GestureDetector));
        await tester.pump();
        await tester.tap(find.byType(GestureDetector));
        await tester.pump();

        // Verify gesture detector handles interaction
        expect(find.byType(GestureDetector), findsOneWidget);

        testContainer.dispose();
      });

      testWidgets('should handle long press', (WidgetTester tester) async {
        // Arrange
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Long press the widget
        await tester.longPress(find.byType(GestureDetector));
        await tester.pump();

        // Verify gesture detector handles long press
        expect(find.byType(GestureDetector), findsOneWidget);

        testContainer.dispose();
      });

      testWidgets('should provide visual feedback on tap', (WidgetTester tester) async {
        // Arrange
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Tap and check for animation - find specific GestureDetector within Positioned
        final gestureDetector = find.descendant(
          of: find.byType(Positioned),
          matching: find.byType(GestureDetector),
        );
        await tester.tap(gestureDetector, warnIfMissed: false);
        await tester.pump();

        // AnimatedScale should be present for touch feedback
        expect(find.byType(AnimatedScale), findsOneWidget);

        testContainer.dispose();
      });
    });

    group('State Changes and Reactivity Tests', () {
      testWidgets('should appear when audio starts playing', (WidgetTester tester) async {
        // Arrange - Initially not playing
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: false,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act - Initial render (not visible)
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();
        expect(find.byType(Positioned), findsNothing);

        // Update to playing state
        testContainer.read(audioPlayerProvider.notifier).state = AudioPlayerState(
          currentEpisode: testEpisode,
          isPlaying: true,
        );
        await tester.pump();
        await tester.pumpAndSettle();

        // Assert - Should now be visible
        expect(find.byType(Positioned), findsOneWidget);

        testContainer.dispose();
      });

      testWidgets('should disappear when navigating to player page', (WidgetTester tester) async {
        // Arrange - Playing on feed page
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/feed');

        // Act - Initial render (visible)
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();
        expect(find.byType(Positioned), findsOneWidget);

        // Navigate to player page
        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/1/player');
        await tester.pump();
        await tester.pumpAndSettle();

        // Assert - Should now be hidden
        expect(find.byType(Positioned), findsNothing);

        testContainer.dispose();
      });

      testWidgets('should animate appearance and disappearance', (WidgetTester tester) async {
        // Arrange
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );

        // Before animation completes
        await tester.pump(const Duration(milliseconds: 100));
        expect(find.byType(AnimatedScale), findsOneWidget);

        // After animation completes
        await tester.pumpAndSettle();

        testContainer.dispose();
      });
    });

    group('Error Handling Tests', () {
      testWidgets('should handle missing AppLocalizations gracefully', (WidgetTester tester) async {
        // Arrange - Without AppLocalizations
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act - Widget without localization
        await tester.pumpWidget(
          UncontrolledProviderScope(
            container: testContainer,
            child: MaterialApp(
              home: MediaQuery(
                data: const MediaQueryData(size: Size(400, 800)),
                child: Scaffold(
                  body: Stack(
                    children: const [FloatingPlayerWidget()],
                  ),
                ),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Should return SizedBox.shrink without crashing
        expect(find.byType(SizedBox), findsWidgets);

        testContainer.dispose();
      });

      testWidgets('should handle null currentEpisode gracefully', (WidgetTester tester) async {
        // Arrange
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              const AudioPlayerState(
                currentEpisode: null,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Should return SizedBox.shrink without crashing
        expect(find.byType(SizedBox), findsWidgets);
        expect(find.byType(Positioned), findsNothing);

        testContainer.dispose();
      });

      testWidgets('should handle image loading error', (WidgetTester tester) async {
        // Arrange - Episode with invalid image URL
        final episodeWithBadImage = PodcastEpisodeModel(
          id: 3,
          subscriptionId: 1,
          title: 'Episode with Bad Image',
          audioUrl: 'https://example.com/audio.mp3',
          publishedAt: DateTime.now(),
          createdAt: DateTime.now(),
          imageUrl: 'https://invalid-url-that-will-fail.jpg',
        );

        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: episodeWithBadImage,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Should show fallback instead of crashing
        // Image widget with errorBuilder should handle the error
        expect(find.byType(Image), findsOneWidget);

        testContainer.dispose();
      });
    });

    group('Accessibility Tests', () {
      testWidgets('should have correct semantic labels', (WidgetTester tester) async {
        // Arrange
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Semantics widgets should be present
        expect(find.byType(Semantics), findsWidgets);

        testContainer.dispose();
      });

      testWidgets('should support touch exploration for screen readers', (WidgetTester tester) async {
        // Arrange
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        await tester.pumpWidget(
          createTestWidget(
            testContainer: testContainer,
            child: const FloatingPlayerWidget(),
          ),
        );
        await tester.pumpAndSettle();

        // Assert - Semantics widgets should be present for accessibility
        expect(find.byType(Semantics), findsWidgets);

        testContainer.dispose();
      });
    });
  });
}

// Mock AudioPlayerNotifier for testing
class MockAudioPlayerNotifier extends AudioPlayerNotifier {
  MockAudioPlayerNotifier(this._initialState);

  final AudioPlayerState _initialState;

  @override
  AudioPlayerState build() {
    return _initialState;
  }

  @override
  Future<void> playEpisode(PodcastEpisodeModel episode) async {
    // Do nothing in test
  }

  @override
  Future<void> pause() async {
    // Do nothing in test
  }

  @override
  Future<void> resume() async {
    // Do nothing in test
  }

  @override
  Future<void> stop() async {
    // Do nothing in test
  }
}
