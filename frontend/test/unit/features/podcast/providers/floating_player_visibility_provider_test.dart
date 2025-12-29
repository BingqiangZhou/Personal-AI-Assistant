import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/floating_player_visibility_provider.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/core/providers/route_provider.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/audio_player_state_model.dart';

void main() {
  group('FloatingPlayerVisibilityProvider Unit Tests', () {
    late ProviderContainer container;

    // Test episode data
    final testEpisode = PodcastEpisodeModel(
      id: 1,
      subscriptionId: 1,
      title: 'Test Episode',
      audioUrl: 'https://example.com/audio.mp3',
      publishedAt: DateTime.now(),
      createdAt: DateTime.now(),
      imageUrl: 'https://example.com/image.jpg',
    );

    setUp(() {
      container = ProviderContainer();
    });

    tearDown(() {
      container.dispose();
    });

    group('FloatingPlayerVisibilityState', () {
      test('should create default state with isVisible=false', () {
        // Act
        const state = FloatingPlayerVisibilityState();

        // Assert
        expect(state.isVisible, false);
        expect(state.isAnimating, false);
      });

      test('should create state with custom values', () {
        // Act
        const state = FloatingPlayerVisibilityState(
          isVisible: true,
          isAnimating: true,
        );

        // Assert
        expect(state.isVisible, true);
        expect(state.isAnimating, true);
      });

      test('copyWith should update only specified fields', () {
        // Arrange
        const initialState = FloatingPlayerVisibilityState(
          isVisible: false,
          isAnimating: false,
        );

        // Act - Update only isVisible
        final newState = initialState.copyWith(isVisible: true);

        // Assert
        expect(newState.isVisible, true);
        expect(newState.isAnimating, false);
      });

      test('copyWith should preserve unspecified fields', () {
        // Arrange
        const initialState = FloatingPlayerVisibilityState(
          isVisible: true,
          isAnimating: true,
        );

        // Act - Update only isAnimating
        final newState = initialState.copyWith(isAnimating: false);

        // Assert
        expect(newState.isVisible, true);
        expect(newState.isAnimating, false);
      });

      test('should implement equality correctly', () {
        // Arrange
        const state1 = FloatingPlayerVisibilityState(
          isVisible: true,
          isAnimating: false,
        );
        const state2 = FloatingPlayerVisibilityState(
          isVisible: true,
          isAnimating: false,
        );
        const state3 = FloatingPlayerVisibilityState(
          isVisible: false,
          isAnimating: false,
        );

        // Assert
        expect(state1, equals(state2));
        expect(state1, isNot(equals(state3)));
      });

      test('should implement hashCode correctly', () {
        // Arrange
        const state1 = FloatingPlayerVisibilityState(
          isVisible: true,
          isAnimating: false,
        );
        const state2 = FloatingPlayerVisibilityState(
          isVisible: true,
          isAnimating: false,
        );

        // Assert
        expect(state1.hashCode, equals(state2.hashCode));
      });
    });

    group('FloatingPlayerVisibilityNotifier - Visibility Logic', () {
      test('should be invisible when no episode is loaded', () {
        // Arrange - Override with no episode and not playing
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
        final visibilityState = testContainer.read(floatingPlayerVisibilityProvider);

        // Assert
        expect(visibilityState.isVisible, false);

        testContainer.dispose();
      });

      test('should be invisible when episode is loaded but not playing', () {
        // Arrange - Override with episode but not playing
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

        // Set route
        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        final visibilityState = testContainer.read(floatingPlayerVisibilityProvider);

        // Assert
        expect(visibilityState.isVisible, false);

        testContainer.dispose();
      });

      test('should be visible when episode is playing and not on player page', () {
        // Arrange - Override with playing episode and not on player page
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

        // Set route to feed page (not player)
        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/feed');

        // Act
        final visibilityState = testContainer.read(floatingPlayerVisibilityProvider);

        // Assert
        expect(visibilityState.isVisible, true);

        testContainer.dispose();
      });

      test('should be invisible when on player page even if playing', () {
        // Arrange - Override with playing episode but on player page
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

        // Set route to player page
        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/1/player');

        // Act
        final visibilityState = testContainer.read(floatingPlayerVisibilityProvider);

        // Assert
        expect(visibilityState.isVisible, false);

        testContainer.dispose();
      });

      test('should be invisible when paused on player page', () {
        // Arrange
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

        // Set route to player page
        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/1/player');

        // Act
        final visibilityState = testContainer.read(floatingPlayerVisibilityProvider);

        // Assert
        expect(visibilityState.isVisible, false);

        testContainer.dispose();
      });

      test('should reactively update when play state changes', () {
        // Arrange
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

        // Initially not visible (not playing)
        expect(testContainer.read(floatingPlayerVisibilityProvider).isVisible, false);

        // Update to playing state
        testContainer.read(audioPlayerProvider.notifier).state = AudioPlayerState(
          currentEpisode: testEpisode,
          isPlaying: true,
        );

        // Now should be visible
        expect(testContainer.read(floatingPlayerVisibilityProvider).isVisible, true);

        // Pause again
        testContainer.read(audioPlayerProvider.notifier).state = AudioPlayerState(
          currentEpisode: testEpisode,
          isPlaying: false,
        );

        // Should be invisible again
        expect(testContainer.read(floatingPlayerVisibilityProvider).isVisible, false);

        testContainer.dispose();
      });

      test('should reactively update when route changes', () {
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

        // Start on feed page - should be visible
        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/feed');
        expect(testContainer.read(floatingPlayerVisibilityProvider).isVisible, true);

        // Navigate to player page - should be invisible
        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/1/player');
        expect(testContainer.read(floatingPlayerVisibilityProvider).isVisible, false);

        // Navigate back to feed - should be visible again
        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/feed');
        expect(testContainer.read(floatingPlayerVisibilityProvider).isVisible, true);

        testContainer.dispose();
      });

      test('should handle simultaneous play state and route changes', () {
        // Arrange
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

        // Initial state - not visible
        testContainer.read(currentRouteProvider.notifier).setRoute('/');
        expect(testContainer.read(floatingPlayerVisibilityProvider).isVisible, false);

        // Navigate to feed - not visible (not playing yet)
        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/feed');
        expect(testContainer.read(floatingPlayerVisibilityProvider).isVisible, false);

        // Start playing - should be visible now
        testContainer.read(audioPlayerProvider.notifier).state = AudioPlayerState(
          currentEpisode: testEpisode,
          isPlaying: true,
        );
        expect(testContainer.read(floatingPlayerVisibilityProvider).isVisible, true);

        // Navigate to player - should hide
        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/1/player');
        expect(testContainer.read(floatingPlayerVisibilityProvider).isVisible, false);

        // Pause on player - still hidden
        testContainer.read(audioPlayerProvider.notifier).state = AudioPlayerState(
          currentEpisode: testEpisode,
          isPlaying: false,
        );
        expect(testContainer.read(floatingPlayerVisibilityProvider).isVisible, false);

        testContainer.dispose();
      });

      test('should be invisible when loading audio (isLoading)', () {
        // Arrange
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: false,
                isLoading: true,
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        final visibilityState = testContainer.read(floatingPlayerVisibilityProvider);

        // Assert - Not playing, so not visible even though loading
        expect(visibilityState.isVisible, false);

        testContainer.dispose();
      });

      test('should handle error states correctly', () {
        // Arrange - Playing with error
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              AudioPlayerState(
                currentEpisode: testEpisode,
                isPlaying: true,
                error: 'Network error',
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/podcast/feed');

        // Act - Even with error, if playing and not on player page, should be visible
        final visibilityState = testContainer.read(floatingPlayerVisibilityProvider);

        // Assert
        expect(visibilityState.isVisible, true);

        testContainer.dispose();
      });

      test('should handle different screen sizes', () {
        // Note: Position calculations are in the widget, not the provider
        // The provider only controls visibility based on play state and route

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

        testContainer.read(currentRouteProvider.notifier).setRoute('/home');

        // Act
        final visibilityState = testContainer.read(floatingPlayerVisibilityProvider);

        // Assert - Should be visible regardless of screen size
        expect(visibilityState.isVisible, true);

        testContainer.dispose();
      });
    });

    group('Edge Cases and Boundary Conditions', () {
      test('should handle null episode gracefully', () {
        final testContainer = ProviderContainer(
          overrides: [
            audioPlayerProvider.overrideWith(() => MockAudioPlayerNotifier(
              const AudioPlayerState(
                currentEpisode: null,
                isPlaying: true, // Playing but no episode
              ),
            )),
          ],
        );

        testContainer.read(currentRouteProvider.notifier).setRoute('/');

        // Act
        final visibilityState = testContainer.read(floatingPlayerVisibilityProvider);

        // Assert - Should not be visible (no episode)
        expect(visibilityState.isVisible, false);

        testContainer.dispose();
      });

      test('should handle rapid state changes', () {
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

        // Simulate rapid state changes
        for (int i = 0; i < 5; i++) {
          testContainer.read(audioPlayerProvider.notifier).state = AudioPlayerState(
            currentEpisode: testEpisode,
            isPlaying: i % 2 == 0,
          );

          final expectedVisibility = i % 2 == 0;
          expect(
            testContainer.read(floatingPlayerVisibilityProvider).isVisible,
            expectedVisibility,
            reason: 'Iteration $i: Expected visibility to be $expectedVisibility',
          );
        }

        testContainer.dispose();
      });

      test('should handle empty route string', () {
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

        testContainer.read(currentRouteProvider.notifier).setRoute('');

        // Act - Empty route is not player page
        final visibilityState = testContainer.read(floatingPlayerVisibilityProvider);

        // Assert
        expect(visibilityState.isVisible, true);

        testContainer.dispose();
      });

      test('should maintain isAnimating flag as false', () {
        // The current implementation sets isAnimating to false
        // This test documents the current behavior
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
        final visibilityState = testContainer.read(floatingPlayerVisibilityProvider);

        // Assert
        expect(visibilityState.isAnimating, false);

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

  // Override methods to avoid actual audio player initialization
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
