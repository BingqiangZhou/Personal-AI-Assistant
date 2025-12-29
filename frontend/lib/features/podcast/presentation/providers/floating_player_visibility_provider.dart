import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/providers/route_provider.dart';
import '../providers/podcast_providers.dart';

/// State for the floating player visibility
class FloatingPlayerVisibilityState {
  final bool isVisible;
  final bool isAnimating;

  const FloatingPlayerVisibilityState({
    this.isVisible = false,
    this.isAnimating = false,
  });

  FloatingPlayerVisibilityState copyWith({
    bool? isVisible,
    bool? isAnimating,
  }) {
    return FloatingPlayerVisibilityState(
      isVisible: isVisible ?? this.isVisible,
      isAnimating: isAnimating ?? this.isAnimating,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is FloatingPlayerVisibilityState &&
          runtimeType == other.runtimeType &&
          isVisible == other.isVisible &&
          isAnimating == other.isAnimating;

  @override
  int get hashCode => isVisible.hashCode ^ isAnimating.hashCode;
}

/// Notifier that manages the floating player visibility based on:
/// 1. Audio player state (currentEpisode)
/// 2. Current route (should hide on player page)
///
/// Visibility logic: Show if there is a current episode AND NOT on player page
/// The button remains visible even when paused to allow easy access to play/pause
class FloatingPlayerVisibilityNotifier
    extends Notifier<FloatingPlayerVisibilityState> {
  @override
  FloatingPlayerVisibilityState build() {
    // Watch the relevant providers
    final audioPlayerState = ref.watch(audioPlayerProvider);
    final isOnPlayerPage = ref.watch(isOnPlayerPageProvider);

    // Determine visibility based on conditions:
    // - Show if there is a current episode AND NOT on player page
    // - This allows the button to remain visible even when paused
    final shouldShow = audioPlayerState.currentEpisode != null &&
        !isOnPlayerPage;

    return FloatingPlayerVisibilityState(
      isVisible: shouldShow,
    );
  }
}

/// Provider for the floating player visibility state
final floatingPlayerVisibilityProvider =
    NotifierProvider<FloatingPlayerVisibilityNotifier, FloatingPlayerVisibilityState>(
        FloatingPlayerVisibilityNotifier.new);
