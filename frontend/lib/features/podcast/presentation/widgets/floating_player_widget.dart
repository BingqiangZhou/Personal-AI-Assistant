import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/podcast_episode_model.dart';
import '../providers/podcast_providers.dart';
import '../providers/floating_player_visibility_provider.dart';
import 'podcast_image_widget.dart';

/// Material 3 floating player widget that appears when podcast is playing
/// Shows podcast cover image with play/pause control
/// positioned on the right side of the screen
class FloatingPlayerWidget extends ConsumerWidget {
  const FloatingPlayerWidget({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    if (l10n == null) {
      return const SizedBox.shrink();
    }

    final visibilityState = ref.watch(floatingPlayerVisibilityProvider);
    final audioPlayerState = ref.watch(audioPlayerProvider);

    // Don't render if not visible
    if (!visibilityState.isVisible) {
      return const SizedBox.shrink();
    }

    final episode = audioPlayerState.currentEpisode;
    if (episode == null) {
      return const SizedBox.shrink();
    }

    return Positioned(
      right: _getRightPosition(context),
      top: _getTopPosition(context),
      child: AnimatedScale(
        scale: visibilityState.isVisible ? 1.0 : 0.0,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeInOut,
        child: _FloatingPlayerButton(
          episode: episode,
          isPlaying: audioPlayerState.isPlaying,
          onTap: () => _handlePlayPause(ref, audioPlayerState.isPlaying),
          onLongPress: () => _handleNavigateToPlayer(context, episode),
          tooltip: l10n.floating_player_tooltip,
        ),
      ),
    );
  }

  /// Calculate right position based on screen size (Material 3 guidelines)
  double _getRightPosition(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    // Mobile: 16dp from right edge
    if (screenWidth < 600) {
      return 16;
    }
    // Tablet/Desktop: 24dp from right edge
    return 24;
  }

  /// Calculate top position based on screen size
  /// Desktop/Tablet: vertically centered
  /// Mobile: slightly above bottom navigation
  double _getTopPosition(BuildContext context) {
    final screenHeight = MediaQuery.of(context).size.height;
    final screenWidth = MediaQuery.of(context).size.width;

    // Mobile: position above bottom navigation (80dp from bottom)
    if (screenWidth < 600) {
      return screenHeight - 136; // 56dp button + 80dp margin
    }

    // Desktop/Tablet: vertically centered
    return (screenHeight - 56) / 2;
  }

  /// Handle play/pause toggle
  void _handlePlayPause(WidgetRef ref, bool isPlaying) {
    final notifier = ref.read(audioPlayerProvider.notifier);
    if (isPlaying) {
      notifier.pause();
    } else {
      notifier.resume();
    }
  }

  /// Navigate to episode detail page on long-press
  /// Same navigation path as clicking an episode from the feed
  void _handleNavigateToPlayer(BuildContext context, PodcastEpisodeModel episode) {
    // Navigate to the episode detail page (same as tapping episode from feed)
    context.push('/podcast/episode/detail/${episode.id}');
  }
}

/// The actual floating action button widget
class _FloatingPlayerButton extends StatelessWidget {
  final PodcastEpisodeModel episode;
  final bool isPlaying;
  final VoidCallback onTap;
  final VoidCallback onLongPress;
  final String tooltip;

  const _FloatingPlayerButton({
    required this.episode,
    required this.isPlaying,
    required this.onTap,
    required this.onLongPress,
    required this.tooltip,
  });

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    if (l10n == null) {
      return const SizedBox.shrink();
    }

    return Tooltip(
      message: tooltip,
      child: GestureDetector(
        onTap: onTap,
        onLongPress: onLongPress,
        child: Container(
          width: 56,
          height: 56,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.3),
                blurRadius: 8,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          child: Material(
            elevation: 6,
            shape: const CircleBorder(),
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            clipBehavior: Clip.antiAlias,
            child: Stack(
              fit: StackFit.expand,
              children: [
                // Background image (podcast cover art)
                // Priority: subscriptionImageUrl > imageUrl > default cover
                if (episode.subscriptionImageUrl != null &&
                    episode.subscriptionImageUrl!.isNotEmpty)
                  PodcastImageWidget(
                    imageUrl: episode.subscriptionImageUrl,
                    width: 56,
                    height: 56,
                    iconSize: 28,
                    iconColor: Theme.of(context)
                        .colorScheme
                        .onSurfaceVariant
                        .withValues(alpha: 0.7),
                  )
                else if (episode.imageUrl != null && episode.imageUrl!.isNotEmpty)
                  PodcastImageWidget(
                    imageUrl: episode.imageUrl,
                    width: 56,
                    height: 56,
                    iconSize: 28,
                    iconColor: Theme.of(context)
                        .colorScheme
                        .onSurfaceVariant
                        .withValues(alpha: 0.7),
                  )
                else
                  _buildDefaultCover(context),

                // Semi-transparent overlay for icon contrast
                Container(
                  decoration: BoxDecoration(
                    color: Colors.black.withValues(alpha: 0.3),
                    shape: BoxShape.circle,
                  ),
                ),

                // Play/Pause icon centered
                Center(
                  child: Icon(
                    isPlaying ? Icons.pause : Icons.play_arrow,
                    size: 28,
                    color: Colors.white,
                  ),
                ),

                // Accessibility label
                Semantics(
                  label: l10n.floating_player_label,
                  hint: l10n.floating_player_nav_hint,
                  button: true,
                  excludeSemantics: true,
                  child: const SizedBox.expand(),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  /// Build default cover when no image is available
  Widget _buildDefaultCover(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Theme.of(context).colorScheme.primary,
            Theme.of(context).colorScheme.secondary,
          ],
        ),
      ),
      child: Center(
        child: Icon(
          Icons.podcasts,
          size: 28,
          color: Theme.of(context).colorScheme.onPrimary.withValues(alpha: 0.7),
        ),
      ),
    );
  }

}
