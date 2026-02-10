import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:url_launcher/url_launcher.dart';

import '../navigation/podcast_navigation.dart';
import '../providers/podcast_providers.dart';
import '../../data/models/audio_player_state_model.dart';
import '../constants/playback_speed_options.dart';
import 'playback_speed_selector_sheet.dart';
import 'sleep_timer_selector_sheet.dart';
import '../../../../core/utils/app_logger.dart' as logger;

class AudioPlayerWidget extends ConsumerWidget {
  const AudioPlayerWidget({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final audioPlayerState = ref.watch(audioPlayerProvider);
    final theme = Theme.of(context);

    if (audioPlayerState.currentEpisode == null) {
      return const SizedBox.shrink();
    }

    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.1),
            blurRadius: 8,
            offset: const Offset(0, -2),
          ),
        ],
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Mini player (when collapsed)
          if (!audioPlayerState.isExpanded)
            _buildMiniPlayer(context, ref, audioPlayerState),
          // Full player (when expanded)
          if (audioPlayerState.isExpanded)
            _buildFullPlayer(context, ref, audioPlayerState),
        ],
      ),
    );
  }

  Widget _buildMiniPlayer(
    BuildContext context,
    WidgetRef ref,
    AudioPlayerState state,
  ) {
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Row(
        children: [
          // Episode thumbnail with podcast icon
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(borderRadius: BorderRadius.circular(8)),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(8),
              child: state.currentEpisode!.subscriptionImageUrl != null
                  ? Image.network(
                      state.currentEpisode!.subscriptionImageUrl!,
                      width: 48,
                      height: 48,
                      fit: BoxFit.cover,
                      errorBuilder: (context, error, stackTrace) {
                        return Container(
                          color: theme.primaryColor.withValues(alpha: 0.1),
                          child: Icon(
                            Icons.podcasts,
                            color: theme.primaryColor,
                          ),
                        );
                      },
                    )
                  : Container(
                      color: theme.primaryColor.withValues(alpha: 0.1),
                      child: Icon(Icons.podcasts, color: theme.primaryColor),
                    ),
            ),
          ),
          const SizedBox(width: 12),
          // Episode info
          Expanded(
            child: GestureDetector(
              onTap: () {
                final episode = state.currentEpisode;
                if (episode != null) {
                  final currentLocation = GoRouterState.of(context).uri.toString();
                  final episodeDetailPath = '/podcast/episodes/${episode.subscriptionId}/${episode.id}';
                  if (currentLocation.startsWith(episodeDetailPath)) {
                    ref.read(audioPlayerProvider.notifier).setExpanded(true);
                  } else {
                    PodcastNavigation.goToEpisodeDetail(
                      context,
                      episodeId: episode.id,
                      subscriptionId: episode.subscriptionId,
                      episodeTitle: episode.title,
                    );
                  }
                }
              },
              behavior: HitTestBehavior.opaque,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    state.currentEpisode!.title,
                    style: Theme.of(
                      context,
                    ).textTheme.titleSmall?.copyWith(fontWeight: FontWeight.w600),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 2),
                  Text(
                    '${state.formattedPosition} / ${state.formattedDuration}',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Theme.of(
                        context,
                      ).textTheme.bodySmall?.color?.withValues(alpha: 0.7),
                    ),
                  ),
                ],
              ),
            ),
          ),
          // Play/pause button
          Container(
            decoration: BoxDecoration(
              color: theme.primaryColor.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(20),
              border: Border.all(
                color: theme.primaryColor.withValues(alpha: 0.3),
                width: 1,
              ),
            ),
            child: IconButton(
              onPressed: state.isLoading
                  ? null
                  : () async {
                      if (state.isPlaying) {
                        await ref.read(audioPlayerProvider.notifier).pause();
                      } else {
                        await ref.read(audioPlayerProvider.notifier).resume();
                      }
                    },
              icon: state.isLoading
                  ? SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        valueColor: AlwaysStoppedAnimation<Color>(
                          theme.primaryColor,
                        ),
                      ),
                    )
                  : Icon(
                      state.isPlaying ? Icons.pause : Icons.play_arrow,
                      color: theme.primaryColor.withValues(alpha: 0.8),
                    ),
            ),
          ),
          const SizedBox(width: 8),
          // Expand button
          Container(
            decoration: BoxDecoration(
              color: theme.colorScheme.surface.withValues(alpha: 0.5),
              borderRadius: BorderRadius.circular(20),
              border: Border.all(
                color: theme.dividerColor.withValues(alpha: 0.3),
                width: 1,
              ),
            ),
            child: IconButton(
              onPressed: () {
                ref.read(audioPlayerProvider.notifier).setExpanded(true);
              },
              icon: Icon(
                Icons.keyboard_arrow_up,
                color: theme.colorScheme.onSurfaceVariant.withValues(
                  alpha: 0.8,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFullPlayer(
    BuildContext context,
    WidgetRef ref,
    AudioPlayerState state,
  ) {
    final theme = Theme.of(context);

    return Container(
      height: MediaQuery.of(context).size.height * 0.7,
      padding: const EdgeInsets.all(24),
      child: SingleChildScrollView(
        child: Column(
          children: [
            // Header with sleep timer and close button
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Text(
                  'Now Playing',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600),
                ),
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // Sleep timer button
                    _buildSleepTimerButton(context, ref, state),
                    const SizedBox(width: 4),
                    IconButton(
                      onPressed: () {
                        ref.read(audioPlayerProvider.notifier).setExpanded(false);
                      },
                      icon: const Icon(Icons.keyboard_arrow_down),
                    ),
                  ],
                ),
              ],
            ),
            const SizedBox(height: 32),
            // Episode artwork with podcast icon
            Container(
              width: 200,
              height: 200,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(16),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.1),
                    blurRadius: 20,
                    offset: const Offset(0, 10),
                  ),
                ],
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(16),
                child: state.currentEpisode!.subscriptionImageUrl != null
                    ? Image.network(
                        state.currentEpisode!.subscriptionImageUrl!,
                        width: 200,
                        height: 200,
                        fit: BoxFit.cover,
                        errorBuilder: (context, error, stackTrace) {
                          return Container(
                            color: theme.primaryColor.withValues(alpha: 0.1),
                            child: Icon(
                              Icons.podcasts,
                              size: 80,
                              color: theme.primaryColor,
                            ),
                          );
                        },
                      )
                    : Container(
                        color: theme.primaryColor.withValues(alpha: 0.1),
                        child: Icon(
                          Icons.podcasts,
                          size: 80,
                          color: theme.primaryColor,
                        ),
                      ),
              ),
            ),
            const SizedBox(height: 32),
            // Episode title and info
            Column(
              children: [
                // Title with link icon
                Builder(
                  builder: (context) {
                    final titleStyle = Theme.of(context).textTheme.headlineSmall
                        ?.copyWith(fontWeight: FontWeight.bold);
                    final hasItemLink =
                        state.currentEpisode!.itemLink != null &&
                        state.currentEpisode!.itemLink!.isNotEmpty;

                    if (!hasItemLink) {
                      return Text(
                        state.currentEpisode!.title,
                        style: titleStyle,
                        textAlign: TextAlign.center,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      );
                    }

                    // Use Wrap to center title with icon after it
                    return Wrap(
                      alignment: WrapAlignment.center,
                      crossAxisAlignment: WrapCrossAlignment.center,
                      children: [
                        Text(
                          state.currentEpisode!.title,
                          style: titleStyle,
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(width: 6),
                        InkWell(
                          onTap: () async {
                            final Uri linkUri = Uri.parse(
                              state.currentEpisode!.itemLink!,
                            );
                            if (await canLaunchUrl(linkUri)) {
                              await launchUrl(
                                linkUri,
                                mode: LaunchMode.externalApplication,
                              );
                            }
                          },
                          child: Icon(
                            Icons.link,
                            size: 20,
                            color: theme.primaryColor,
                          ),
                        ),
                      ],
                    );
                  },
                ),
                const SizedBox(height: 8),
                if (state.currentEpisode!.description != null)
                  Text(
                    state.currentEpisode!.description!,
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: Theme.of(
                        context,
                      ).textTheme.bodyMedium?.color?.withValues(alpha: 0.7),
                    ),
                    textAlign: TextAlign.center,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
              ],
            ),
            const SizedBox(height: 32),
            // Progress bar
            Column(
              children: [
                SliderTheme(
                  data: SliderTheme.of(context).copyWith(
                    trackHeight: 4,
                    thumbShape: const RoundSliderThumbShape(
                      enabledThumbRadius: 8,
                    ),
                    overlayShape: const RoundSliderOverlayShape(
                      overlayRadius: 16,
                    ),
                  ),
                  child: Slider(
                    min: 0,
                    max: state.duration.toDouble(),
                    value: state.position.toDouble().clamp(
                      0.0,
                      state.duration.toDouble(),
                    ),
                    onChanged: (value) async {
                      await ref
                          .read(audioPlayerProvider.notifier)
                          .seekTo(value.round());
                    },
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(state.formattedPosition),
                      // Debug: Show duration value
                      Builder(
                        builder: (context) {
                          if (const bool.fromEnvironment('dart.vm.product') ==
                              false) {
                            // Only log in debug mode
                            logger.AppLogger.debug(
                              '🎵 [EXPANDED PLAYER] state.duration=${state.duration}ms, formatted=${state.formattedDuration}',
                            );
                          }
                          return Text(state.formattedDuration);
                        },
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 32),
            // Playback controls
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
              children: [
                // Previous button (placeholder)
                Container(
                  decoration: BoxDecoration(
                    color: theme.colorScheme.surface.withValues(alpha: 0.5),
                    borderRadius: BorderRadius.circular(24),
                    border: Border.all(
                      color: theme.dividerColor.withValues(alpha: 0.3),
                      width: 1,
                    ),
                  ),
                  child: IconButton(
                    onPressed: () {
                      // TODO: Implement previous episode
                    },
                    icon: Icon(
                      Icons.skip_previous,
                      color: theme.colorScheme.onSurfaceVariant.withValues(
                        alpha: 0.8,
                      ),
                    ),
                    iconSize: 36,
                  ),
                ),
                // Rewind 15 seconds
                Container(
                  decoration: BoxDecoration(
                    color: theme.colorScheme.surface.withValues(alpha: 0.5),
                    borderRadius: BorderRadius.circular(24),
                    border: Border.all(
                      color: theme.dividerColor.withValues(alpha: 0.3),
                      width: 1,
                    ),
                  ),
                  child: IconButton(
                    onPressed: () async {
                      final newPosition = (state.position - 15000).clamp(
                        0,
                        state.duration,
                      );
                      await ref
                          .read(audioPlayerProvider.notifier)
                          .seekTo(newPosition);
                    },
                    icon: Icon(
                      Icons.fast_rewind,
                      color: theme.colorScheme.onSurfaceVariant.withValues(
                        alpha: 0.8,
                      ),
                    ),
                    iconSize: 36,
                  ),
                ),
                // Play/pause button
                Container(
                  decoration: BoxDecoration(
                    color: theme.primaryColor,
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: theme.primaryColor.withValues(alpha: 0.3),
                        blurRadius: 12,
                        offset: const Offset(0, 4),
                      ),
                    ],
                  ),
                  child: IconButton(
                    onPressed: state.isLoading
                        ? null
                        : () async {
                            if (state.isPlaying) {
                              await ref
                                  .read(audioPlayerProvider.notifier)
                                  .pause();
                            } else {
                              await ref
                                  .read(audioPlayerProvider.notifier)
                                  .resume();
                            }
                          },
                    icon: state.isLoading
                        ? SizedBox(
                            width: 24,
                            height: 24,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              valueColor: AlwaysStoppedAnimation<Color>(
                                theme.colorScheme.onPrimary,
                              ),
                            ),
                          )
                        : Icon(
                            state.isPlaying ? Icons.pause : Icons.play_arrow,
                            color: theme.colorScheme.onPrimary,
                            size: 40,
                          ),
                  ),
                ),
                // Forward 30 seconds
                Container(
                  decoration: BoxDecoration(
                    color: theme.colorScheme.surface.withValues(alpha: 0.5),
                    borderRadius: BorderRadius.circular(24),
                    border: Border.all(
                      color: theme.dividerColor.withValues(alpha: 0.3),
                      width: 1,
                    ),
                  ),
                  child: IconButton(
                    onPressed: () async {
                      final newPosition = (state.position + 30000).clamp(
                        0,
                        state.duration,
                      );
                      await ref
                          .read(audioPlayerProvider.notifier)
                          .seekTo(newPosition);
                    },
                    icon: Icon(
                      Icons.fast_forward,
                      color: theme.colorScheme.onSurfaceVariant.withValues(
                        alpha: 0.8,
                      ),
                    ),
                    iconSize: 36,
                  ),
                ),
                // Next button (placeholder)
                Container(
                  decoration: BoxDecoration(
                    color: theme.colorScheme.surface.withValues(alpha: 0.5),
                    borderRadius: BorderRadius.circular(24),
                    border: Border.all(
                      color: theme.dividerColor.withValues(alpha: 0.3),
                      width: 1,
                    ),
                  ),
                  child: IconButton(
                    onPressed: () {
                      // TODO: Implement next episode
                    },
                    icon: Icon(
                      Icons.skip_next,
                      color: theme.colorScheme.onSurfaceVariant.withValues(
                        alpha: 0.8,
                      ),
                    ),
                    iconSize: 36,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 32),
            // Playback speed and additional options
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // Playback speed
                Container(
                  key: const Key('audio_player_speed_button'),
                  decoration: BoxDecoration(
                    color: theme.colorScheme.surface.withValues(alpha: 0.5),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: theme.dividerColor.withValues(alpha: 0.3),
                      width: 1,
                    ),
                  ),
                  child: InkWell(
                    borderRadius: BorderRadius.circular(8),
                    onTap: () async {
                      final selection = await showPlaybackSpeedSelectorSheet(
                        context: context,
                        initialSpeed: state.playbackRate,
                      );
                      if (selection == null) return;
                      if (!context.mounted) return;
                      await ref
                          .read(audioPlayerProvider.notifier)
                          .setPlaybackRate(
                            selection.speed,
                            applyToSubscription: selection.applyToSubscription,
                          );
                    },
                    child: Padding(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 10,
                        vertical: 6,
                      ),
                      child: Text(
                        formatPlaybackSpeed(state.playbackRate),
                        style: TextStyle(
                          color: theme.colorScheme.onSurfaceVariant.withValues(
                            alpha: 0.8,
                          ),
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 32),
                // View episode details
                Container(
                  decoration: BoxDecoration(
                    color: theme.primaryColor.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: theme.primaryColor.withValues(alpha: 0.3),
                      width: 1,
                    ),
                  ),
                  child: TextButton.icon(
                    onPressed: () {
                      // Navigate to episode detail - need subscriptionId too
                      if (state.currentEpisode?.subscriptionId != null) {
                        context.go(
                          '/podcast/episodes/${state.currentEpisode!.subscriptionId}/${state.currentEpisode!.id}',
                        );
                      }
                    },
                    icon: Icon(
                      Icons.info_outline,
                      color: theme.primaryColor.withValues(alpha: 0.8),
                    ),
                    label: Text(
                      'Episode Details',
                      style: TextStyle(
                        color: theme.primaryColor.withValues(alpha: 0.8),
                      ),
                    ),
                    style: TextButton.styleFrom(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 8,
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSleepTimerButton(
    BuildContext context,
    WidgetRef ref,
    AudioPlayerState state,
  ) {
    final theme = Theme.of(context);
    final isActive = state.isSleepTimerActive;

    return IconButton(
      onPressed: () async {
        final selection = await showSleepTimerSelectorSheet(
          context: context,
          isTimerActive: isActive,
        );
        if (selection == null) return;
        if (!context.mounted) return;

        final notifier = ref.read(audioPlayerProvider.notifier);
        if (selection.cancel) {
          notifier.cancelSleepTimer();
        } else if (selection.afterEpisode) {
          notifier.setSleepTimerAfterEpisode();
        } else if (selection.duration != null) {
          notifier.setSleepTimer(selection.duration!);
        }
      },
      tooltip: '睡眠定时',
      icon: Column(
        mainAxisSize: MainAxisSize.min,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            isActive ? Icons.nightlight_round : Icons.nightlight_outlined,
            color: isActive
                ? theme.colorScheme.primary
                : theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.8),
            size: 24,
          ),
          if (isActive && state.sleepTimerRemainingLabel != null)
            Text(
              state.sleepTimerRemainingLabel!,
              style: TextStyle(
                fontSize: 9,
                color: theme.colorScheme.primary,
                fontWeight: FontWeight.w700,
                height: 1.0,
              ),
            ),
        ],
      ),
    );
  }
}
