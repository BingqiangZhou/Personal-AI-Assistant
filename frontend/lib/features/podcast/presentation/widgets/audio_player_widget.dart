import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/podcast_providers.dart';

class AudioPlayerWidget extends ConsumerWidget {
  const AudioPlayerWidget({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final audioPlayerState = ref.watch(audioPlayerNotifierProvider);
    final theme = Theme.of(context);

    if (audioPlayerState.currentEpisode == null) {
      return const SizedBox.shrink();
    }

    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.1),
            blurRadius: 8,
            offset: const Offset(0, -2),
          ),
        ],
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Mini player (when collapsed)
          if (!audioPlayerState.isExpanded) _buildMiniPlayer(context, ref, audioPlayerState),
          // Full player (when expanded)
          if (audioPlayerState.isExpanded) _buildFullPlayer(context, ref, audioPlayerState),
        ],
      ),
    );
  }

  Widget _buildMiniPlayer(BuildContext context, WidgetRef ref, AudioPlayerState state) {
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Row(
        children: [
          // Episode thumbnail
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(
              color: theme.primaryColor.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(
              Icons.headphones,
              color: theme.primaryColor,
            ),
          ),
          const SizedBox(width: 12),
          // Episode info
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  state.currentEpisode!.title,
                  style: theme.text.titleSmall?.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 2),
                Text(
                  state.formattedPosition,
                  style: theme.text.bodySmall?.copyWith(
                    color: theme.text.bodySmall?.color?.withOpacity(0.7),
                  ),
                ),
              ],
            ),
          ),
          // Play/pause button
          IconButton(
            onPressed: state.isLoading
                ? null
                : () async {
                    if (state.isPlaying) {
                      await ref.read(audioPlayerNotifierProvider.notifier).pause();
                    } else {
                      await ref.read(audioPlayerNotifierProvider.notifier).resume();
                    }
                  },
            icon: state.isLoading
                ? SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      valueColor: AlwaysStoppedAnimation<Color>(
                        theme.colorScheme.primary,
                      ),
                    ),
                  )
                : Icon(
                    state.isPlaying ? Icons.pause : Icons.play_arrow,
                  ),
          ),
          // Expand button
          IconButton(
            onPressed: () {
              ref.read(audioPlayerNotifierProvider.notifier).setExpanded(true);
            },
            icon: const Icon(Icons.keyboard_arrow_up),
          ),
        ],
      ),
    );
  }

  Widget _buildFullPlayer(BuildContext context, WidgetRef ref, AudioPlayerState state) {
    final theme = Theme.of(context);

    return Container(
      height: MediaQuery.of(context).size.height * 0.7,
      padding: const EdgeInsets.all(24),
      child: Column(
        children: [
          // Header with close button
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text(
                'Now Playing',
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.w600,
                ),
              ),
              IconButton(
                onPressed: () {
                  ref.read(audioPlayerNotifierProvider.notifier).setExpanded(false);
                },
                icon: const Icon(Icons.keyboard_arrow_down),
              ),
            ],
          ),
          const SizedBox(height: 32),
          // Episode artwork
          Container(
            width: 200,
            height: 200,
            decoration: BoxDecoration(
              color: theme.primaryColor.withOpacity(0.1),
              borderRadius: BorderRadius.circular(16),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.1),
                  blurRadius: 20,
                  offset: const Offset(0, 10),
                ),
              ],
            ),
            child: Icon(
              Icons.headphones,
              size: 80,
              color: theme.primaryColor,
            ),
          ),
          const SizedBox(height: 32),
          // Episode title and info
          Column(
            children: [
              Text(
                state.currentEpisode!.title,
                style: theme.text.headlineSmall?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
                textAlign: TextAlign.center,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
              const SizedBox(height: 8),
              if (state.currentEpisode!.description != null)
                Text(
                  state.currentEpisode!.description!,
                  style: theme.text.bodyMedium?.copyWith(
                    color: theme.text.bodyMedium?.color?.withOpacity(0.7),
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
                  value: state.position.toDouble().clamp(0.0, state.duration.toDouble()),
                  onChanged: (value) async {
                    await ref
                        .read(audioPlayerNotifierProvider.notifier)
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
                    Text(state.formattedDuration),
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
              IconButton(
                onPressed: () {
                  // TODO: Implement previous episode
                },
                icon: const Icon(Icons.skip_previous),
                iconSize: 40,
              ),
              // Rewind 15 seconds
              IconButton(
                onPressed: () async {
                  final newPosition = (state.position - 15000).clamp(0, state.duration);
                  await ref
                      .read(audioPlayerNotifierProvider.notifier)
                      .seekTo(newPosition);
                },
                icon: const Icon(Icons.replay_15),
                iconSize: 40,
              ),
              // Play/pause button
              Container(
                decoration: BoxDecoration(
                  color: theme.primaryColor,
                  shape: BoxShape.circle,
                ),
                child: IconButton(
                  onPressed: state.isLoading
                      ? null
                      : () async {
                          if (state.isPlaying) {
                            await ref.read(audioPlayerNotifierProvider.notifier).pause();
                          } else {
                            await ref.read(audioPlayerNotifierProvider.notifier).resume();
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
              // Forward 15 seconds
              IconButton(
                onPressed: () async {
                  final newPosition = (state.position + 15000).clamp(0, state.duration);
                  await ref
                      .read(audioPlayerNotifierProvider.notifier)
                      .seekTo(newPosition);
                },
                icon: const Icon(Icons.forward_15),
                iconSize: 40,
              ),
              // Next button (placeholder)
              IconButton(
                onPressed: () {
                  // TODO: Implement next episode
                },
                icon: const Icon(Icons.skip_next),
                iconSize: 40,
              ),
            ],
          ),
          const SizedBox(height: 32),
          // Playback speed and additional options
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // Playback speed
              PopupMenuButton<double>(
                icon: Text('${state.playbackRate}x'),
                onSelected: (speed) async {
                  await ref
                      .read(audioPlayerNotifierProvider.notifier)
                      .setPlaybackRate(speed);
                },
                itemBuilder: (context) => [
                  const PopupMenuItem(
                    value: 0.5,
                    child: Text('0.5x'),
                  ),
                  const PopupMenuItem(
                    value: 0.75,
                    child: Text('0.75x'),
                  ),
                  const PopupMenuItem(
                    value: 1.0,
                    child: Text('1x'),
                  ),
                  const PopupMenuItem(
                    value: 1.25,
                    child: Text('1.25x'),
                  ),
                  const PopupMenuItem(
                    value: 1.5,
                    child: Text('1.5x'),
                  ),
                  const PopupMenuItem(
                    value: 2.0,
                    child: Text('2x'),
                  ),
                ],
              ),
              const SizedBox(width: 32),
              // View episode details
              TextButton.icon(
                onPressed: () {
                  context.go('/podcasts/episodes/${state.currentEpisode!.id}');
                },
                icon: const Icon(Icons.info_outline),
                label: const Text('Episode Details'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}