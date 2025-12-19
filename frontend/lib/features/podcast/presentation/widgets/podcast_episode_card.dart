import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../data/models/podcast_episode_model.dart';
import '../providers/podcast_providers.dart';

class PodcastEpisodeCard extends ConsumerWidget {
  final PodcastEpisodeModel episode;
  final VoidCallback? onTap;
  final VoidCallback? onPlay;

  const PodcastEpisodeCard({
    super.key,
    required this.episode,
    this.onTap,
    this.onPlay,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final audioPlayerState = ref.watch(audioPlayerNotifierProvider);

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: InkWell(
        onTap: onTap ?? () {
          context.go('/podcasts/episodes/${episode.id}');
        },
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header with title and play button
              Row(
                children: [
                  // Episode thumbnail placeholder
                  Container(
                    width: 60,
                    height: 60,
                    decoration: BoxDecoration(
                      color: theme.primaryColor.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Stack(
                      children: [
                        Center(
                          child: Icon(
                            Icons.headphones,
                            size: 30,
                            color: theme.primaryColor,
                          ),
                        ),
                        // Show play/pause icon if currently playing
                        if (audioPlayerState.currentEpisode?.id == episode.id)
                          Center(
                            child: Icon(
                              audioPlayerState.isPlaying
                                  ? Icons.pause
                                  : Icons.play_arrow,
                              size: 30,
                              color: theme.primaryColor,
                            ),
                          ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 16),
                  // Episode info
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        // Episode identifier and status
                        Row(
                          children: [
                            if (episode.episodeIdentifier.isNotEmpty) ...[
                              Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 8,
                                  vertical: 2,
                                ),
                                decoration: BoxDecoration(
                                  color: theme.primaryColor.withOpacity(0.1),
                                  borderRadius: BorderRadius.circular(12),
                                ),
                                child: Text(
                                  episode.episodeIdentifier,
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: theme.primaryColor,
                                    fontWeight: FontWeight.w500,
                                  ),
                                ),
                              ),
                              const SizedBox(width: 8),
                            ],
                            if (episode.isPlayed)
                              Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 8,
                                  vertical: 2,
                                ),
                                decoration: BoxDecoration(
                                  color: Colors.grey.withOpacity(0.2),
                                  borderRadius: BorderRadius.circular(12),
                                ),
                                child: Text(
                                  'Played',
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: Colors.grey[600],
                                    fontWeight: FontWeight.w500,
                                  ),
                                ),
                              ),
                            if (episode.explicit) ...[
                              const SizedBox(width: 8),
                              Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 8,
                                  vertical: 2,
                                ),
                                decoration: BoxDecoration(
                                  color: Colors.red.withOpacity(0.1),
                                  borderRadius: BorderRadius.circular(12),
                                ),
                                child: Text(
                                  'E',
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: Colors.red,
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                              ),
                            ],
                          ],
                        ),
                        const SizedBox(height: 8),
                        // Episode title
                        Text(
                          episode.title,
                          style: theme.textTheme.titleMedium?.copyWith(
                            fontWeight: FontWeight.bold,
                          ),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 4),
                        // Published date
                        Text(
                          DateFormat('MMM d, yyyy').format(episode.publishedAt),
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: Colors.grey[600],
                          ),
                        ),
                      ],
                    ),
                  ),
                  // Play button
                  IconButton.filled(
                    onPressed: () async {
                      if (audioPlayerState.currentEpisode?.id == episode.id) {
                        // Toggle play/pause for current episode
                        if (audioPlayerState.isPlaying) {
                          await ref
                              .read(audioPlayerNotifierProvider.notifier)
                              .pause();
                        } else {
                          await ref
                              .read(audioPlayerNotifierProvider.notifier)
                              .resume();
                        }
                      } else {
                        // Play this episode
                        onPlay?.call();
                      }
                    },
                    icon: Icon(
                      audioPlayerState.currentEpisode?.id == episode.id
                          ? (audioPlayerState.isPlaying
                              ? Icons.pause
                              : Icons.play_arrow)
                          : Icons.play_arrow,
                    ),
                  ),
                ],
              ),
              // Description (if available)
              if (episode.description != null && episode.description!.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Text(
                    episode.description!,
                    style: theme.textTheme.bodyMedium?.copyWith(
                      color: theme.textTheme.bodyMedium?.color?.withOpacity(0.7),
                    ),
                    maxLines: 3,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              // Progress bar and duration
              if (episode.playbackPosition != null && episode.audioDuration != null)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Column(
                    children: [
                      LinearProgressIndicator(
                        value: episode.progressPercentage,
                        backgroundColor: Colors.grey[300],
                        valueColor: AlwaysStoppedAnimation<Color>(
                          theme.primaryColor,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            episode.formattedPlaybackPosition,
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: Colors.grey[600],
                            ),
                          ),
                          Text(
                            episode.formattedDuration,
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: Colors.grey[600],
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              // Bottom row with metadata
              Padding(
                padding: const EdgeInsets.only(top: 12),
                child: Row(
                  children: [
                    if (episode.audioDuration != null)
                      _buildMetadataItem(
                        context,
                        Icons.schedule,
                        episode.formattedDuration,
                      ),
                    if (episode.aiSummary != null) ...[
                      const SizedBox(width: 16),
                      _buildMetadataItem(
                        context,
                        Icons.summarize,
                        'AI Summary',
                        color: Colors.green,
                      ),
                    ],
                    if (episode.transcriptContent != null) ...[
                      const SizedBox(width: 16),
                      _buildMetadataItem(
                        context,
                        Icons.transcript,
                        'Transcript',
                      ),
                    ],
                    if (episode.playCount > 0) ...[
                      const SizedBox(width: 16),
                      _buildMetadataItem(
                        context,
                        Icons.play_circle_outline,
                        '${episode.playCount} plays',
                      ),
                    ],
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildMetadataItem(
    BuildContext context,
    IconData icon,
    String text, {
    Color? color,
  }) {
    final theme = Theme.of(context);
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(
          icon,
          size: 16,
          color: color ?? theme.textTheme.bodySmall?.color?.withOpacity(0.7),
        ),
        const SizedBox(width: 4),
        Text(
          text,
          style: theme.textTheme.bodySmall?.copyWith(
            color: color ?? theme.textTheme.bodySmall?.color?.withOpacity(0.7),
          ),
        ),
      ],
    );
  }
}