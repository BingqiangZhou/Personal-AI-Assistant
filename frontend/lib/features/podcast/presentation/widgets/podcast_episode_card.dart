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
    final audioPlayerState = ref.watch(audioPlayerProvider);

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: InkWell(
        onTap: onTap ?? () {
          context.go('/podcast/episodes/${episode.subscriptionId}/${episode.id}');
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
                  // Episode thumbnail placeholder with enhanced contrast
                  Container(
                    width: 60,
                    height: 60,
                    decoration: BoxDecoration(
                      color: theme.primaryColor.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(
                        color: theme.primaryColor.withValues(alpha: 0.3),
                        width: 1,
                      ),
                    ),
                    child: Stack(
                      children: [
                        Center(
                          child: Container(
                            padding: const EdgeInsets.all(8),
                            decoration: BoxDecoration(
                              color: theme.primaryColor.withValues(alpha: 0.2),
                              shape: BoxShape.circle,
                            ),
                            child: Icon(
                              Icons.headphones,
                              size: 24,
                              color: theme.primaryColor.withValues(alpha: 0.9),
                            ),
                          ),
                        ),
                        // Show play/pause icon if currently playing
                        if (audioPlayerState.currentEpisode?.id == episode.id)
                          Center(
                            child: Container(
                              padding: const EdgeInsets.all(8),
                              decoration: BoxDecoration(
                                color: theme.primaryColor.withValues(alpha: 0.3),
                                shape: BoxShape.circle,
                                border: Border.all(
                                  color: theme.primaryColor.withValues(alpha: 0.5),
                                  width: 1,
                                ),
                              ),
                              child: Icon(
                                audioPlayerState.isPlaying
                                    ? Icons.pause
                                    : Icons.play_arrow,
                                size: 24,
                                color: theme.primaryColor,
                              ),
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
                        // Episode identifier and status with enhanced contrast
                        Row(
                          children: [
                            if (episode.episodeIdentifier.isNotEmpty) ...[
                              Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 10,
                                  vertical: 4,
                                ),
                                decoration: BoxDecoration(
                                  color: theme.primaryColor.withValues(alpha: 0.2),
                                  borderRadius: BorderRadius.circular(12),
                                  border: Border.all(
                                    color: theme.primaryColor.withValues(alpha: 0.4),
                                    width: 1,
                                  ),
                                ),
                                child: Text(
                                  episode.episodeIdentifier,
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: theme.primaryColor.withValues(alpha: 0.9),
                                    fontWeight: FontWeight.w700,
                                    fontSize: 11,
                                  ),
                                ),
                              ),
                              const SizedBox(width: 8),
                            ],
                            if (episode.isPlayed)
                              Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 10,
                                  vertical: 4,
                                ),
                                decoration: BoxDecoration(
                                  color: Colors.grey.withValues(alpha: 0.3),
                                  borderRadius: BorderRadius.circular(12),
                                  border: Border.all(
                                    color: Colors.grey.withValues(alpha: 0.5),
                                    width: 1,
                                  ),
                                ),
                                child: Text(
                                  'Played',
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: Colors.grey[700] ?? Colors.grey.shade700,
                                    fontWeight: FontWeight.w700,
                                    fontSize: 11,
                                  ),
                                ),
                              ),
                            if (episode.explicit) ...[
                              const SizedBox(width: 8),
                              Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 10,
                                  vertical: 4,
                                ),
                                decoration: BoxDecoration(
                                  color: Colors.red.withValues(alpha: 0.2),
                                  borderRadius: BorderRadius.circular(12),
                                  border: Border.all(
                                    color: Colors.red.withValues(alpha: 0.4),
                                    width: 1,
                                  ),
                                ),
                                child: Text(
                                  'E',
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: Colors.red.shade700 ?? Colors.red[700],
                                    fontWeight: FontWeight.w900,
                                    fontSize: 11,
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
                  // Enhanced play button with better contrast
                  Container(
                    decoration: BoxDecoration(
                      color: theme.primaryColor,
                      shape: BoxShape.circle,
                      boxShadow: [
                        BoxShadow(
                          color: theme.primaryColor.withValues(alpha: 0.4),
                          blurRadius: 8,
                          offset: const Offset(0, 3),
                        ),
                      ],
                      border: Border.all(
                        color: theme.primaryColor.withValues(alpha: 0.3),
                        width: 1,
                      ),
                    ),
                    child: IconButton(
                      onPressed: () async {
                        if (audioPlayerState.currentEpisode?.id == episode.id) {
                          // Toggle play/pause for current episode
                          if (audioPlayerState.isPlaying) {
                            await ref
                                .read(audioPlayerProvider.notifier)
                                .pause();
                          } else {
                            await ref
                                .read(audioPlayerProvider.notifier)
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
                        color: theme.colorScheme.onPrimary,
                        size: 28,
                      ),
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
                      color: theme.textTheme.bodyMedium?.color?.withValues(alpha: 0.7),
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
                        Icons.description,
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
    final defaultColor = color ?? theme.colorScheme.primary;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: defaultColor.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(
          color: defaultColor.withValues(alpha: 0.3),
          width: 1,
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            icon,
            size: 14,
            color: defaultColor.withValues(alpha: 0.9),
          ),
          const SizedBox(width: 4),
          Text(
            text,
            style: theme.textTheme.bodySmall?.copyWith(
              color: defaultColor.withValues(alpha: 0.9),
              fontWeight: FontWeight.w600,
              fontSize: 11,
            ),
          ),
        ],
      ),
    );
  }
}