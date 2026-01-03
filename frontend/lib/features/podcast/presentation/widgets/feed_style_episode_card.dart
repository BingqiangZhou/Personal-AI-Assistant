import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../data/models/podcast_episode_model.dart';
import '../navigation/podcast_navigation.dart';
import '../../../../core/utils/time_formatter.dart';

class FeedStyleEpisodeCard extends ConsumerWidget {
  final PodcastEpisodeModel episode;
  final VoidCallback? onTap;
  final VoidCallback? onPlay;

  const FeedStyleEpisodeCard({
    super.key,
    required this.episode,
    this.onTap,
    this.onPlay,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: InkWell(
        onTap: onTap ?? () {
          PodcastNavigation.goToEpisodeDetail(
            context,
            episodeId: episode.id,
            subscriptionId: episode.subscriptionId,
            episodeTitle: episode.title,
          );
        },
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Play Button / Image
                  Container(
                    width: 48,
                    height: 48,
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.primaryContainer,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(8),
                      child: (episode.imageUrl != null || episode.subscriptionImageUrl != null)
                          ? Image.network(
                              episode.imageUrl ?? episode.subscriptionImageUrl!,
                              fit: BoxFit.cover,
                              errorBuilder: (context, error, stackTrace) => Icon(
                                episode.isPlayed ? Icons.play_arrow : Icons.play_circle_filled,
                                color: Theme.of(context).colorScheme.onPrimaryContainer,
                                size: 28,
                              ),
                            )
                          : Icon(
                              episode.isPlayed ? Icons.play_arrow : Icons.play_circle_filled,
                              color: Theme.of(context).colorScheme.onPrimaryContainer,
                              size: 28,
                            ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  // Title and Tags
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          episode.title,
                          style: Theme.of(context).textTheme.titleMedium?.copyWith(
                                fontWeight: FontWeight.w600,
                                fontSize: 13,
                              ),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 8),
                        Wrap(
                          spacing: 12,
                          runSpacing: 8,
                          crossAxisAlignment: WrapCrossAlignment.center,
                          children: [
                            // Podcast Name
                            if (episode.subscriptionTitle != null)
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
                                decoration: BoxDecoration(
                                  color: Theme.of(context).colorScheme.primary,
                                  borderRadius: BorderRadius.circular(12),
                                ),
                                child: Text(
                                  episode.subscriptionTitle!,
                                  style: Theme.of(context).textTheme.labelSmall?.copyWith(
                                        color: Theme.of(context).colorScheme.onPrimary,
                                        fontWeight: FontWeight.bold,
                                        fontSize: 11,
                                      ),
                                ),
                              ),
                            // Date
                            Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  Icons.calendar_today_outlined,
                                  size: 16,
                                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                                ),
                                const SizedBox(width: 4),
                                Text(
                                  TimeFormatter.formatRelativeTime(episode.publishedAt),
                                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                                      ),
                                ),
                              ],
                            ),
                            // Duration
                            Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  Icons.schedule,
                                  size: 16,
                                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                                ),
                                const SizedBox(width: 4),
                                Text(
                                  episode.formattedDuration,
                                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                                      ),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              if (episode.description != null) ...[
                const SizedBox(height: 12),
                Text(
                  episode.description!,
                  style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                  maxLines: 4,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
              const SizedBox(height: 12),
              // Action Buttons
              Align(
                alignment: Alignment.centerRight,
                child: FilledButton.tonal(
                  onPressed: onPlay,
                  child: const Text('Play'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
