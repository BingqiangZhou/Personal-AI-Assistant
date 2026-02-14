import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../data/models/podcast_episode_model.dart';
import '../navigation/podcast_navigation.dart';
import '../../../../core/utils/time_formatter.dart';
import '../../core/utils/episode_description_helper.dart';
import '../../../../core/localization/app_localizations.dart';
import 'podcast_image_widget.dart';

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
    final l10n = AppLocalizations.of(context)!;
    // Get display description: AI summary main topics or plain shownotes
    final displayDescription = EpisodeDescriptionHelper.getDisplayDescription(
      aiSummary: episode.aiSummary,
      description: episode.description,
    );

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: InkWell(
        onTap:
            onTap ??
            () {
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
                      child: PodcastImageWidget(
                        imageUrl: episode.imageUrl ?? episode.subscriptionImageUrl,
                        width: 48,
                        height: 48,
                        iconSize: 28,
                        iconColor: Theme.of(context).colorScheme.onPrimaryContainer,
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  // Title
                  Expanded(
                    child: Text(
                      episode.title,
                      style: Theme.of(context).textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.w600,
                        fontSize: 13,
                      ),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
              ),
              // Display description: AI summary main topics or plain shownotes
              if (displayDescription.isNotEmpty) ...[
                const SizedBox(height: 12),
                Text(
                  key: const Key('feed_style_description'),
                  displayDescription,
                  style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
              const SizedBox(height: 12),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: Wrap(
                      key: const Key('feed_style_metadata'),
                      spacing: 12,
                      runSpacing: 8,
                      crossAxisAlignment: WrapCrossAlignment.center,
                      children: [
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 10,
                            vertical: 3,
                          ),
                          decoration: BoxDecoration(
                            color: Theme.of(context).colorScheme.primary,
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: Text(
                            episode.subscriptionTitle ??
                                l10n.podcast_default_podcast,
                            style: Theme.of(context).textTheme.labelSmall
                                ?.copyWith(
                                  color: Theme.of(
                                    context,
                                  ).colorScheme.onPrimary,
                                  fontWeight: FontWeight.bold,
                                  fontSize: 11,
                                ),
                          ),
                        ),
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.calendar_today_outlined,
                              size: 16,
                              color: Theme.of(
                                context,
                              ).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 4),
                            Text(
                              TimeFormatter.formatRelativeTime(
                                episode.publishedAt,
                              ),
                              style: Theme.of(context).textTheme.bodySmall
                                  ?.copyWith(
                                    color: Theme.of(
                                      context,
                                    ).colorScheme.onSurfaceVariant,
                                  ),
                            ),
                          ],
                        ),
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.schedule,
                              size: 16,
                              color: Theme.of(
                                context,
                              ).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 4),
                            Text(
                              episode.formattedDuration,
                              style: Theme.of(context).textTheme.bodySmall
                                  ?.copyWith(
                                    color: Theme.of(
                                      context,
                                    ).colorScheme.onSurfaceVariant,
                                  ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 12),
                  FilledButton.tonal(
                    key: const Key('feed_style_play_button'),
                    onPressed: onPlay,
                    child: Text(l10n.play_button_short),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
