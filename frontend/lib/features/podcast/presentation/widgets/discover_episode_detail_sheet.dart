import 'package:flutter/material.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/itunes_episode_lookup_model.dart';
import 'podcast_image_widget.dart';

class DiscoverEpisodeDetailSheet extends StatelessWidget {
  const DiscoverEpisodeDetailSheet({
    super.key,
    required this.episode,
    required this.onPlay,
  });

  final ITunesPodcastEpisodeResult episode;
  final VoidCallback onPlay;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final description = episode.description?.trim().isNotEmpty == true
        ? episode.description!
        : (episode.shortDescription ?? '');

    return SafeArea(
      child: SingleChildScrollView(
        key: const Key('discover_episode_detail_sheet'),
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                ClipRRect(
                  borderRadius: BorderRadius.circular(8),
                  child: PodcastImageWidget(
                    imageUrl: episode.artworkUrl600 ?? episode.artworkUrl100,
                    width: 64,
                    height: 64,
                    iconSize: 26,
                    iconColor: theme.colorScheme.primary,
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        episode.trackName,
                        style: theme.textTheme.titleMedium?.copyWith(
                          fontWeight: FontWeight.w700,
                          height: 1.15,
                        ),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 4),
                      Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  episode.collectionName,
                                  style: theme.textTheme.bodyMedium?.copyWith(
                                    color: theme.colorScheme.onSurfaceVariant,
                                    height: 1.15,
                                  ),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                                const SizedBox(height: 2),
                                Text(
                                  _buildMetaText(episode),
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: theme.colorScheme.onSurfaceVariant,
                                    height: 1.15,
                                  ),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ],
                            ),
                          ),
                          const SizedBox(width: 6),
                          Align(
                            alignment: Alignment.center,
                            child: SizedBox.square(
                              dimension: 36,
                              child: IconButton.filled(
                                key: const Key('discover_episode_detail_play_button'),
                                onPressed: onPlay,
                                icon: const Icon(Icons.play_arrow),
                                iconSize: 18,
                                style: IconButton.styleFrom(
                                  padding: EdgeInsets.zero,
                                  visualDensity: VisualDensity.compact,
                                ),
                                tooltip: l10n.podcast_play,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ],
            ),
            if (description.isNotEmpty) ...[
              const SizedBox(height: 10),
              Text(description, style: theme.textTheme.bodyMedium),
            ],
          ],
        ),
      ),
    );
  }

  String _buildMetaText(ITunesPodcastEpisodeResult episode) {
    final parts = <String>[];
    if (episode.releaseDate != null) {
      parts.add(_formatDate(episode.releaseDate!));
    }
    if (episode.trackTimeMillis != null && episode.trackTimeMillis! > 0) {
      parts.add(
        _formatDuration(Duration(milliseconds: episode.trackTimeMillis!)),
      );
    }
    return parts.join(' · ');
  }

  String _formatDate(DateTime dateTime) {
    final date = dateTime.toLocal();
    final month = date.month.toString().padLeft(2, '0');
    final day = date.day.toString().padLeft(2, '0');
    return '${date.year}-$month-$day';
  }

  String _formatDuration(Duration duration) {
    final hours = duration.inHours;
    final minutes = duration.inMinutes.remainder(60);
    final seconds = duration.inSeconds.remainder(60);
    if (hours > 0) {
      return '${hours.toString().padLeft(2, '0')}:${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
    }
    return '${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';
  }
}
