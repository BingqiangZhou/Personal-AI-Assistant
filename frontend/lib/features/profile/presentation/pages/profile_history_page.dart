import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/utils/time_formatter.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/playback_history_lite_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_image_widget.dart';

class ProfileHistoryPage extends ConsumerWidget {
  const ProfileHistoryPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context)!;
    final historyAsync = ref.watch(playbackHistoryLiteProvider);

    return Scaffold(
      appBar: AppBar(title: Text(l10n.profile_viewed_title)),
      body: RefreshIndicator(
        onRefresh: () {
          ref.invalidate(playbackHistoryLiteProvider);
          return ref.read(playbackHistoryLiteProvider.future);
        },
        child: historyAsync.when(
          data: (response) {
            final episodes =
                List<PlaybackHistoryLiteItem>.from(
                  response?.episodes ?? const <PlaybackHistoryLiteItem>[],
                )..sort((a, b) {
                  final aTime =
                      a.lastPlayedAt ?? DateTime.fromMillisecondsSinceEpoch(0);
                  final bTime =
                      b.lastPlayedAt ?? DateTime.fromMillisecondsSinceEpoch(0);
                  return bTime.compareTo(aTime);
                });

            if (episodes.isEmpty) {
              return ListView(
                physics: const AlwaysScrollableScrollPhysics(),
                children: [
                  const SizedBox(height: 120),
                  Icon(
                    Icons.history,
                    size: 56,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                  const SizedBox(height: 16),
                  Center(
                    child: Text(
                      l10n.server_history_empty,
                      style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ),
                ],
              );
            }

            return ListView.separated(
              physics: const AlwaysScrollableScrollPhysics(),
              padding: const EdgeInsets.all(16),
              itemCount: episodes.length,
              separatorBuilder: (_, index) => const SizedBox(height: 8),
              itemBuilder: (context, index) {
                final episode = episodes[index];
                return Card(
                  margin: EdgeInsets.zero,
                  child: ListTile(
                    leading: ClipRRect(
                      borderRadius: BorderRadius.circular(8),
                      child: PodcastImageWidget(
                        imageUrl: episode.imageUrl,
                        fallbackImageUrl: episode.subscriptionImageUrl,
                        width: 40,
                        height: 40,
                        iconSize: 20,
                        iconColor: Theme.of(context).colorScheme.primary,
                      ),
                    ),
                    title: Text(
                      episode.title,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    subtitle: Text(
                      _buildSubtitle(context, episode),
                      maxLines: 3,
                      overflow: TextOverflow.ellipsis,
                    ),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () =>
                        context.push('/podcast/episode/detail/${episode.id}'),
                  ),
                );
              },
            );
          },
          loading: () => ListView(
            physics: const AlwaysScrollableScrollPhysics(),
            children: const [
              SizedBox(height: 220),
              Center(child: CircularProgressIndicator()),
            ],
          ),
          error: (error, _) => ListView(
            physics: const AlwaysScrollableScrollPhysics(),
            children: [
              const SizedBox(height: 120),
              Icon(
                Icons.error_outline,
                size: 56,
                color: Theme.of(context).colorScheme.error,
              ),
              const SizedBox(height: 16),
              Center(
                child: Text(
                  error.toString(),
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  String _buildSubtitle(BuildContext context, PlaybackHistoryLiteItem episode) {
    final lastPlayedAt = episode.lastPlayedAt;
    final playedAtText = lastPlayedAt == null
        ? '--'
        : TimeFormatter.formatFullDateTime(lastPlayedAt);
    final position = episode.playbackPosition ?? 0;
    final progressText = episode.audioDuration != null
        ? '${_formatPlaybackPosition(context, position)} / ${episode.formattedDuration}'
        : _formatPlaybackPosition(context, position);

    final subscriptionTitle = episode.subscriptionTitle ?? '';
    if (subscriptionTitle.isEmpty) {
      return '$playedAtText\n$progressText';
    }
    return '$subscriptionTitle\n$playedAtText\n$progressText';
  }

  String _formatPlaybackPosition(BuildContext context, int seconds) {
    final l10n = AppLocalizations.of(context)!;
    final duration = Duration(seconds: seconds);
    final hours = duration.inHours;
    final minutes = duration.inMinutes.remainder(60);
    final remainingSeconds = duration.inSeconds.remainder(60);

    if (hours > 0) {
      return '${hours.toString().padLeft(2, '0')}:${minutes.toString().padLeft(2, '0')}:${remainingSeconds.toString().padLeft(2, '0')}';
    }

    if (remainingSeconds > 0) {
      return '${minutes.toString().padLeft(2, '0')}:${remainingSeconds.toString().padLeft(2, '0')}';
    }

    return l10n.player_minutes(minutes);
  }
}
