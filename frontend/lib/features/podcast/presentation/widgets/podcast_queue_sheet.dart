import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/adaptive_sheet_helper.dart';
import '../../../../core/widgets/top_floating_notice.dart';
import '../../data/models/podcast_queue_model.dart';
import '../providers/podcast_providers.dart';
import 'podcast_image_widget.dart';

class PodcastQueueSheet extends ConsumerWidget {
  const PodcastQueueSheet({super.key});

  static Future<void>? _activeShowFuture;

  static Future<void> show(
    BuildContext context, {
    Future<void> Function()? beforeShow,
  }) {
    final existing = _activeShowFuture;
    if (existing != null) {
      return existing;
    }

    final showFuture = Future.sync(() async {
      if (beforeShow != null) {
        await beforeShow();
        if (!context.mounted) {
          return;
        }
      }
      await showAdaptiveSheet<void>(
        context: context,
        builder: (context) => const PodcastQueueSheet(),
      );
    });

    late final Future<void> trackedFuture;
    trackedFuture = showFuture.whenComplete(() {
      if (identical(_activeShowFuture, trackedFuture)) {
        _activeShowFuture = null;
      }
    });

    _activeShowFuture = trackedFuture;
    return trackedFuture;
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final title = l10n?.podcast_player_list ?? 'Playlist';
    final queueAsync = ref.watch(podcastQueueControllerProvider);
    final notifier = ref.read(podcastQueueControllerProvider.notifier);
    final theme = Theme.of(context);

    return SizedBox(
      height: MediaQuery.of(context).size.height * 0.72,
      child: queueAsync.when(
        data: (queue) {
          if (queue.items.isEmpty) {
            return _QueueScaffold(
              title: title,
              onRefresh: () => notifier.loadQueue(),
              child: ListView(
                physics: const AlwaysScrollableScrollPhysics(),
                padding: const EdgeInsets.symmetric(horizontal: 24),
                children: [
                  SizedBox(height: MediaQuery.of(context).size.height * 0.12),
                  Icon(
                    Icons.playlist_play,
                    size: 42,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  const SizedBox(height: 12),
                  Text(
                    l10n?.queue_is_empty ?? 'Queue is empty',
                    textAlign: TextAlign.center,
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    l10n?.pull_to_refresh ?? 'Pull to refresh',
                    textAlign: TextAlign.center,
                    style: theme.textTheme.bodyMedium?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            );
          }

          return _QueueScaffold(
            title: title,
            onRefresh: () => notifier.loadQueue(),
            child: _QueueList(queue: queue),
          );
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, _) {
          return _QueueScaffold(
            title: title,
            onRefresh: () => notifier.loadQueue(),
            child: ListView(
              physics: const AlwaysScrollableScrollPhysics(),
              padding: const EdgeInsets.symmetric(horizontal: 24),
              children: [
                SizedBox(height: MediaQuery.of(context).size.height * 0.12),
                Icon(
                  Icons.error_outline,
                  size: 42,
                  color: theme.colorScheme.error,
                ),
                const SizedBox(height: 12),
                Text(
                  l10n?.failed_to_load_queue(error.toString()) ??
                      'Failed to load queue: $error',
                  textAlign: TextAlign.center,
                  style: theme.textTheme.bodyMedium,
                ),
                const SizedBox(height: 10),
                Center(
                  child: FilledButton.tonalIcon(
                    onPressed: () => notifier.loadQueue(),
                    icon: const Icon(Icons.refresh),
                    label: Text(l10n?.retry ?? 'Retry'),
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }
}

class _QueueScaffold extends StatelessWidget {
  final String title;
  final Future<void> Function() onRefresh;
  final Widget child;

  const _QueueScaffold({
    required this.title,
    required this.onRefresh,
    required this.child,
  });

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return Column(
      children: [
        const SizedBox(height: 4),
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 8, 8),
          child: Row(
            children: [
              Text(
                title,
                style: Theme.of(
                  context,
                ).textTheme.titleMedium?.copyWith(
                  fontSize: 20,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const Spacer(),
              IconButton(
                tooltip: l10n?.refresh ?? 'Refresh',
                onPressed: onRefresh,
                icon: const Icon(Icons.refresh),
              ),
              IconButton(
                tooltip: l10n?.close ?? 'Close',
                onPressed: () => Navigator.of(context).pop(),
                icon: const Icon(Icons.close),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: RefreshIndicator(
            onRefresh: onRefresh,
            child: child,
          ),
        ),
      ],
    );
  }
}

class _QueueList extends ConsumerWidget {
  final PodcastQueueModel queue;

  const _QueueList({required this.queue});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final notifier = ref.read(podcastQueueControllerProvider.notifier);
    final audioPlayerState = ref.watch(audioPlayerProvider);
    final currentEpisodeId = queue.currentEpisodeId;

    return ReorderableListView.builder(
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 24),
      buildDefaultDragHandles: false,
      physics: const AlwaysScrollableScrollPhysics(),
      itemCount: queue.items.length,
      onReorder: (oldIndex, newIndex) async {
        var targetIndex = newIndex;
        if (oldIndex < newIndex) {
          targetIndex -= 1;
        }

        final ordered = [...queue.items];
        final moved = ordered.removeAt(oldIndex);
        ordered.insert(targetIndex, moved);
        final orderedIds = ordered.map((item) => item.episodeId).toList();

        try {
          await notifier.reorderQueue(orderedIds);
        } catch (error) {
          if (context.mounted) {
            final l10n = AppLocalizations.of(context);
            showTopFloatingNotice(
              context,
              message:
                  l10n?.failed_to_reorder_queue(error.toString()) ??
                  'Failed to reorder queue: $error',
              isError: true,
            );
          }
        }
      },
      itemBuilder: (context, index) {
        final item = queue.items[index];
        final isCurrent = item.episodeId == currentEpisodeId;
        final theme = Theme.of(context);
        return Material(
          key: ValueKey(item.episodeId),
          color: Colors.transparent,
          child: InkWell(
            borderRadius: BorderRadius.circular(16),
            onTap: () async {
              try {
                await notifier.playFromQueue(item.episodeId);
              } catch (error) {
                if (context.mounted) {
                  final l10n = AppLocalizations.of(context);
                  showTopFloatingNotice(
                    context,
                    message:
                        l10n?.failed_to_play_item(error.toString()) ??
                        'Failed to play item: $error',
                    isError: true,
                  );
                }
              }
            },
            child: Ink(
              decoration: BoxDecoration(
                color: isCurrent
                    ? theme.colorScheme.primaryContainer.withValues(alpha: 0.28)
                    : theme.colorScheme.surfaceContainerHighest
                        .withValues(alpha: 0.35),
                borderRadius: BorderRadius.circular(16),
              ),
              child: Padding(
                padding: const EdgeInsets.fromLTRB(10, 10, 6, 10),
                child: Row(
                  children: [
                    SizedBox(
                      width: 34,
                      height: 44,
                      child: ReorderableDragStartListener(
                        key: Key('queue_item_drag_${item.episodeId}'),
                        index: index,
                        child: Icon(
                          Icons.drag_indicator,
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ),
                    _QueueItemCover(item: item, isCurrent: isCurrent, size: 44),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Text(
                            item.title,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: theme.textTheme.titleMedium?.copyWith(
                              fontWeight: isCurrent
                                  ? FontWeight.w700
                                  : FontWeight.w600,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            _formatSubtitle(
                              item,
                              isCurrent: isCurrent,
                              currentPositionMs: audioPlayerState.position,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: theme.textTheme.bodyMedium?.copyWith(
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 8),
                    IconButton(
                      key: Key('queue_item_remove_${item.episodeId}'),
                      tooltip: AppLocalizations.of(context)?.delete ?? 'Delete',
                      constraints: const BoxConstraints.tightFor(
                        width: 40,
                        height: 40,
                      ),
                      padding: EdgeInsets.zero,
                      onPressed: () async {
                        try {
                          await notifier.removeFromQueue(item.episodeId);
                        } catch (error) {
                          if (context.mounted) {
                            final l10n = AppLocalizations.of(context);
                            showTopFloatingNotice(
                              context,
                              message:
                                  l10n
                                      ?.failed_to_remove_item(error.toString()) ??
                                  'Failed to remove item: $error',
                              isError: true,
                            );
                          }
                        }
                      },
                      icon: const Icon(Icons.delete_outline),
                    ),
                  ],
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  String _formatSubtitle(
    PodcastQueueItemModel item, {
    required bool isCurrent,
    required int currentPositionMs,
  }) {
    final title = item.subscriptionTitle;
    final durationSec = item.duration;
    var playedSec = isCurrent
        ? (currentPositionMs / 1000).round()
        : (item.playbackPosition ?? 0);
    if (playedSec < 0) {
      playedSec = 0;
    }

    final progressText = _formatProgress(
      playedSec: playedSec,
      durationSec: durationSec,
    );
    if (title == null || title.isEmpty) {
      return progressText;
    }
    return '$title · $progressText';
  }

  String _formatProgress({required int playedSec, required int? durationSec}) {
    if (durationSec == null || durationSec <= 0) {
      return '${_formatClock(playedSec)} / --:--';
    }

    final clampedPlayed = playedSec > durationSec ? durationSec : playedSec;
    return '${_formatClock(clampedPlayed)} / ${_formatClock(durationSec)}';
  }

  String _formatClock(int seconds) {
    final safeSeconds = seconds < 0 ? 0 : seconds;
    final duration = Duration(seconds: safeSeconds);
    final hours = duration.inHours;
    final minutes = duration.inMinutes.remainder(60);
    final remainingSeconds = duration.inSeconds.remainder(60);

    if (hours > 0) {
      return '$hours:${minutes.toString().padLeft(2, '0')}:${remainingSeconds.toString().padLeft(2, '0')}';
    }
    return '${minutes.toString().padLeft(2, '0')}:${remainingSeconds.toString().padLeft(2, '0')}';
  }
}

class _QueueItemCover extends StatelessWidget {
  const _QueueItemCover({
    required this.item,
    required this.isCurrent,
    required this.size,
  });

  final PodcastQueueItemModel item;
  final bool isCurrent;
  final double size;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final imageUrl = item.subscriptionImageUrl ?? item.imageUrl;

    return SizedBox(
      key: Key('queue_item_cover_${item.episodeId}'),
      width: size,
      height: size,
      child: Stack(
        clipBehavior: Clip.none,
        children: [
          Positioned.fill(
            child: ClipRRect(
              borderRadius: BorderRadius.circular(12),
              child: imageUrl != null && imageUrl.isNotEmpty
                  ? PodcastImageWidget(
                      imageUrl: imageUrl,
                      width: size,
                      height: size,
                      iconSize: size * 0.52,
                    )
                  : _fallback(theme),
            ),
          ),
          if (isCurrent)
            Positioned(
              right: -2,
              bottom: -2,
              child: Container(
                key: Key('queue_item_playing_badge_${item.episodeId}'),
                width: 18,
                height: 18,
                decoration: BoxDecoration(
                  color: theme.colorScheme.secondary,
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: theme.colorScheme.surface,
                    width: 1.5,
                  ),
                ),
                child: Icon(
                  Icons.equalizer,
                  size: 12,
                  color: theme.colorScheme.onSecondary,
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _fallback(ThemeData theme) {
    return Container(
      key: Key('queue_item_cover_fallback_${item.episodeId}'),
      color: theme.colorScheme.surfaceContainerHighest,
      alignment: Alignment.center,
      child: Icon(
        Icons.podcasts,
        color: theme.colorScheme.onSurfaceVariant,
        size: size * 0.52,
      ),
    );
  }
}
