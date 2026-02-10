import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../data/models/podcast_queue_model.dart';
import '../providers/podcast_providers.dart';
import '../../../../core/localization/app_localizations.dart';

class PodcastQueueSheet extends ConsumerWidget {
  const PodcastQueueSheet({super.key});

  static Future<void> show(BuildContext context) {
    return showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      useSafeArea: true,
      builder: (context) => const PodcastQueueSheet(),
    );
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context)!;
    final queueAsync = ref.watch(podcastQueueControllerProvider);
    final notifier = ref.read(podcastQueueControllerProvider.notifier);

    return SizedBox(
      height: MediaQuery.of(context).size.height * 0.72,
      child: queueAsync.when(
        data: (queue) {
          if (queue.items.isEmpty) {
            return _QueueScaffold(
              title: l10n.podcast_rss_list,
              onRefresh: () => notifier.loadQueue(),
              child: Center(child: Text(l10n.queue_is_empty)),
            );
          }

          return _QueueScaffold(
            title: l10n.podcast_rss_list,
            onRefresh: () => notifier.loadQueue(),
            child: _QueueList(queue: queue),
          );
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, _) {
          return _QueueScaffold(
            title: l10n.podcast_rss_list,
            onRefresh: () => notifier.loadQueue(),
            child: Center(child: Text(l10n.failed_to_load_queue(error.toString()))),
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
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 8, 8),
          child: Row(
            children: [
              Text(
                title,
                style: Theme.of(
                  context,
                ).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w700),
              ),
              const Spacer(),
              IconButton(
                tooltip: 'Refresh',
                onPressed: onRefresh,
                icon: const Icon(Icons.refresh),
              ),
              IconButton(
                tooltip: 'Close',
                onPressed: () => Navigator.of(context).pop(),
                icon: const Icon(Icons.close),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(child: child),
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
    final currentEpisodeId = queue.currentEpisodeId;

    return ReorderableListView.builder(
      padding: const EdgeInsets.symmetric(vertical: 8),
      buildDefaultDragHandles: false,
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
            final l10n = AppLocalizations.of(context)!;
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(content: Text(l10n.failed_to_reorder_queue(error.toString()))),
            );
          }
        }
      },
      itemBuilder: (context, index) {
        final item = queue.items[index];
        final isCurrent = item.episodeId == currentEpisodeId;
        final theme = Theme.of(context);
        return Container(
          key: ValueKey(item.episodeId),
          margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
          decoration: BoxDecoration(
            color: isCurrent
                ? theme.colorScheme.primaryContainer.withValues(alpha: 0.24)
                : Colors.transparent,
            borderRadius: BorderRadius.circular(12),
          ),
          child: InkWell(
            borderRadius: BorderRadius.circular(12),
            onTap: () async {
              try {
                await notifier.playFromQueue(item.episodeId);
              } catch (error) {
                if (context.mounted) {
                  final l10n = AppLocalizations.of(context)!;
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text(l10n.failed_to_play_item(error.toString()))),
                  );
                }
              }
            },
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
              child: Row(
                children: [
                  SizedBox(
                    width: 40,
                    height: 40,
                    child: ReorderableDragStartListener(
                      key: Key('queue_item_drag_${item.episodeId}'),
                      index: index,
                      child: Icon(
                        Icons.drag_indicator,
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  _QueueItemCover(
                    item: item,
                    isCurrent: isCurrent,
                    size: 44,
                  ),
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
                                : FontWeight.w500,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          _formatSubtitle(item),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.bodyLarge?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 8),
                  IconButton(
                    key: Key('queue_item_remove_${item.episodeId}'),
                    tooltip: AppLocalizations.of(context)!.delete,
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
                          final l10n = AppLocalizations.of(context)!;
                          ScaffoldMessenger.of(context).showSnackBar(
                            SnackBar(content: Text(l10n.failed_to_remove_item(error.toString()))),
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
        );
      },
    );
  }

  String _formatSubtitle(PodcastQueueItemModel item) {
    final title = item.subscriptionTitle;
    final duration = item.duration;
    if (duration == null) {
      return title ?? '';
    }
    final minutes = duration ~/ 60;
    final seconds = duration % 60;
    final durationText = '$minutes:${seconds.toString().padLeft(2, '0')}';
    if (title == null || title.isEmpty) {
      return durationText;
    }
    return '$title · $durationText';
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
                  ? Image.network(
                      imageUrl,
                      fit: BoxFit.cover,
                      errorBuilder: (_, _, _) => _fallback(theme),
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
                  color: theme.colorScheme.primary,
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: theme.colorScheme.surface,
                    width: 1.5,
                  ),
                ),
                child: Icon(
                  Icons.equalizer,
                  size: 12,
                  color: theme.colorScheme.onPrimary,
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
      color: theme.colorScheme.primary.withValues(alpha: 0.14),
      alignment: Alignment.center,
      child: Icon(
        Icons.podcasts,
        color: theme.colorScheme.primary,
        size: size * 0.52,
      ),
    );
  }
}
