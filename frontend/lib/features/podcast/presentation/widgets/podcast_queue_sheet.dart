import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../data/models/podcast_queue_model.dart';
import '../providers/podcast_providers.dart';

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
    final queueAsync = ref.watch(podcastQueueControllerProvider);
    final notifier = ref.read(podcastQueueControllerProvider.notifier);

    return SizedBox(
      height: MediaQuery.of(context).size.height * 0.72,
      child: queueAsync.when(
        data: (queue) {
          if (queue.items.isEmpty) {
            return _QueueScaffold(
              title: 'Playlist',
              onRefresh: () => notifier.loadQueue(),
              child: const Center(child: Text('Queue is empty')),
            );
          }

          return _QueueScaffold(
            title: 'Playlist',
            onRefresh: () => notifier.loadQueue(),
            child: _QueueList(queue: queue),
          );
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, _) {
          return _QueueScaffold(
            title: 'Playlist',
            onRefresh: () => notifier.loadQueue(),
            child: Center(child: Text('Failed to load queue: $error')),
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
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(content: Text('Failed to reorder queue: $error')),
            );
          }
        }
      },
      itemBuilder: (context, index) {
        final item = queue.items[index];
        final isCurrent = item.episodeId == currentEpisodeId;
        return ListTile(
          key: ValueKey(item.episodeId),
          leading: CircleAvatar(
            child: Icon(
              isCurrent ? Icons.equalizer : Icons.music_note,
              size: 18,
            ),
          ),
          title: Text(item.title, maxLines: 1, overflow: TextOverflow.ellipsis),
          subtitle: Text(_formatSubtitle(item)),
          onTap: () async {
            try {
              await notifier.playFromQueue(item.episodeId);
            } catch (error) {
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text('Failed to play item: $error')),
                );
              }
            }
          },
          trailing: IconButton(
            tooltip: 'Remove',
            onPressed: () async {
              try {
                await notifier.removeFromQueue(item.episodeId);
              } catch (error) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('Failed to remove item: $error')),
                  );
                }
              }
            },
            icon: const Icon(Icons.delete_outline),
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
