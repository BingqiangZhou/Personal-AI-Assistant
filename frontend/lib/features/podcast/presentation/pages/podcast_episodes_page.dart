import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../data/models/podcast_episode_model.dart';
import '../../data/models/podcast_subscription_model.dart';
import '../navigation/podcast_navigation.dart';
import '../providers/podcast_providers.dart';
import '../widgets/podcast_episode_card.dart';

class PodcastEpisodesPage extends ConsumerStatefulWidget {
  final int subscriptionId;
  final String? podcastTitle;
  final PodcastSubscriptionModel? subscription;

  const PodcastEpisodesPage({
    super.key,
    required this.subscriptionId,
    this.podcastTitle,
    this.subscription,
  });

  /// Factory for navigation from args
  factory PodcastEpisodesPage.fromArgs(PodcastEpisodesPageArgs args) {
    return PodcastEpisodesPage(
      subscriptionId: args.subscriptionId,
      podcastTitle: args.podcastTitle,
      subscription: args.subscription,
    );
  }

  /// Factory for direct navigation with subscription object
  factory PodcastEpisodesPage.withSubscription(PodcastSubscriptionModel subscription) {
    return PodcastEpisodesPage(
      subscriptionId: subscription.id,
      podcastTitle: subscription.title,
      subscription: subscription,
    );
  }

  @override
  ConsumerState<PodcastEpisodesPage> createState() => _PodcastEpisodesPageState();
}

class _PodcastEpisodesPageState extends ConsumerState<PodcastEpisodesPage> {
  final ScrollController _scrollController = ScrollController();
  String _selectedFilter = 'all';
  bool _showOnlyWithSummary = false;

  @override
  void initState() {
    super.initState();
    // Load initial episodes
    Future.microtask(() {
      ref.read(podcastEpisodeProvider.notifier).loadEpisodes(
            subscriptionId: widget.subscriptionId,
          );
    });

    // Setup scroll listener for infinite scroll
    _scrollController.addListener(() {
      if (_scrollController.position.pixels ==
          _scrollController.position.maxScrollExtent) {
        ref.read(podcastEpisodeProvider.notifier).loadMoreEpisodes();
      }
    });
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _refreshEpisodes() async {
    await ref.read(podcastEpisodeProvider.notifier).loadEpisodes(
          subscriptionId: widget.subscriptionId,
          hasSummary: _showOnlyWithSummary ? true : null,
          isPlayed: _selectedFilter == 'played' ? true : _selectedFilter == 'unplayed' ? false : null,
        );
  }

  @override
  Widget build(BuildContext context) {
    final episodesAsync = ref.watch(podcastEpisodeProvider);
    final audioPlayerState = ref.watch(audioPlayerProvider);

    return Scaffold(
      appBar: AppBar(
        title: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.15),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(
              color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
              width: 1,
            ),
          ),
          child: Text(
            widget.podcastTitle ?? 'Podcast Episodes',
            style: TextStyle(
              color: Theme.of(context).colorScheme.primary,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
        backgroundColor: Theme.of(context).colorScheme.surface,
        elevation: 2,
        actions: [
          Container(
            margin: const EdgeInsets.only(right: 8),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
                width: 1,
              ),
            ),
            child: IconButton(
              icon: Icon(
                Icons.filter_list,
                color: Theme.of(context).colorScheme.primary,
              ),
              onPressed: _showFilterDialog,
              tooltip: 'Filter',
            ),
          ),
          Container(
            margin: const EdgeInsets.only(right: 16),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.secondary.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                color: Theme.of(context).colorScheme.secondary.withValues(alpha: 0.3),
                width: 1,
              ),
            ),
            child: PopupMenuButton<String>(
              icon: Icon(
                Icons.more_vert,
                color: Theme.of(context).colorScheme.secondary,
              ),
              onSelected: (value) {
                switch (value) {
                  case 'mark_all_played':
                    // TODO: Implement mark all as played
                    break;
                  case 'mark_all_unplayed':
                    // TODO: Implement mark all as unplayed
                    break;
                }
              },
              itemBuilder: (context) => [
                const PopupMenuItem(
                  value: 'mark_all_played',
                  child: Row(
                    children: [
                      Icon(Icons.check_circle),
                      SizedBox(width: 8),
                      Text('Mark All as Played'),
                    ],
                  ),
                ),
                const PopupMenuItem(
                  value: 'mark_all_unplayed',
                  child: Row(
                    children: [
                      Icon(Icons.radio_button_unchecked),
                      SizedBox(width: 8),
                      Text('Mark All as Unplayed'),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _refreshEpisodes,
        child: episodesAsync.when(
          data: (response) {
            if (response.episodes.isEmpty) {
              return _buildEmptyState();
            }
            return Column(
              children: [
                // Filter chips
                _buildFilterChips(),
                // Episodes list
                Expanded(
                  child: ListView.builder(
                    controller: _scrollController,
                    padding: const EdgeInsets.symmetric(vertical: 8),
                    itemCount: response.episodes.length,
                    itemBuilder: (context, index) {
                      final episode = response.episodes[index];
                      return PodcastEpisodeCard(
                        episode: episode,
                        onTap: () {
                          // 跳转到分集详细页面
                          context.push('/podcast/episode/detail/${episode.id}');
                        },
                        onPlay: () async {
                          await ref
                              .read(audioPlayerProvider.notifier)
                              .playEpisode(episode);
                        },
                      );
                    },
                  ),
                ),
              ],
            );
          },
          loading: () => const Center(
            child: CircularProgressIndicator(),
          ),
          error: (error, stack) => _buildErrorState(error),
        ),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.headphones_outlined,
            size: 80,
            color: Theme.of(context).colorScheme.onSurfaceVariant.withValues(alpha: 0.5),
          ),
          const SizedBox(height: 16),
          Text(
            _showOnlyWithSummary
                ? 'No Episodes with AI Summary'
                : 'No Episodes Found',
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            _showOnlyWithSummary
                ? 'Try adjusting your filters'
                : 'This podcast might not have any episodes yet',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFilterChips() {
    return Container(
      height: 60,
      padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 16),
      child: ListView(
        scrollDirection: Axis.horizontal,
        children: [
          FilterChip(
            label: const Text('All'),
            selected: _selectedFilter == 'all',
            onSelected: (selected) {
              setState(() {
                _selectedFilter = 'all';
              });
              _refreshEpisodes();
            },
          ),
          const SizedBox(width: 8),
          FilterChip(
            label: const Text('Unplayed'),
            selected: _selectedFilter == 'unplayed',
            onSelected: (selected) {
              setState(() {
                _selectedFilter = 'unplayed';
              });
              _refreshEpisodes();
            },
          ),
          const SizedBox(width: 8),
          FilterChip(
            label: const Text('Played'),
            selected: _selectedFilter == 'played',
            onSelected: (selected) {
              setState(() {
                _selectedFilter = 'played';
              });
              _refreshEpisodes();
            },
          ),
          const SizedBox(width: 8),
          FilterChip(
            label: const Text('With AI Summary'),
            selected: _showOnlyWithSummary,
            onSelected: (selected) {
              setState(() {
                _showOnlyWithSummary = selected;
              });
              _refreshEpisodes();
            },
            avatar: _showOnlyWithSummary
                ? const Icon(Icons.summarize, size: 16)
                : null,
          ),
        ],
      ),
    );
  }

  Widget _buildErrorState(Object error) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.error_outline,
            size: 80,
            color: Theme.of(context).colorScheme.error,
          ),
          const SizedBox(height: 16),
          Text(
            'Failed to Load Episodes',
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
              color: Theme.of(context).colorScheme.error,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            error.toString(),
            style: Theme.of(context).textTheme.bodyMedium,
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 32),
          ElevatedButton.icon(
            onPressed: _refreshEpisodes,
            icon: const Icon(Icons.refresh),
            label: const Text('Retry'),
          ),
        ],
      ),
    );
  }

  void _showFilterDialog() {
    showDialog(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: const Text('Filter Episodes'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Playback Status:'),
              const SizedBox(height: 8),
              RadioGroup<String>(
                groupValue: _selectedFilter,
                onChanged: (value) {
                  if (value != null) {
                    setDialogState(() {
                      _selectedFilter = value;
                    });
                  }
                },
                child: Column(
                  children: [
                    RadioListTile<String>(
                      title: const Text('All Episodes'),
                      value: 'all',
                    ),
                    RadioListTile<String>(
                      title: const Text('Unplayed Only'),
                      value: 'unplayed',
                    ),
                    RadioListTile<String>(
                      title: const Text('Played Only'),
                      value: 'played',
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
              CheckboxListTile(
                title: const Text('Only episodes with AI Summary'),
                value: _showOnlyWithSummary,
                onChanged: (value) {
                  setDialogState(() {
                    _showOnlyWithSummary = value!;
                  });
                },
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Cancel'),
            ),
            TextButton(
              onPressed: () {
                Navigator.of(context).pop();
                setState(() {});
                _refreshEpisodes();
              },
              child: const Text('Apply'),
            ),
          ],
        ),
      ),
    );
  }
}