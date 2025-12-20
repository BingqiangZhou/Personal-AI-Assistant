import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../providers/podcast_providers.dart';
import '../widgets/podcast_episode_card.dart';
import '../widgets/podcast_feed_shimmer.dart';
import '../widgets/empty_feed_widget.dart';
import '../widgets/feed_error_widget.dart';

class PodcastFeedPage extends ConsumerStatefulWidget {
  const PodcastFeedPage({super.key});

  @override
  ConsumerState<PodcastFeedPage> createState() => _PodcastFeedPageState();
}

class _PodcastFeedPageState extends ConsumerState<PodcastFeedPage>
    with AutomaticKeepAliveClientMixin {
  final ScrollController _scrollController = ScrollController();

  @override
  bool get wantKeepAlive => true;

  @override
  void initState() {
    super.initState();

    _scrollController.addListener(_onScroll);

    // Load initial feed
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(podcastFeedProvider.notifier).loadInitialFeed();
    });
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  void _onScroll() {
    if (!_scrollController.hasClients) return;

    final maxScroll = _scrollController.position.maxScrollExtent;
    final currentScroll = _scrollController.position.pixels;
    final threshold = maxScroll * 0.8; // Load more when 80% scrolled

    if (currentScroll >= threshold) {
      final notifier = ref.read(podcastFeedProvider.notifier);
      final state = ref.read(podcastFeedProvider);

      if (state.hasMore && !state.isLoadingMore && !state.isLoading) {
        notifier.loadMoreFeed();
      }
    }
  }

  Future<void> _refresh() async {
    await ref.read(podcastFeedProvider.notifier).refreshFeed();
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final feedState = ref.watch(podcastFeedProvider);

    // Error state
    if (feedState.error != null && feedState.episodes.isEmpty) {
      return Scaffold(
        appBar: AppBar(
          title: Text(
            '信息流',
            style: Theme.of(context).textTheme.titleLarge?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          centerTitle: true,
        ),
        body: FeedErrorWidget(
          error: feedState.error!,
          onRetry: _refresh,
        ),
      );
    }

    // Empty state
    if (!feedState.isLoading &&
        feedState.episodes.isEmpty &&
        feedState.error == null) {
      return Scaffold(
        appBar: AppBar(
          title: Text(
            '信息流',
            style: Theme.of(context).textTheme.titleLarge?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
          centerTitle: true,
        ),
        body: const EmptyFeedWidget(),
      );
    }

    return Scaffold(
      body: RefreshIndicator(
        onRefresh: _refresh,
        child: CustomScrollView(
          controller: _scrollController,
          slivers: [
            // Header
            SliverAppBar(
              floating: true,
              snap: true,
              backgroundColor: Theme.of(context).scaffoldBackgroundColor,
              elevation: 0,
              title: Text(
                '信息流',
                style: Theme.of(context).textTheme.titleLarge?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
              ),
              centerTitle: true,
            ),

            // Loading shimmer (initial load)
            if (feedState.isLoading && feedState.episodes.isEmpty)
              const SliverFillRemaining(
                child: PodcastFeedShimmer(),
              ),

            // Episodes list
            if (feedState.episodes.isNotEmpty)
              SliverList(
                delegate: SliverChildBuilderDelegate(
                  (context, index) {
                    if (index >= feedState.episodes.length) {
                      return null; // Should not happen
                    }

                    final episode = feedState.episodes[index];
                    return PodcastEpisodeCard(
                      episode: episode,
                      onTap: () {
                        // Navigate to episode detail
                        // TODO: Implement navigation
                      },
                      onPlay: () {
                        // Play episode
                        // TODO: Implement play functionality
                      },
                    );
                  },
                  childCount: feedState.episodes.length,
                ),
              ),

            // Loading more indicator
            if (feedState.isLoadingMore && feedState.episodes.isNotEmpty)
              const SliverToBoxAdapter(
                child: Padding(
                  padding: EdgeInsets.all(16.0),
                  child: Center(
                    child: CircularProgressIndicator(),
                  ),
                ),
              ),

            // End of content indicator
            if (!feedState.hasMore && feedState.episodes.isNotEmpty)
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Center(
                    child: Text(
                      '已加载全部内容',
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Colors.grey[500],
                      ),
                    ),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}