import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/podcast_providers.dart';
import '../widgets/podcast_episode_card.dart';
import '../widgets/podcast_feed_shimmer.dart';
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
    if (!_scrollController.hasClients) {
      return;
    }

    final maxScroll = _scrollController.position.maxScrollExtent;
    final currentScroll = _scrollController.position.pixels;

    // 当滚动到距离底部300px时触发加载更多
    // 修复: 确保threshold不为负值
    final threshold = maxScroll > 300 ? maxScroll - 300.0 : maxScroll * 0.8;

    // debugPrint('📏 滚动位置: current=$currentScroll, max=$maxScroll, threshold=$threshold, diff=${maxScroll - currentScroll}');

    // 修复: 添加更多调试信息
    if (currentScroll >= threshold) {
      debugPrint('✅ 达到阈值，准备加载更多...');
      final notifier = ref.read(podcastFeedProvider.notifier);
      final state = ref.read(podcastFeedProvider);

      debugPrint('📊 当前状态: hasMore=${state.hasMore}, isLoadingMore=${state.isLoadingMore}, isLoading=${state.isLoading}, nextPage=${state.nextPage}');
      debugPrint('📊 episodes数量: ${state.episodes.length}, total: ${state.total}');

      // 防抖处理，避免重复触发
      if (state.hasMore && !state.isLoadingMore && !state.isLoading) {
        debugPrint('🚀 触发加载更多内容...');
        notifier.loadMoreFeed();
        debugPrint('✅ loadMoreFeed()已调用');
      } else {
        debugPrint('🚫 加载被阻止，条件不满足: hasMore=${state.hasMore}, isLoadingMore=${state.isLoadingMore}, isLoading=${state.isLoading}');
      }
    }
  }

  Future<void> _refresh() async {
    await ref.read(podcastFeedProvider.notifier).refreshFeed();
  }

  void _clearError() {
    ref.read(podcastFeedProvider.notifier).clearError();
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final theme = Theme.of(context);
    final feedState = ref.watch(podcastFeedProvider);

    // Determine what to display
    Widget bodyContent;

    if (feedState.error != null && feedState.episodes.isEmpty) {
      // Error state
      bodyContent = FeedErrorWidget(
        error: feedState.error!,
        onRetry: _refresh,
      );
    } else if (!feedState.isLoading &&
        feedState.episodes.isEmpty &&
        feedState.error == null) {
      // Empty state - enhanced styling to match podcast list page
      final theme = Theme.of(context);
      bodyContent = Center(
        child: Container(
          padding: const EdgeInsets.all(32),
          margin: const EdgeInsets.all(24),
          decoration: BoxDecoration(
            color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color: theme.dividerColor.withValues(alpha: 0.5),
              width: 1,
            ),
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                padding: const EdgeInsets.all(24),
                decoration: BoxDecoration(
                  color: theme.primaryColor.withValues(alpha: 0.1),
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: theme.primaryColor.withValues(alpha: 0.3),
                    width: 2,
                  ),
                ),
                child: Icon(
                  Icons.feed_outlined,
                  size: 80,
                  color: theme.primaryColor.withValues(alpha: 0.8),
                ),
              ),
              const SizedBox(height: 24),
              Text(
                'No Feed Content',
                style: theme.textTheme.headlineSmall?.copyWith(
                  color: theme.colorScheme.onSurface,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 12),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: theme.dividerColor.withValues(alpha: 0.3),
                    width: 1,
                  ),
                ),
                child: Text(
                  'Subscribe to podcasts to see your feed',
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  textAlign: TextAlign.center,
                ),
              ),
              const SizedBox(height: 32),
              Container(
                decoration: BoxDecoration(
                  color: theme.primaryColor,
                  borderRadius: BorderRadius.circular(8),
                  boxShadow: [
                    BoxShadow(
                      color: theme.primaryColor.withValues(alpha: 0.3),
                      blurRadius: 8,
                      offset: const Offset(0, 4),
                    ),
                  ],
                  border: Border.all(
                    color: theme.primaryColor.withValues(alpha: 0.5),
                    width: 1,
                  ),
                ),
                child: ElevatedButton.icon(
                  onPressed: _refresh,
                  icon: const Icon(Icons.refresh),
                  label: const Text('Refresh Feed'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.transparent,
                    foregroundColor: theme.colorScheme.onPrimary,
                    shadowColor: Colors.transparent,
                    padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                  ),
                ),
              ),
            ],
          ),
        ),
      );
    } else {
      // Normal content with loading state
      bodyContent = RefreshIndicator(
        onRefresh: _refresh,
        child: CustomScrollView(
          controller: _scrollController,
          physics: const AlwaysScrollableScrollPhysics(), // 确保滚动事件可以被检测
          slivers: [
            SliverAppBar(
              title: Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                decoration: BoxDecoration(
                  color: theme.colorScheme.primary.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: theme.colorScheme.primary.withValues(alpha: 0.3),
                    width: 1,
                  ),
                ),
                child: Text(
                  'Feed',
                  style: TextStyle(
                    color: theme.colorScheme.primary,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              backgroundColor: theme.colorScheme.surface,
              elevation: 2,
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
                    final episode = feedState.episodes[index];
                    return PodcastEpisodeCard(
                      episode: episode,
                      onTap: () {
                        context.push('/podcast/episode/detail/${episode.id}');
                      },
                      // onPlay removed - play only available in detail page
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
            // Load more error indicator
            if (feedState.error != null && feedState.episodes.isNotEmpty)
              SliverToBoxAdapter(
                child: Container(
                  margin: const EdgeInsets.all(16),
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: theme.colorScheme.errorContainer.withValues(alpha: 0.3),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: theme.colorScheme.error.withValues(alpha: 0.3),
                      width: 1,
                    ),
                  ),
                  child: Row(
                    children: [
                      Icon(
                        Icons.error_outline,
                        color: theme.colorScheme.error,
                        size: 24,
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Load failed: ${feedState.error}',
                              style: theme.textTheme.bodyMedium?.copyWith(
                                color: theme.colorScheme.error,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                            const SizedBox(height: 4),
                            Text(
                              'Tap retry to load more',
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: theme.colorScheme.error.withValues(alpha: 0.7),
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 8),
                      TextButton.icon(
                        onPressed: () {
                          _clearError();
                          ref.read(podcastFeedProvider.notifier).loadMoreFeed();
                        },
                        icon: const Icon(Icons.refresh, size: 16),
                        label: const Text('Retry'),
                        style: TextButton.styleFrom(
                          foregroundColor: theme.colorScheme.error,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            // End of content indicator
            if (!feedState.hasMore && feedState.episodes.isNotEmpty)
              SliverToBoxAdapter(
                child: Container(
                  margin: const EdgeInsets.all(16),
                  padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 16),
                  decoration: BoxDecoration(
                    color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: theme.dividerColor.withValues(alpha: 0.3),
                      width: 1,
                    ),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(
                        Icons.check_circle_outline,
                        size: 16,
                        color: theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.6),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        'All content loaded',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
          ],
        ),
      );
    }

    return Scaffold(
      body: bodyContent,
    );
  }
}