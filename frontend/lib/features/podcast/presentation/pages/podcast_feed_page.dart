import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../data/models/podcast_episode_model.dart';
import '../navigation/podcast_navigation.dart';
import '../providers/podcast_providers.dart';

/// Material Design 3自适应Feed页面
class PodcastFeedPage extends ConsumerStatefulWidget {
  const PodcastFeedPage({super.key});

  @override
  ConsumerState<PodcastFeedPage> createState() => _PodcastFeedPageState();
}

class _PodcastFeedPageState extends ConsumerState<PodcastFeedPage> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(podcastFeedProvider.notifier).loadInitialFeed();
    });
  }

  @override
  Widget build(BuildContext context) {
    return ResponsiveContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // 页面标题
          SizedBox(
            height: 56,
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    'Feed',
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                  ),
                ),
                IconButton(onPressed: () {
                  ref.read(podcastFeedProvider.notifier).refreshFeed();
                }, icon: const Icon(Icons.refresh))
              ],
            ),
          ),
          const SizedBox(height: 24),

          // Feed内容 - 直接使用Expanded填充剩余空间
          Expanded(
            child: _buildFeedContent(context),
          ),
        ],
      ),
    );
  }

  /// 构建Feed内容
  Widget _buildFeedContent(BuildContext context) {
    final feedState = ref.watch(podcastFeedProvider);

    if (feedState.isLoading && feedState.episodes.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    if (feedState.error != null && feedState.episodes.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 48, color: Colors.orange),
            const SizedBox(height: 16),
            Text('Failed to load feed: ${feedState.error}'),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: () {
                ref.read(podcastFeedProvider.notifier).loadInitialFeed();
              },
              child: const Text('Retry'),
            ),
          ],
        ),
      );
    }

    if (feedState.episodes.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.rss_feed, size: 64, color: Colors.grey),
            const SizedBox(height: 16),
            Text('No episodes found', style: Theme.of(context).textTheme.titleLarge),
          ],
        ),
      );
    }

    // 使用LayoutBuilder来动态调整布局
    return LayoutBuilder(
      builder: (context, constraints) {
        final screenWidth = constraints.maxWidth;

        // 移动端：使用ListView
        if (screenWidth < 600) {
          return RefreshIndicator(
            onRefresh: () async {
              await ref.read(podcastFeedProvider.notifier).refreshFeed();
            },
            child: ListView.builder(
              padding: const EdgeInsets.symmetric(vertical: 12),
              itemCount: feedState.episodes.length + (feedState.hasMore ? 1 : 0),
              itemBuilder: (context, index) {
                if (index >= feedState.episodes.length) {
                  // Loading more indicator
                  Future.microtask(() => ref.read(podcastFeedProvider.notifier).loadMoreFeed());
                  return const Center(child: Padding(
                    padding: EdgeInsets.all(8.0),
                    child: CircularProgressIndicator(),
                  ));
                }
                return _buildMobileCard(context, feedState.episodes[index]);
              },
            ),
          );
        }

        // 桌面端：使用GridView，优化卡片高度
        final crossAxisCount = screenWidth < 900 ? 2 : (screenWidth < 1200 ? 3 : 4);
        final horizontalPadding = 0.0; // ResponsiveContainer handles padding? Checking...
        // ResponsiveContainer has default padding, so we might not need extra. 
        // But GridView needs spacing.
        final spacing = 16.0;
        final availableWidth = screenWidth - horizontalPadding - (crossAxisCount - 1) * spacing;
        final cardWidth = availableWidth / crossAxisCount;

        // 优化宽高比：卡片内容高度约180-200，确保不溢出
        final childAspectRatio = cardWidth / 210;

        return RefreshIndicator(
          onRefresh: () async {
            await ref.read(podcastFeedProvider.notifier).refreshFeed();
          },
          child: GridView.builder(
            padding: const EdgeInsets.symmetric(vertical: 12),
            gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: crossAxisCount,
              crossAxisSpacing: spacing,
              mainAxisSpacing: spacing,
              childAspectRatio: childAspectRatio,
            ),
            itemCount: feedState.episodes.length, // Grid infinite scroll is harder, skipping for MVP-ish
            itemBuilder: (context, index) {
               if (index == feedState.episodes.length - 1 && feedState.hasMore) {
                  Future.microtask(() => ref.read(podcastFeedProvider.notifier).loadMoreFeed());
               }
              return _buildDesktopCard(context, feedState.episodes[index]);
            },
          ),
        );
      },
    );
  }

  /// 构建移动端卡片
  Widget _buildMobileCard(BuildContext context, PodcastEpisodeModel episode) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      child: InkWell(
        onTap: () {
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
                  // 播放按钮
                  // 播放按钮
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
                  // 标题和信息
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          episode.title,
                          style: Theme.of(context).textTheme.titleMedium?.copyWith(
                                fontWeight: FontWeight.w600,
                              ),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 12),
                        Wrap(
                          spacing: 12,
                          runSpacing: 8,
                          crossAxisAlignment: WrapCrossAlignment.center,
                          children: [
                            // 播客名 (圆角框)
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
                              decoration: BoxDecoration(
                                color: Theme.of(context).colorScheme.primary,
                                borderRadius: BorderRadius.circular(12),
                              ),
                              child: Text(
                                episode.subscriptionTitle ?? 'Podcast',
                                style: Theme.of(context).textTheme.labelSmall?.copyWith(
                                      color: Theme.of(context).colorScheme.onPrimary,
                                      fontWeight: FontWeight.bold,
                                      fontSize: 10,
                                    ),
                              ),
                            ),
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
                            Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  Icons.access_time,
                                  size: 16,
                                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                                ),
                                const SizedBox(width: 4),
                                Text(
                                  _formatDate(episode.publishedAt),
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
              // 操作按钮 - 使用Wrap避免溢出
              Wrap(
                alignment: WrapAlignment.end,
                spacing: 8,
                runSpacing: 8,
                children: [
                  IconButton.filled(
                    onPressed: () {
                      // TODO: 实现收藏功能
                    },
                    icon: const Icon(Icons.bookmark_border),
                    tooltip: 'Bookmark',
                    style: IconButton.styleFrom(
                      backgroundColor: Theme.of(context).colorScheme.surfaceContainerHighest,
                      foregroundColor: Theme.of(context).colorScheme.onSurfaceVariant,
                      minimumSize: const Size(40, 40),
                      padding: const EdgeInsets.all(8),
                    ),
                  ),
                  IconButton.filled(
                    onPressed: () {
                      // TODO: 实现分享功能
                    },
                    icon: const Icon(Icons.share),
                    tooltip: 'Share',
                    style: IconButton.styleFrom(
                      backgroundColor: Theme.of(context).colorScheme.surfaceContainerHighest,
                      foregroundColor: Theme.of(context).colorScheme.onSurfaceVariant,
                      minimumSize: const Size(40, 40),
                      padding: const EdgeInsets.all(8),
                    ),
                  ),
                  FilledButton.tonal(
                    onPressed: () {
                      PodcastNavigation.goToEpisodeDetail(
                        context,
                        episodeId: episode.id,
                        subscriptionId: episode.subscriptionId,
                        episodeTitle: episode.title,
                      );
                    },
                    child: const Text('Play'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  String _formatDate(DateTime date) {
    return '${date.year}-${date.month.toString().padLeft(2, '0')}-${date.day.toString().padLeft(2, '0')}';
  }

  /// 构建桌面端卡片（优化布局，避免溢出）
  Widget _buildDesktopCard(BuildContext context, PodcastEpisodeModel episode) {
    return Card(
      child: InkWell(
        onTap: () {
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
              // 第一行：播放按钮 + 标题信息
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // 播放按钮
                  Container(
                    width: 44,
                    height: 44,
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
                                size: 22,
                              ),
                            )
                          : Icon(
                              episode.isPlayed ? Icons.play_arrow : Icons.play_circle_filled,
                              color: Theme.of(context).colorScheme.onPrimaryContainer,
                              size: 22,
                            ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  // 标题和信息
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          episode.title,
                          style: Theme.of(context).textTheme.titleMedium?.copyWith(
                                fontWeight: FontWeight.w600,
                                fontSize: 16,
                              ),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                ],
              ),

              // 描述
              if (episode.description != null) ...[
                const SizedBox(height: 8),
                Text(
                  episode.description!,
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                  maxLines: 4,
                  overflow: TextOverflow.ellipsis,
                ),
              ],

              // 元数据和操作按钮
              const SizedBox(height: 12),
              Row(
                children: [
                  // 时间信息
                  Expanded(
                    child: Wrap(
                      spacing: 12,
                      runSpacing: 8,
                      crossAxisAlignment: WrapCrossAlignment.center,
                      children: [
                        // 播客名 (圆角框)
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
                          decoration: BoxDecoration(
                            color: Theme.of(context).colorScheme.primary,
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: Text(
                            episode.subscriptionTitle ?? 'Podcast',
                            style: Theme.of(context).textTheme.labelSmall?.copyWith(
                                  color: Theme.of(context).colorScheme.onPrimary,
                                  fontWeight: FontWeight.bold,
                                  fontSize: 10,
                                ),
                          ),
                        ),
                        // 时长
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.schedule,
                              size: 13,
                              color: Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 2),
                            Text(
                              episode.formattedDuration,
                              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                                    fontSize: 11,
                                  ),
                            ),
                          ],
                        ),
                        // 日期
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.access_time,
                              size: 13,
                              color: Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 2),
                            Text(
                              _formatDate(episode.publishedAt),
                              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                                    fontSize: 11,
                                  ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),

                  // Play 按钮
                  const SizedBox(width: 8),
                  FilledButton.tonal(
                    onPressed: () {
                      ref.read(audioPlayerProvider.notifier).playEpisode(episode);
                    },
                    child: const Text('Play'),
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