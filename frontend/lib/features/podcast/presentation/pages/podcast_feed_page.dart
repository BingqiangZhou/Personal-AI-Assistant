import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../../../core/widgets/top_floating_notice.dart';
import '../../data/models/podcast_episode_model.dart';
import '../navigation/podcast_navigation.dart';
import '../providers/podcast_providers.dart';
import '../../core/utils/episode_description_helper.dart';
import '../widgets/podcast_image_widget.dart';

/// Material Design 3自适应Feed页面
class PodcastFeedPage extends ConsumerStatefulWidget {
  const PodcastFeedPage({super.key});

  @override
  ConsumerState<PodcastFeedPage> createState() => _PodcastFeedPageState();
}

class _PodcastFeedPageState extends ConsumerState<PodcastFeedPage> {
  final Set<int> _addingEpisodeIds = <int>{};

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(podcastFeedProvider.notifier).loadInitialFeed();
    });
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
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
                    l10n.podcast_feed_page_title,
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                IconButton(
                  onPressed: () {
                    context.push('/profile/subscriptions');
                  },
                  icon: const Icon(Icons.subscriptions_outlined),
                  tooltip: l10n.profile_subscriptions,
                ),
              ],
            ),
          ),

          const SizedBox(height: 4),

          // Feed内容 - 直接使用Expanded填充剩余空间
          Expanded(child: _buildFeedContent(context)),
        ],
      ),
    );
  }

  /// 构建Feed内容
  Future<void> _addToQueue(PodcastEpisodeModel episode) async {
    if (_addingEpisodeIds.contains(episode.id)) {
      return;
    }
    setState(() {
      _addingEpisodeIds.add(episode.id);
    });

    try {
      await ref
          .read(podcastQueueControllerProvider.notifier)
          .addToQueue(episode.id);
      if (mounted) {
        final l10n = AppLocalizations.of(context)!;
        showTopFloatingNotice(
          context,
          message: l10n.added_to_queue,
          extraTopOffset: 64,
        );
      }
    } catch (error) {
      if (mounted) {
        final l10n = AppLocalizations.of(context)!;
        showTopFloatingNotice(
          context,
          message: l10n.failed_to_add_to_queue(error.toString()),
          isError: true,
          extraTopOffset: 64,
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _addingEpisodeIds.remove(episode.id);
        });
      }
    }
  }

  Widget _buildFeedContent(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
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
            Text('${l10n.podcast_failed_to_load_feed}: ${feedState.error}'),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: () {
                ref.read(podcastFeedProvider.notifier).loadInitialFeed();
              },
              child: Text(l10n.podcast_retry),
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
            Text(
              l10n.podcast_no_episodes_found,
              style: Theme.of(context).textTheme.titleLarge,
            ),
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
              padding: const EdgeInsets.symmetric(vertical: 4),
              itemCount:
                  feedState.episodes.length + (feedState.hasMore ? 1 : 0),
              itemBuilder: (context, index) {
                if (index >= feedState.episodes.length) {
                  // Loading more indicator
                  Future.microtask(
                    () => ref.read(podcastFeedProvider.notifier).loadMoreFeed(),
                  );
                  return const Center(
                    child: Padding(
                      padding: EdgeInsets.all(8.0),
                      child: CircularProgressIndicator(),
                    ),
                  );
                }
                return _buildMobileCard(context, feedState.episodes[index]);
              },
            ),
          );
        }

        // 桌面端：使用GridView，优化卡片高度
        final crossAxisCount = screenWidth < 900
            ? 2
            : (screenWidth < 1200 ? 3 : 4);
        final horizontalPadding =
            0.0; // ResponsiveContainer handles padding? Checking...
        // ResponsiveContainer has default padding, so we might not need extra.
        // But GridView needs spacing.
        final spacing = 6.0;
        final availableWidth =
            screenWidth - horizontalPadding - (crossAxisCount - 1) * spacing;
        final cardWidth = availableWidth / crossAxisCount;

        // 优化宽高比：卡片内容高度约180-200，确保不溢出
        const desktopCardHeight = 172.0;
        final childAspectRatio = cardWidth / desktopCardHeight;

        return RefreshIndicator(
          onRefresh: () async {
            await ref.read(podcastFeedProvider.notifier).refreshFeed();
          },
          child: GridView.builder(
            padding: const EdgeInsets.symmetric(vertical: 4),
            gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: crossAxisCount,
              crossAxisSpacing: spacing,
              mainAxisSpacing: spacing,
              childAspectRatio: childAspectRatio,
            ),
            itemCount: feedState
                .episodes
                .length, // Grid infinite scroll is harder, skipping for MVP-ish
            itemBuilder: (context, index) {
              if (index == feedState.episodes.length - 1 && feedState.hasMore) {
                Future.microtask(
                  () => ref.read(podcastFeedProvider.notifier).loadMoreFeed(),
                );
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
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final isAddingToQueue = _addingEpisodeIds.contains(episode.id);
    // Get display description: AI summary main topics or plain shownotes
    final displayDescription = EpisodeDescriptionHelper.getDisplayDescription(
      aiSummary: episode.aiSummary,
      description: episode.description,
    );
    final titleStyle = theme.textTheme.titleMedium?.copyWith(
      fontWeight: FontWeight.w600,
      fontSize: 13,
    );
    final titleFontSize = titleStyle?.fontSize ?? 13;
    final titleLineHeightFactor = titleStyle?.height ?? 1.0;
    final coverSize = 2 * (titleFontSize * titleLineHeightFactor);
    final coverIconSize = (coverSize * 0.58).clamp(14.0, 28.0).toDouble();

    void playAndOpenDetail() {
      ref.read(audioPlayerProvider.notifier).playEpisode(episode);
      PodcastNavigation.goToEpisodeDetail(
        context,
        episodeId: episode.id,
        subscriptionId: episode.subscriptionId,
        episodeTitle: episode.title,
      );
    }

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 4, vertical: 6),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
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
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                key: const Key('podcast_feed_mobile_header_row'),
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Material(
                    color: Colors.transparent,
                    child: InkWell(
                      onTap: playAndOpenDetail,
                      borderRadius: BorderRadius.circular(8),
                      child: Container(
                        key: const Key('podcast_feed_mobile_cover'),
                        width: coverSize,
                        height: coverSize,
                        decoration: BoxDecoration(
                          color: theme.colorScheme.primaryContainer,
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: ClipRRect(
                          borderRadius: BorderRadius.circular(8),
                          child: PodcastImageWidget(
                            imageUrl:
                                episode.imageUrl ??
                                episode.subscriptionImageUrl,
                            width: coverSize,
                            height: coverSize,
                            iconSize: coverIconSize,
                            iconColor: theme.colorScheme.onPrimaryContainer,
                          ),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: SizedBox(
                      height: coverSize,
                      child: Align(
                        alignment: Alignment.centerLeft,
                        child: Text(
                          episode.title,
                          style: titleStyle,
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
              if (displayDescription.isNotEmpty) ...[
                const SizedBox(height: 8),
                Text(
                  key: const Key('podcast_feed_mobile_description'),
                  displayDescription,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 4),
              ] else ...[
                const SizedBox(height: 4),
              ],
              Row(
                key: const Key('podcast_feed_mobile_meta_action_row'),
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Expanded(
                    child: Align(
                      alignment: Alignment.centerLeft,
                      child: FittedBox(
                        fit: BoxFit.scaleDown,
                        alignment: Alignment.centerLeft,
                        child: Row(
                          key: const Key('podcast_feed_mobile_metadata'),
                          mainAxisSize: MainAxisSize.min,
                          crossAxisAlignment: CrossAxisAlignment.center,
                          children: [
                            ConstrainedBox(
                              constraints: const BoxConstraints(maxWidth: 112),
                              child: Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 8,
                                  vertical: 2,
                                ),
                                decoration: BoxDecoration(
                                  color: theme.colorScheme.primary,
                                  borderRadius: BorderRadius.circular(10),
                                ),
                                child: Text(
                                  episode.subscriptionTitle ??
                                      l10n.podcast_default_podcast,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  style: theme.textTheme.labelSmall?.copyWith(
                                    color: theme.colorScheme.onPrimary,
                                    fontWeight: FontWeight.bold,
                                    fontSize: 10,
                                  ),
                                ),
                              ),
                            ),
                            const SizedBox(width: 8),
                            Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  Icons.calendar_today_outlined,
                                  size: 13,
                                  color: theme.colorScheme.onSurfaceVariant,
                                ),
                                const SizedBox(width: 3),
                                Text(
                                  _formatDate(episode.publishedAt),
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: theme.colorScheme.onSurfaceVariant,
                                    fontSize: 11,
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(width: 8),
                            Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  Icons.schedule,
                                  size: 13,
                                  color: theme.colorScheme.onSurfaceVariant,
                                ),
                                const SizedBox(width: 3),
                                Text(
                                  episode.formattedDuration,
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: theme.colorScheme.onSurfaceVariant,
                                    fontSize: 11,
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 6),
                  IconButton(
                    key: const Key('podcast_feed_mobile_add_to_queue'),
                    tooltip: isAddingToQueue
                        ? l10n.podcast_adding
                        : l10n.podcast_add_to_queue,
                    onPressed: isAddingToQueue
                        ? null
                        : () => _addToQueue(episode),
                    style: IconButton.styleFrom(
                      minimumSize: const Size(28, 28),
                      maximumSize: const Size(28, 28),
                      tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                      visualDensity: VisualDensity.compact,
                      padding: EdgeInsets.zero,
                      foregroundColor: theme.colorScheme.onSurfaceVariant,
                    ),
                    icon: isAddingToQueue
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.playlist_add, size: 18),
                  ),
                  const SizedBox(width: 10),
                  IconButton(
                    key: const Key('podcast_feed_mobile_play'),
                    tooltip: l10n.podcast_play,
                    onPressed: playAndOpenDetail,
                    style: IconButton.styleFrom(
                      minimumSize: const Size(28, 28),
                      maximumSize: const Size(28, 28),
                      tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                      visualDensity: VisualDensity.compact,
                      padding: EdgeInsets.zero,
                      foregroundColor: theme.colorScheme.primary,
                      shape: const CircleBorder(),
                      side: BorderSide(
                        color: theme.colorScheme.primary.withValues(
                          alpha: 0.65,
                        ),
                        width: 1,
                      ),
                    ),
                    icon: const Icon(Icons.play_arrow, size: 18),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  /// 构建桌面端卡片（使用小图标布局）
  Widget _buildDesktopCard(BuildContext context, PodcastEpisodeModel episode) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final isAddingToQueue = _addingEpisodeIds.contains(episode.id);
    final displayDescription = EpisodeDescriptionHelper.getDisplayDescription(
      aiSummary: episode.aiSummary,
      description: episode.description,
    );
    final titleStyle = theme.textTheme.titleMedium?.copyWith(
      fontWeight: FontWeight.w600,
      fontSize: 13,
    );
    final titleFontSize = titleStyle?.fontSize ?? 13;
    final titleLineHeightFactor = titleStyle?.height ?? 1.0;
    final coverSize = 2 * (titleFontSize * titleLineHeightFactor);
    final coverIconSize = (coverSize * 0.58).clamp(14.0, 28.0).toDouble();

    void playAndOpenDetail() {
      ref.read(audioPlayerProvider.notifier).playEpisode(episode);
      PodcastNavigation.goToEpisodeDetail(
        context,
        episodeId: episode.id,
        subscriptionId: episode.subscriptionId,
        episodeTitle: episode.title,
      );
    }

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
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                key: const Key('podcast_feed_desktop_header_row'),
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Container(
                    width: coverSize,
                    height: coverSize,
                    decoration: BoxDecoration(
                      color: theme.colorScheme.primaryContainer,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(8),
                      child: PodcastImageWidget(
                        imageUrl:
                            episode.imageUrl ?? episode.subscriptionImageUrl,
                        width: coverSize,
                        height: coverSize,
                        iconSize: coverIconSize,
                        iconColor: theme.colorScheme.onPrimaryContainer,
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: SizedBox(
                      height: coverSize,
                      child: Align(
                        alignment: Alignment.centerLeft,
                        child: Text(
                          episode.title,
                          style: titleStyle,
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
              if (displayDescription.isNotEmpty) ...[
                const SizedBox(height: 8),
                Text(
                  key: const Key('podcast_feed_desktop_description'),
                  displayDescription,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  maxLines: 4,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 4),
              ] else ...[
                const SizedBox(height: 4),
              ],
              Row(
                key: const Key('podcast_feed_desktop_meta_action_row'),
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Expanded(
                    child: Align(
                      alignment: Alignment.centerLeft,
                      child: FittedBox(
                        fit: BoxFit.scaleDown,
                        alignment: Alignment.centerLeft,
                        child: Row(
                          key: const Key('podcast_feed_desktop_metadata'),
                          mainAxisSize: MainAxisSize.min,
                          crossAxisAlignment: CrossAxisAlignment.center,
                          children: [
                            ConstrainedBox(
                              constraints: const BoxConstraints(maxWidth: 140),
                              child: Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 10,
                                  vertical: 3,
                                ),
                                decoration: BoxDecoration(
                                  color: theme.colorScheme.primary,
                                  borderRadius: BorderRadius.circular(12),
                                ),
                                child: Text(
                                  episode.subscriptionTitle ??
                                      l10n.podcast_default_podcast,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  style: theme.textTheme.labelSmall?.copyWith(
                                    color: theme.colorScheme.onPrimary,
                                    fontWeight: FontWeight.bold,
                                    fontSize: 11,
                                  ),
                                ),
                              ),
                            ),
                            const SizedBox(width: 8),
                            Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  Icons.calendar_today_outlined,
                                  size: 13,
                                  color: theme.colorScheme.onSurfaceVariant,
                                ),
                                const SizedBox(width: 2),
                                Text(
                                  _formatDate(episode.publishedAt),
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: theme.colorScheme.onSurfaceVariant,
                                    fontSize: 11,
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(width: 8),
                            Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  Icons.schedule,
                                  size: 13,
                                  color: theme.colorScheme.onSurfaceVariant,
                                ),
                                const SizedBox(width: 2),
                                Text(
                                  episode.formattedDuration,
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: theme.colorScheme.onSurfaceVariant,
                                    fontSize: 11,
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 6),
                  IconButton(
                    key: const Key('podcast_feed_desktop_add_to_queue'),
                    tooltip: isAddingToQueue
                        ? l10n.podcast_adding
                        : l10n.podcast_add_to_queue,
                    onPressed: isAddingToQueue
                        ? null
                        : () => _addToQueue(episode),
                    style: IconButton.styleFrom(
                      minimumSize: const Size(28, 28),
                      maximumSize: const Size(28, 28),
                      tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                      visualDensity: VisualDensity.compact,
                      padding: EdgeInsets.zero,
                      foregroundColor: theme.colorScheme.onSurfaceVariant,
                    ),
                    icon: isAddingToQueue
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.playlist_add, size: 18),
                  ),
                  const SizedBox(width: 10),
                  IconButton(
                    key: const Key('podcast_feed_desktop_play'),
                    tooltip: l10n.podcast_play,
                    onPressed: playAndOpenDetail,
                    style: IconButton.styleFrom(
                      minimumSize: const Size(28, 28),
                      maximumSize: const Size(28, 28),
                      tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                      visualDensity: VisualDensity.compact,
                      padding: EdgeInsets.zero,
                      foregroundColor: theme.colorScheme.primary,
                      shape: const CircleBorder(),
                      side: BorderSide(
                        color: theme.colorScheme.primary.withValues(
                          alpha: 0.65,
                        ),
                        width: 1,
                      ),
                    ),
                    icon: const Icon(Icons.play_arrow, size: 18),
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

String _formatDate(DateTime date) {
  final localDate = date.isUtc ? date.toLocal() : date;
  return '${localDate.year}-${localDate.month.toString().padLeft(2, '0')}-${localDate.day.toString().padLeft(2, '0')}';
}
