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

/// Material Design 3鑷€傚簲Feed椤甸潰
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
          // 椤甸潰鏍囬
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

          // Feed鍐呭 - 鐩存帴浣跨敤Expanded濉厖鍓╀綑绌洪棿
          Expanded(child: _buildFeedContent(context)),
        ],
      ),
    );
  }

  /// 鏋勫缓Feed鍐呭
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

  Widget _buildDailyReportEntryTile(
    BuildContext context, {
    required bool compact,
  }) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);

    return Semantics(
      button: true,
      label: l10n.podcast_daily_report_open,
      child: Tooltip(
        message: l10n.podcast_daily_report_open,
        child: Material(
          key: const Key('library_daily_report_entry_tile'),
          color: theme.colorScheme.surfaceContainerLow,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: BorderSide(
              color: theme.colorScheme.outlineVariant.withValues(alpha: 0.35),
            ),
          ),
          child: InkWell(
            borderRadius: BorderRadius.circular(12),
            onTap: () =>
                PodcastNavigation.goToDailyReport(context, source: 'library'),
            child: Padding(
              padding: EdgeInsets.symmetric(
                horizontal: compact ? 12 : 16,
                vertical: compact ? 10 : 12,
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.summarize_outlined,
                    color: theme.colorScheme.primary,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          l10n.podcast_daily_report_title,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.titleSmall?.copyWith(
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(
                          l10n.podcast_daily_report_entry_subtitle,
                          maxLines: compact ? 1 : 2,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 8),
                  Icon(
                    Icons.chevron_right,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildEmptyFeedWithEntry(
    BuildContext context, {
    required bool mobile,
  }) {
    final l10n = AppLocalizations.of(context)!;
    return RefreshIndicator(
      onRefresh: () async {
        await ref.read(podcastFeedProvider.notifier).refreshFeed();
      },
      child: ListView(
        padding: const EdgeInsets.symmetric(vertical: 4),
        children: [
          _buildDailyReportEntryTile(context, compact: mobile),
          const SizedBox(height: 28),
          Center(
            child: Column(
              children: [
                Icon(
                  Icons.rss_feed,
                  size: 64,
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
                const SizedBox(height: 16),
                Text(
                  l10n.podcast_no_episodes_found,
                  style: Theme.of(context).textTheme.titleLarge,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFeedContent(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final feedState = ref.watch(podcastFeedProvider);

    if (feedState.isLoading && feedState.episodes.isEmpty) {
      return Center(
        child: CircularProgressIndicator(
          color: Theme.of(context).colorScheme.tertiary,
        ),
      );
    }

    if (feedState.error != null && feedState.episodes.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.error_outline,
              size: 48,
              color: Theme.of(context).colorScheme.error,
            ),
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

    // 浣跨敤LayoutBuilder鏉ュ姩鎬佽皟鏁村竷灞€
    return LayoutBuilder(
      builder: (context, constraints) {
        final screenWidth = constraints.maxWidth;
        final isMobile = screenWidth < 600;

        if (feedState.episodes.isEmpty) {
          return _buildEmptyFeedWithEntry(context, mobile: isMobile);
        }

        // 绉诲姩绔細浣跨敤ListView
        if (isMobile) {
          return RefreshIndicator(
            onRefresh: () async {
              await ref.read(podcastFeedProvider.notifier).refreshFeed();
            },
            child: ListView.builder(
              padding: const EdgeInsets.symmetric(vertical: 4),
              itemCount:
                  feedState.episodes.length + (feedState.hasMore ? 1 : 0) + 1,
              itemBuilder: (context, index) {
                if (index == 0) {
                  return _buildDailyReportEntryTile(context, compact: true);
                }

                final episodeIndex = index - 1;
                if (episodeIndex >= feedState.episodes.length) {
                  // Loading more indicator
                  Future.microtask(
                    () => ref.read(podcastFeedProvider.notifier).loadMoreFeed(),
                  );
                  return Center(
                    child: Padding(
                      padding: const EdgeInsets.all(8.0),
                      child: CircularProgressIndicator(
                        color: Theme.of(context).colorScheme.tertiary,
                      ),
                    ),
                  );
                }
                return _buildMobileCard(
                  context,
                  feedState.episodes[episodeIndex],
                );
              },
            ),
          );
        }

        // 妗岄潰绔細浣跨敤GridView锛屼紭鍖栧崱鐗囬珮搴?
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

        // 浼樺寲瀹介珮姣旓細鍗＄墖鍐呭楂樺害绾?80-200锛岀‘淇濅笉婧㈠嚭
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
            itemCount: feedState.episodes.length + 1,
            itemBuilder: (context, index) {
              if (index == 0) {
                return _buildDailyReportEntryTile(context, compact: false);
              }

              final episodeIndex = index - 1;
              if (episodeIndex == feedState.episodes.length - 1 &&
                  feedState.hasMore) {
                Future.microtask(
                  () => ref.read(podcastFeedProvider.notifier).loadMoreFeed(),
                );
              }
              return _buildDesktopCard(
                context,
                feedState.episodes[episodeIndex],
              );
            },
          ),
        );
      },
    );
  }

  /// 鏋勫缓绉诲姩绔崱鐗?
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
                      foregroundColor: theme.colorScheme.onSurfaceVariant,
                    ),
                    icon: const Icon(Icons.play_circle_outline, size: 22),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  /// 鏋勫缓妗岄潰绔崱鐗囷紙浣跨敤灏忓浘鏍囧竷灞€锛?
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
