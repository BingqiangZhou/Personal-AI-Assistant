import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../../../core/widgets/top_floating_notice.dart';
import '../../core/utils/episode_description_helper.dart';
import '../../data/models/podcast_episode_model.dart';
import '../../data/models/podcast_state_models.dart';
import '../navigation/podcast_navigation.dart';
import '../providers/podcast_providers.dart';
import '../widgets/podcast_image_widget.dart';

class PodcastFeedPage extends ConsumerStatefulWidget {
  const PodcastFeedPage({super.key});

  @override
  ConsumerState<PodcastFeedPage> createState() => _PodcastFeedPageState();
}

class _PodcastFeedPageState extends ConsumerState<PodcastFeedPage> {
  final Set<int> _addingEpisodeIds = <int>{};
  final ScrollController _scrollController = ScrollController();
  static const double _loadMoreThresholdPx = 320;

  @override
  void initState() {
    super.initState();
    _scrollController.addListener(_onScroll);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) {
        return;
      }
      ref.read(podcastFeedProvider.notifier).loadInitialFeed();
    });
  }

  void _onScroll() {
    if (!_scrollController.hasClients) {
      return;
    }
    final position = _scrollController.position;
    if (!position.hasPixels || !position.hasContentDimensions) {
      return;
    }
    final remaining = position.maxScrollExtent - position.pixels;
    if (remaining > _loadMoreThresholdPx) {
      return;
    }

    final feedState = ref.read(podcastFeedProvider);
    if (feedState.isLoadingMore || !feedState.hasMore) {
      return;
    }
    ref.read(podcastFeedProvider.notifier).loadMoreFeed();
  }

  @override
  void dispose() {
    _scrollController
      ..removeListener(_onScroll)
      ..dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return ResponsiveContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header row
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

          // Feed content fills remaining space with Expanded.
          Expanded(
            child: Consumer(
              builder: (context, localRef, child) {
                final feedState = localRef.watch(podcastFeedProvider);
                return _buildFeedContent(context, localRef, feedState);
              },
            ),
          ),
        ],
      ),
    );
  }

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
        await ref
            .read(podcastFeedProvider.notifier)
            .refreshFeed(fastReturn: true);
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

  Widget _buildFeedContent(
    BuildContext context,
    WidgetRef localRef,
    PodcastFeedState feedState,
  ) {
    final l10n = AppLocalizations.of(context)!;

    if (feedState.isLoading && feedState.episodes.isEmpty) {
      return Center(
        child: CircularProgressIndicator(
          color: Theme.of(context).colorScheme.onSurfaceVariant,
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
                localRef.read(podcastFeedProvider.notifier).loadInitialFeed();
              },
              child: Text(l10n.podcast_retry),
            ),
          ],
        ),
      );
    }

    // Use LayoutBuilder to switch between mobile and desktop layouts.
    return LayoutBuilder(
      builder: (context, constraints) {
        final screenWidth = constraints.maxWidth;
        final isMobile = screenWidth < 600;

        if (feedState.episodes.isEmpty) {
          return _buildEmptyFeedWithEntry(context, mobile: isMobile);
        }

        return RefreshIndicator(
          onRefresh: () => localRef
              .read(podcastFeedProvider.notifier)
              .refreshFeed(fastReturn: true),
          child: _buildFeedScrollable(
            context,
            feedState: feedState,
            screenWidth: screenWidth,
          ),
        );
      },
    );
  }

  Widget _buildFeedScrollable(
    BuildContext context, {
    required PodcastFeedState feedState,
    required double screenWidth,
  }) {
    final isMobile = screenWidth < 600;
    final itemCount =
        feedState.episodes.length + (feedState.hasMore ? 1 : 0) + 1;

    if (isMobile) {
      return ListView.builder(
        controller: _scrollController,
        padding: const EdgeInsets.symmetric(vertical: 4),
        itemCount: itemCount,
        itemBuilder: (context, index) =>
            _buildFeedListItem(context, feedState, index, compact: true),
      );
    }

    final crossAxisCount = screenWidth < 900 ? 2 : (screenWidth < 1200 ? 3 : 4);
    const spacing = 6.0;
    final availableWidth = screenWidth - (crossAxisCount - 1) * spacing;
    final cardWidth = availableWidth / crossAxisCount;
    const desktopCardHeight = 172.0;
    final childAspectRatio = cardWidth / desktopCardHeight;

    return GridView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.symmetric(vertical: 4),
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: crossAxisCount,
        crossAxisSpacing: spacing,
        mainAxisSpacing: spacing,
        childAspectRatio: childAspectRatio,
      ),
      itemCount: itemCount,
      itemBuilder: (context, index) =>
          _buildFeedListItem(context, feedState, index, compact: false),
    );
  }

  Widget _buildFeedListItem(
    BuildContext context,
    PodcastFeedState feedState,
    int index, {
    required bool compact,
  }) {
    if (index == 0) {
      return _buildDailyReportEntryTile(context, compact: compact);
    }

    final episodeIndex = index - 1;
    if (episodeIndex >= feedState.episodes.length) {
      if (!feedState.isLoadingMore) {
        return const SizedBox.shrink();
      }
      final loader = CircularProgressIndicator(
        color: Theme.of(context).colorScheme.onSurfaceVariant,
      );
      if (compact) {
        return Center(
          child: Padding(padding: const EdgeInsets.all(8), child: loader),
        );
      }
      return Center(child: loader);
    }

    final episode = feedState.episodes[episodeIndex];
    return compact
        ? _buildMobileCard(context, episode)
        : _buildDesktopCard(context, episode);
  }

  /// Build mobile feed card.
  Widget _buildMobileCard(BuildContext context, PodcastEpisodeModel episode) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final isAddingToQueue = _addingEpisodeIds.contains(episode.id);
    // Feed cards display sanitized plain-text descriptions.
    final displayDescription = _getFeedCardDescription(episode.description);
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

  /// Build desktop feed card.
  Widget _buildDesktopCard(BuildContext context, PodcastEpisodeModel episode) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final isAddingToQueue = _addingEpisodeIds.contains(episode.id);
    final displayDescription = _getFeedCardDescription(episode.description);
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

String _getFeedCardDescription(String? description) {
  final sanitized = EpisodeDescriptionHelper.stripHtmlTags(description);
  if (sanitized.isEmpty) {
    return '';
  }

  // Recover visible content when malformed/truncated tag fragments remain.
  final recovered = _recoverMalformedTagInlineContent(sanitized);
  final cleaned = recovered.replaceAll(
    RegExp(r'<[/!]?[a-zA-Z][^>\n]*(?=\n|$)'),
    '',
  );

  final cssCleaned = _removeLikelyCssNoise(cleaned);
  return cssCleaned.trim();
}

String _recoverMalformedTagInlineContent(String text) {
  final lines = text.split('\n');
  final recoveredLines = lines.map(_recoverMalformedTagLine).toList();
  return recoveredLines.join('\n');
}

String _recoverMalformedTagLine(String line) {
  final malformedTagMatch = RegExp(r'<[/!]?[a-zA-Z][^>]*$').firstMatch(line);
  if (malformedTagMatch == null) {
    return line;
  }

  final tagStart = malformedTagMatch.start;
  final prefix = line.substring(0, tagStart);
  final fragment = line.substring(tagStart);

  // If content is appended after a quoted attribute value, keep that tail.
  final lastDoubleQuote = fragment.lastIndexOf('"');
  final lastSingleQuote = fragment.lastIndexOf("'");
  final lastQuoteIndex = lastDoubleQuote > lastSingleQuote
      ? lastDoubleQuote
      : lastSingleQuote;

  if (lastQuoteIndex != -1 && lastQuoteIndex + 1 < fragment.length) {
    final tail = fragment.substring(lastQuoteIndex + 1).trimLeft();
    if (tail.isNotEmpty &&
        !RegExp(r'^[a-zA-Z_:-][\w:.-]*\s*=').hasMatch(tail)) {
      return '$prefix$tail';
    }
  }

  // Fallback for CJK text directly following malformed tag attributes.
  final cjkMatch = RegExp(r'[\u4E00-\u9FFF]').firstMatch(fragment);
  if (cjkMatch != null) {
    return '$prefix${fragment.substring(cjkMatch.start)}';
  }

  return prefix;
}

String _removeLikelyCssNoise(String text) {
  final lines = text.split('\n');
  final cleanedLines = <String>[];

  for (var line in lines) {
    // Drop leading runs of style declarations (common malformed "<p style=..."
    // remnants once tags are stripped).
    line = line.replaceFirst(
      RegExp(
        r'^\s*(?:(?:color|font-weight|font-size|line-height|font-family|hyphens|text-align|letter-spacing|word-spacing|white-space|word-break|overflow-wrap|text-indent|text-decoration|font-style|font-variant|font-stretch|font)\s*:\s*[^;\n]+;?\s*){2,}',
        caseSensitive: false,
      ),
      '',
    );

    // Remove inline attribute fragments if any survived.
    line = line.replaceAll(
      RegExp(
        r'''\b(?:data-[\w-]+|style)\s*=\s*["'][^"']*["']''',
        caseSensitive: false,
      ),
      '',
    );

    // Remove remaining standalone CSS declarations.
    line = line.replaceAll(
      RegExp(
        r'\b(?:color|font-weight|font-size|line-height|font-family|hyphens|text-align|letter-spacing|word-spacing|white-space|word-break|overflow-wrap|text-indent|text-decoration|font-style|font-variant|font-stretch|font)\s*:\s*[^;\n]+;?',
        caseSensitive: false,
      ),
      '',
    );

    line = line.replaceAll(RegExp(r'^[;,\s]+|[;,\s]+$'), '').trim();

    final isPureCssLine = RegExp(
      r'^(?:[a-z-]+\s*:[^;\n]+;?\s*)+$',
      caseSensitive: false,
    ).hasMatch(line);

    if (line.isNotEmpty && !isPureCssLine) {
      cleanedLines.add(line);
    }
  }

  return cleanedLines.join('\n');
}
