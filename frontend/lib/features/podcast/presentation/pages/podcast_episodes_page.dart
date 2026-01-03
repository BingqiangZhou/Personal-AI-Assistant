import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/podcast_subscription_model.dart';
import '../navigation/podcast_navigation.dart';
import '../providers/podcast_providers.dart';
import '../widgets/simplified_episode_card.dart';
import '../widgets/floating_player_widget.dart';

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
  factory PodcastEpisodesPage.withSubscription(
    PodcastSubscriptionModel subscription,
  ) {
    return PodcastEpisodesPage(
      subscriptionId: subscription.id,
      podcastTitle: subscription.title,
      subscription: subscription,
    );
  }

  @override
  ConsumerState<PodcastEpisodesPage> createState() =>
      _PodcastEpisodesPageState();
}

class _PodcastEpisodesPageState extends ConsumerState<PodcastEpisodesPage> {
  final ScrollController _scrollController = ScrollController();
  String _selectedFilter = 'all';
  bool _showOnlyWithSummary = false;
  bool _isReparsing = false;  // 重新解析状态

  @override
  void initState() {
    super.initState();
    // Load initial episodes
    _loadEpisodesForSubscription();

    // Setup scroll listener for infinite scroll
    _scrollController.addListener(() {
      if (_scrollController.position.pixels ==
          _scrollController.position.maxScrollExtent) {
        ref
            .read(podcastEpisodesProvider.notifier)
            .loadMoreEpisodesForSubscription(subscriptionId: widget.subscriptionId);
      }
    });
  }

  @override
  void didUpdateWidget(PodcastEpisodesPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    // Check if subscriptionId has changed
    if (oldWidget.subscriptionId != widget.subscriptionId) {
      debugPrint('🔄 ===== didUpdateWidget: Subscription ID changed =====');
      debugPrint('🔄 Old Subscription ID: ${oldWidget.subscriptionId}');
      debugPrint('🔄 New Subscription ID: ${widget.subscriptionId}');
      debugPrint('🔄 Reloading episodes for new subscription');

      // Reset filters
      _selectedFilter = 'all';
      _showOnlyWithSummary = false;

      // Reload episodes for the new subscription
      _loadEpisodesForSubscription();

      debugPrint('🔄 ===== didUpdateWidget complete =====');
    }
  }

  Future<void> _loadEpisodesForSubscription() {
    return Future.microtask(() {
      debugPrint('📋 Loading episodes for subscription: ${widget.subscriptionId}');
      ref
          .read(podcastEpisodesProvider.notifier)
          .loadEpisodesForSubscription(subscriptionId: widget.subscriptionId);
    });
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _refreshEpisodes() async {
    await ref
        .read(podcastEpisodesProvider.notifier)
        .refreshEpisodesForSubscription(
          subscriptionId: widget.subscriptionId,
          status: _selectedFilter == 'played'
              ? 'played'
              : _selectedFilter == 'unplayed'
              ? 'unplayed'
              : null,
        );
  }

  // 重新解析订阅
  Future<void> _reparseSubscription() async {
    if (_isReparsing) return;  // 防止重复点击

    setState(() {
      _isReparsing = true;
    });

    final l10n = AppLocalizations.of(context)!;

    try {
      // 显示 loading 提示
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.podcast_reparsing),
            duration: Duration(seconds: 2),
            behavior: SnackBarBehavior.floating,
          ),
        );
      }

      // 调用重新解析
      await ref.read(podcastSubscriptionProvider.notifier).reparseSubscription(
        widget.subscriptionId,
        true,  // forceAll: 重新解析所有分集
      );

      // 重新加载分集列表
      await _refreshEpisodes();

      // 显示成功提示
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.podcast_reparse_completed),
            duration: Duration(seconds: 2),
            backgroundColor: Colors.green,
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    } catch (error) {
      // 显示错误提示
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('${l10n.podcast_reparse_failed} $error'),
            duration: Duration(seconds: 3),
            backgroundColor: Colors.red,
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isReparsing = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final episodesState = ref.watch(podcastEpisodesProvider);
    // Don't watch audioPlayerProvider to avoid initializing it on startup
    // final audioPlayerState = ref.watch(audioPlayerProvider);

    // Debug: 输出分集图像链接信息（已注释）
    // if (episodesState.episodes.isNotEmpty) {
    //   final firstEpisode = episodesState.episodes.first;
    //   debugPrint('📺 PodcastEpisodesPage - First episode image debug:');
    //   debugPrint('  Episode ID: ${firstEpisode.id}');
    //   debugPrint('  Episode Title: ${firstEpisode.title}');
    //   debugPrint('  Image URL: ${firstEpisode.imageUrl}');
    //   debugPrint('  Subscription Image URL: ${firstEpisode.subscriptionImageUrl}');
    //   debugPrint('  Has episode image: ${firstEpisode.imageUrl != null}');
    //   debugPrint('  Has subscription image: ${firstEpisode.subscriptionImageUrl != null}');
    // }

    return Scaffold(
      body: Stack(
        children: [
          Column(
            children: [
              // Custom Header with top padding to align with Feed page
              Padding(
                padding: const EdgeInsets.only(top: 16),
                child: Container(
                  height: 56,
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  child: Row(
                    children: [
                      IconButton(
                        icon: const Icon(Icons.arrow_back),
                        onPressed: () => context.pop(),
                      ),
                      const SizedBox(width: 8),
                      // Icon
                        Container(
                        width: 40,
                        height: 40,
                        decoration: BoxDecoration(
                          color: Theme.of(context).colorScheme.primaryContainer,
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: ClipRRect(
                          borderRadius: BorderRadius.circular(8),
                          child: Builder(
                            builder: (context) {
                              final sub = widget.subscription;
                              if (sub?.imageUrl != null) {
                                return Image.network(
                                  sub!.imageUrl!,
                                  fit: BoxFit.cover,
                                  errorBuilder: (context, error, stackTrace) =>
                                      Icon(
                                        Icons.podcasts,
                                        size: 24,
                                        color: Theme.of(context).colorScheme.onPrimaryContainer,
                                      ),
                                );
                              }

                              if (episodesState.episodes.isNotEmpty) {
                                final firstEp = episodesState.episodes.first;
                                if (firstEp.subscriptionImageUrl != null) {
                                  return Image.network(
                                    firstEp.subscriptionImageUrl!,
                                    fit: BoxFit.cover,
                                    errorBuilder: (context, error, stackTrace) =>
                                        Icon(
                                          Icons.podcasts,
                                          size: 24,
                                          color: Theme.of(context).colorScheme.onPrimaryContainer,
                                        ),
                                  );
                                }
                              }

                              return Icon(
                                  Icons.podcasts,
                                  size: 24,
                                  color: Theme.of(context).colorScheme.onPrimaryContainer,
                                );
                            },
                          ),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          widget.podcastTitle ?? l10n.podcast_episodes,
                          style: Theme.of(context).textTheme.titleLarge?.copyWith(
                            fontWeight: FontWeight.bold,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      // 重新解析按钮
                      IconButton(
                        icon: _isReparsing
                            ? SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: Theme.of(context).colorScheme.primary,
                                ),
                              )
                            : Icon(Icons.refresh),
                        onPressed: _isReparsing ? null : _reparseSubscription,
                        tooltip: l10n.podcast_reparse_tooltip,
                      ),
                      // 筛选按钮移到标题行
                      if (MediaQuery.of(context).size.width < 700) ...[
                         IconButton(
                          icon: const Icon(Icons.filter_list),
                          onPressed: _showFilterDialog,
                          tooltip: l10n.filter,
                        ),
                        _buildMoreMenu(),
                      ] else ...[
                        _buildFilterChips(),
                         const SizedBox(width: 8),
                        _buildMoreMenu(),
                      ],
                    ],
                  ),
                ),
              ),

              Expanded(
                child: RefreshIndicator(
                  onRefresh: _refreshEpisodes,
                  child: episodesState.isLoading && episodesState.episodes.isEmpty
                      ? const Center(child: CircularProgressIndicator())
                      : episodesState.error != null
                      ? _buildErrorState(episodesState.error!)
                      : episodesState.episodes.isEmpty
                      ? _buildEmptyState()
                      : Column(
                          children: [
                            // Episodes list - Grid Layout
                            Expanded(
                              child: LayoutBuilder(
                                builder: (context, constraints) {
                                  final screenWidth = constraints.maxWidth;

                                  // Mobile: single column
                                  if (screenWidth < 600) {
                                    return ListView.builder(
                                      controller: _scrollController,
                                      padding: const EdgeInsets.symmetric(
                                        vertical: 8,
                                        horizontal: 12,
                                      ),
                                      itemCount:
                                          episodesState.episodes.length +
                                          (episodesState.isLoadingMore ? 1 : 0),
                                      itemBuilder: (context, index) {
                                        if (index ==
                                            episodesState.episodes.length) {
                                          return const Center(
                                            child: Padding(
                                              padding: EdgeInsets.all(16),
                                              child: CircularProgressIndicator(),
                                            ),
                                          );
                                        }
                                        final episode =
                                            episodesState.episodes[index];
                                        return SimplifiedEpisodeCard(
                                          episode: episode,
                                          onTap: () {
                                            context.push(
                                              '/podcast/episode/detail/${episode.id}',
                                            );
                                          },
                                          onPlay: () async {
                                            await ref
                                                .read(audioPlayerProvider.notifier)
                                                .playEpisode(episode);
                                          },
                                        );
                                      },
                                    );
                                  }

                                  // Desktop: grid layout
                                  final crossAxisCount = screenWidth < 900
                                      ? 2
                                      : (screenWidth < 1200 ? 3 : 4);
                                  return GridView.builder(
                                    controller: _scrollController,
                                    padding: const EdgeInsets.all(12),
                                    gridDelegate:
                                        SliverGridDelegateWithFixedCrossAxisCount(
                                          crossAxisCount: crossAxisCount,
                                          crossAxisSpacing: 12,
                                          mainAxisSpacing: 12,
                                          mainAxisExtent: 180,
                                        ),
                                    itemCount:
                                        episodesState.episodes.length +
                                        (episodesState.isLoadingMore ? 1 : 0),
                                    itemBuilder: (context, index) {
                                      if (index == episodesState.episodes.length) {
                                        return const Center(
                                          child: CircularProgressIndicator(),
                                        );
                                      }
                                      final episode = episodesState.episodes[index];
                                      return SimplifiedEpisodeCard(
                                        episode: episode,
                                        onTap: () {
                                          context.push(
                                            '/podcast/episode/detail/${episode.id}',
                                          );
                                        },
                                        onPlay: () async {
                                          await ref
                                              .read(audioPlayerProvider.notifier)
                                              .playEpisode(episode);
                                        },
                                      );
                                    },
                                  );
                                },
                              ),
                            ),
                          ],
                        ),
                ),
              ),
            ],
          ),
          // Floating player overlay
          const FloatingPlayerWidget(),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    final l10n = AppLocalizations.of(context)!;
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.headphones_outlined,
            size: 80,
            color: Theme.of(
              context,
            ).colorScheme.onSurfaceVariant.withValues(alpha: 0.5),
          ),
          const SizedBox(height: 16),
          Text(
            _showOnlyWithSummary
                ? l10n.podcast_no_episodes_with_summary
                : l10n.podcast_no_episodes,
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            _showOnlyWithSummary
                ? l10n.podcast_try_adjusting_filters
                : l10n.podcast_no_episodes_yet,
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              color: Theme.of(
                context,
              ).colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFilterChips() {
    final l10n = AppLocalizations.of(context)!;
    return Row(
      mainAxisSize: MainAxisSize.min,
      mainAxisAlignment: MainAxisAlignment.end,
      children: [
        FilterChip(
          label: Text(l10n.podcast_filter_all),
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
          label: Text(l10n.podcast_filter_unplayed),
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
          label: Text(l10n.podcast_filter_played),
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
          label: Text(l10n.podcast_filter_with_summary),
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
    );
  }

  Widget _buildMoreMenu() {
    final l10n = AppLocalizations.of(context)!;
    return PopupMenuButton<String>(
      icon: Icon(
        Icons.more_vert,
        color: Theme.of(context).colorScheme.secondary,
      ),
      onSelected: (value) {
        // TODO: Implement
      },
      itemBuilder: (context) => [
        PopupMenuItem(
          value: 'mark_all_played',
          child: Text(l10n.podcast_mark_all_played),
        ),
        PopupMenuItem(
          value: 'mark_all_unplayed',
          child: Text(l10n.podcast_mark_all_unplayed),
        ),
      ],
    );
  }

  Widget _buildErrorState(Object error) {
    final l10n = AppLocalizations.of(context)!;
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
            l10n.podcast_failed_load_episodes,
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
            label: Text(l10n.retry),
          ),
        ],
      ),
    );
  }

  void _showFilterDialog() {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: Text(l10n.podcast_filter_episodes),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(l10n.podcast_playback_status),
              const SizedBox(height: 8),
              Column(
                children: [
                  RadioListTile<String>(
                    title: Text(l10n.podcast_all_episodes),
                    value: 'all',
                    groupValue: _selectedFilter,
                    onChanged: (value) {
                      setDialogState(() {
                        _selectedFilter = value!;
                      });
                    },
                  ),
                  RadioListTile<String>(
                    title: Text(l10n.podcast_unplayed_only),
                    value: 'unplayed',
                    groupValue: _selectedFilter,
                    onChanged: (value) {
                      setDialogState(() {
                        _selectedFilter = value!;
                      });
                    },
                  ),
                  RadioListTile<String>(
                    title: Text(l10n.podcast_played_only),
                    value: 'played',
                    groupValue: _selectedFilter,
                    onChanged: (value) {
                      setDialogState(() {
                        _selectedFilter = value!;
                      });
                    },
                  ),
                ],
              ),
              const SizedBox(height: 16),
              CheckboxListTile(
                title: Text(l10n.podcast_only_with_summary),
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
              child: Text(l10n.cancel),
            ),
            TextButton(
              onPressed: () {
                Navigator.of(context).pop();
                setState(() {});
                _refreshEpisodes();
              },
              child: Text(l10n.podcast_apply),
            ),
          ],
        ),
      ),
    );
  }
}
