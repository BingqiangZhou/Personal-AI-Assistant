import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:flutter_markdown_plus/flutter_markdown_plus.dart';
import '../../../../core/localization/app_localizations.dart';

import '../providers/podcast_providers.dart';
import '../providers/transcription_providers.dart';
import '../providers/summary_providers.dart';
import '../../data/models/podcast_episode_model.dart';
import '../../data/models/audio_player_state_model.dart';
import '../widgets/transcript_display_widget.dart';
import '../widgets/shownotes_display_widget.dart';
import '../widgets/transcription_status_widget.dart';
import '../widgets/ai_summary_control_widget.dart';
import '../widgets/conversation_chat_widget.dart';
import '../widgets/podcast_image_widget.dart';
import '../widgets/podcast_bottom_player_widget.dart';
import '../widgets/scrollable_content_wrapper.dart';
import '../services/content_image_share_service.dart';
import '../../../../core/utils/app_logger.dart' as logger;

class PodcastEpisodeDetailPage extends ConsumerStatefulWidget {
  final int episodeId;

  const PodcastEpisodeDetailPage({super.key, required this.episodeId});

  @override
  ConsumerState<PodcastEpisodeDetailPage> createState() =>
      _PodcastEpisodeDetailPageState();
}

class _PodcastEpisodeDetailPageState
    extends ConsumerState<PodcastEpisodeDetailPage> {
  int _selectedTabIndex =
      0; // 0 = Shownotes, 1 = Transcript, 2 = AI Summary, 3 = Conversation
  Timer? _summaryPollingTimer;
  bool _isPolling = false; // Guard flag to prevent multiple polls
  bool _hasTrackedEpisodeView = false;
  String _selectedSummaryText = '';

  // Sticky header animation
  final ScrollController _scrollController = ScrollController();
  final PageController _pageController = PageController();
  double _scrollOffset = 0.0;
  static const double _headerScrollThreshold =
      50.0; // Header starts fading after 50px scroll
  static const double _autoCollapseScrollDeltaThreshold = 6.0;

  // Scroll to top button
  final Map<int, double> _tabScrollPositions = {
    0: 0.0,
    1: 0.0,
    2: 0.0,
    3: 0.0,
  }; // Track scroll position for each tab
  final Map<int, double> _tabScrollPercentages = {
    0: 0.0,
    1: 0.0,
    2: 0.0,
    3: 0.0,
  }; // Track scroll percentage for each tab
  final Map<int, ScrollController> _tabScrollControllers =
      {}; // ScrollController for each tab

  // GlobalKeys for accessing child widget states to call scrollToTop
  final GlobalKey<ShownotesDisplayWidgetState> _shownotesKey =
      GlobalKey<ShownotesDisplayWidgetState>();
  final GlobalKey<TranscriptDisplayWidgetState> _transcriptKey =
      GlobalKey<TranscriptDisplayWidgetState>();
  final GlobalKey<ScrollableContentWrapperState> _aiSummaryKey =
      GlobalKey<ScrollableContentWrapperState>();
  final GlobalKey<ConversationChatWidgetState> _conversationKey =
      GlobalKey<ConversationChatWidgetState>();

  @override
  void initState() {
    super.initState();
    // Don't auto-play episode when page loads - user must click play button
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _loadTranscriptionStatus();
      // Auto-expand the bottom player when entering the detail page
      ref.read(audioPlayerProvider.notifier).setExpanded(true);
    });
    // Setup scroll listener for sticky header effect
    _scrollController.addListener(_onScroll);
  }

  @override
  void dispose() {
    _scrollController.removeListener(_onScroll);
    _scrollController.dispose();
    _pageController.dispose();
    _summaryPollingTimer?.cancel();
    // Clean up tab scroll controllers
    for (final controller in _tabScrollControllers.values) {
      controller.dispose();
    }
    super.dispose();
  }

  void _onScroll() {
    setState(() {
      _scrollOffset = _scrollController.offset;
    });
  }

  // Calculate header opacity based on scroll offset
  double get _headerOpacity {
    if (_scrollOffset <= 0) return 1.0;
    if (_scrollOffset >= _headerScrollThreshold) return 0.0;
    return 1.0 - (_scrollOffset / _headerScrollThreshold);
  }

  // Calculate header clipping height based on scroll offset
  double get _headerClipHeight {
    const maxHeaderHeight = 100.0;
    if (_scrollOffset <= 0) return maxHeaderHeight;
    if (_scrollOffset >= _headerScrollThreshold) return 0.0;
    return maxHeaderHeight * (1 - _scrollOffset / _headerScrollThreshold);
  }

  bool get _isHeaderExpanded {
    return _scrollOffset < _headerScrollThreshold;
  }

  void _updateHeaderStateForTab(int tabIndex) {
    _scrollOffset = tabIndex == 3 ? _headerScrollThreshold : 0.0;
  }

  Future<void> _loadAndPlayEpisode() async {
    logger.AppLogger.debug('[Playback] ===== _loadAndPlayEpisode called =====');
    logger.AppLogger.debug('[Playback] widget.episodeId: ${widget.episodeId}');

    try {
      // Wait for episode detail to be loaded
      final episodeDetailAsync = await ref.read(
        episodeDetailProvider(widget.episodeId).future,
      );

      logger.AppLogger.debug(
        '[Playback] Loaded episode detail: ID=${episodeDetailAsync?.id}, Title=${episodeDetailAsync?.title}',
      );

      // Debug: Log itemLink from API response
      if (episodeDetailAsync != null) {
        logger.AppLogger.debug(
          '[API Response] itemLink: ${episodeDetailAsync.itemLink ?? "NULL"}',
        );
      }

      if (episodeDetailAsync != null) {
        // Convert PodcastEpisodeDetailResponse to PodcastEpisodeModel
        final episodeModel = PodcastEpisodeModel(
          id: episodeDetailAsync.id,
          subscriptionId: episodeDetailAsync.subscriptionId,
          subscriptionImageUrl: episodeDetailAsync.subscriptionImageUrl,
          title: episodeDetailAsync.title,
          description: episodeDetailAsync.description,
          audioUrl: episodeDetailAsync.audioUrl,
          audioDuration: episodeDetailAsync.audioDuration,
          audioFileSize: episodeDetailAsync.audioFileSize,
          publishedAt: episodeDetailAsync.publishedAt,
          imageUrl: episodeDetailAsync.imageUrl,
          itemLink: episodeDetailAsync.itemLink,
          transcriptUrl: episodeDetailAsync.transcriptUrl,
          transcriptContent: episodeDetailAsync.transcriptContent,
          aiSummary: episodeDetailAsync.aiSummary,
          summaryVersion: episodeDetailAsync.summaryVersion,
          aiConfidenceScore: episodeDetailAsync.aiConfidenceScore,
          playCount: episodeDetailAsync.playCount,
          lastPlayedAt: episodeDetailAsync.lastPlayedAt,
          season: episodeDetailAsync.season,
          episodeNumber: episodeDetailAsync.episodeNumber,
          explicit: episodeDetailAsync.explicit,
          status: episodeDetailAsync.status,
          metadata: episodeDetailAsync.metadata,
          playbackPosition: episodeDetailAsync.playbackPosition,
          isPlaying: episodeDetailAsync.isPlaying,
          playbackRate: episodeDetailAsync.playbackRate,
          isPlayed: episodeDetailAsync.isPlayed ?? false,
          createdAt: episodeDetailAsync.createdAt,
          updatedAt: episodeDetailAsync.updatedAt,
        );

        logger.AppLogger.debug(
          '[Playback] Auto-playing episode: ${episodeModel.title}',
        );
        await ref.read(audioPlayerProvider.notifier).playEpisode(episodeModel);
      }
    } catch (error) {
      logger.AppLogger.debug('[Error] Failed to auto-play episode: $error');
    }
  }

  Future<void> _loadTranscriptionStatus() async {
    try {
      final transcriptionProvider = getTranscriptionProvider(widget.episodeId);
      // Automatically check/start transcription if missing
      await ref
          .read(transcriptionProvider.notifier)
          .checkOrStartTranscription();
    } catch (error) {
      logger.AppLogger.debug(
        '[Error] Failed to load transcription status: $error',
      );
    }
  }

  void _trackEpisodeViewOnce(PodcastEpisodeDetailResponse episodeDetail) {
    if (_hasTrackedEpisodeView) {
      return;
    }
    _hasTrackedEpisodeView = true;
    unawaited(_trackEpisodeView(episodeDetail));
  }

  Future<void> _trackEpisodeView(
    PodcastEpisodeDetailResponse episodeDetail,
  ) async {
    try {
      final repository = ref.read(podcastRepositoryProvider);
      await repository.updatePlaybackProgress(
        episodeId: widget.episodeId,
        position: episodeDetail.playbackPosition ?? 0,
        isPlaying: false,
        playbackRate: episodeDetail.playbackRate,
      );
      ref.invalidate(podcastStatsProvider);
      ref.invalidate(playbackHistoryProvider);
    } catch (error) {
      logger.AppLogger.debug('Failed to track episode view: $error');
    }
  }

  void _handleAutoCollapseOnRead(ScrollNotification scrollNotification) {
    if (scrollNotification is! ScrollUpdateNotification) {
      return;
    }

    if (scrollNotification.metrics.axis != Axis.vertical) {
      return;
    }

    final scrollDelta = scrollNotification.scrollDelta ?? 0.0;
    if (scrollDelta <= _autoCollapseScrollDeltaThreshold) {
      return;
    }

    final playerState = ref.read(audioPlayerProvider);
    if (!playerState.isExpanded) {
      return;
    }

    ref.read(audioPlayerProvider.notifier).setExpanded(false);
  }

  @override
  Widget build(BuildContext context) {
    final episodeDetailAsync = ref.watch(
      episodeDetailProvider(widget.episodeId),
    );
    final isChatTab = _selectedTabIndex == 3;
    final hideBottomPlayer = isChatTab;

    // Listen to transcription status changes to provide user feedback
    ref.listen(getTranscriptionProvider(widget.episodeId), (previous, next) {
      final prevData = previous?.value;
      final nextData = next.value;

      if (nextData != null && prevData != null) {
        // Only notify if status changed from something else to processing or if we just started
        if (nextData.isProcessing && !prevData.isProcessing) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Row(
                children: [
                  const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(
                      color: Colors.white,
                      strokeWidth: 2,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Text(
                    AppLocalizations.of(
                      context,
                    )!.podcast_transcription_processing,
                  ),
                ],
              ),
              backgroundColor: Theme.of(context).colorScheme.primary,
              duration: const Duration(seconds: 2),
            ),
          );
        }
      } else if (nextData != null &&
          prevData == null &&
          nextData.isProcessing) {
        // Auto-start case
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Row(
              children: [
                const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(
                    color: Colors.white,
                    strokeWidth: 2,
                  ),
                ),
                const SizedBox(width: 12),
                Text(
                  AppLocalizations.of(
                    context,
                  )!.podcast_transcription_auto_starting,
                ),
              ],
            ),
            backgroundColor: Theme.of(context).colorScheme.primary,
            duration: const Duration(seconds: 3),
          ),
        );
      }
    });

    return Scaffold(
      backgroundColor: Theme.of(context).colorScheme.surface,
      bottomNavigationBar: hideBottomPlayer
          ? null
          : const PodcastBottomPlayerWidget(),
      body: episodeDetailAsync.when(
        data: (episodeDetail) {
          if (episodeDetail == null) {
            final l10n = AppLocalizations.of(context)!;
            return _buildErrorState(context, l10n.podcast_episode_not_found);
          }
          _trackEpisodeViewOnce(episodeDetail);
          return _buildNewLayout(context, episodeDetail);
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => _buildErrorState(context, error),
      ),
    );
  }

  Widget _buildNewLayout(BuildContext context, dynamic episode) {
    return LayoutBuilder(
      builder: (context, layoutConstraints) {
        // Use split-pane layout on desktop/tablet widths.
        final isWideScreen = layoutConstraints.maxWidth > 800;

        if (isWideScreen) {
          return Stack(
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SizedBox(
                    width: 200,
                    child: Column(
                      children: [
                        AnimatedContainer(
                          duration: const Duration(milliseconds: 200),
                          curve: Curves.easeInOut,
                          height: _isHeaderExpanded ? 90 : 100,
                        ),
                        Expanded(
                          child: SingleChildScrollView(
                            child: _buildLeftSidebar(),
                          ),
                        ),
                      ],
                    ),
                  ),
                  Expanded(
                    child: Stack(
                      children: [
                        NotificationListener<ScrollNotification>(
                          onNotification: (scrollNotification) {
                            _handleAutoCollapseOnRead(scrollNotification);
                            if (scrollNotification
                                is ScrollUpdateNotification) {
                              final metrics = scrollNotification.metrics;
                              if (metrics.axis == Axis.vertical) {
                                final scrollPosition = metrics.pixels;
                                final maxScroll = metrics.maxScrollExtent;
                                final scrollPercent = maxScroll > 0
                                    ? (scrollPosition / maxScroll)
                                    : 0.0;

                                setState(() {
                                  _scrollOffset = scrollPosition;
                                  _tabScrollPositions[_selectedTabIndex] =
                                      scrollPosition;
                                  _tabScrollPercentages[_selectedTabIndex] =
                                      scrollPercent;
                                });
                              }
                            }
                            return false;
                          },
                          child: Container(
                            padding: EdgeInsets.only(
                              top: _isHeaderExpanded ? 90 : 16,
                              right: 16,
                              bottom: 16,
                            ),
                            child: _buildTabContent(episode),
                          ),
                        ),
                        if (_shouldShowScrollToTopButton())
                          Positioned(
                            right: 16,
                            bottom: 16,
                            child: _buildScrollToTopButton(),
                          ),
                      ],
                    ),
                  ),
                ],
              ),
              AnimatedPositioned(
                duration: const Duration(milliseconds: 200),
                curve: Curves.easeInOut,
                top: 0,
                left: 0,
                right: _isHeaderExpanded ? 0 : null,
                width: _isHeaderExpanded ? null : 200,
                child: _buildAnimatedHeader(episode),
              ),
              if (!_isHeaderExpanded)
                Positioned(
                  left: 16,
                  bottom: 16,
                  child: _buildCollapsedFloatingActions(
                    episode,
                    AppLocalizations.of(context)!,
                  ),
                ),
            ],
          );
        } else {
          final topPadding = MediaQuery.of(context).padding.top;
          final totalTopPadding = topPadding > 0 ? topPadding + 8.0 : 8.0;

          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Padding(
                padding: EdgeInsets.only(top: totalTopPadding),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    ClipRect(
                      child: Align(
                        alignment: Alignment.topCenter,
                        heightFactor: _headerClipHeight / 100.0,
                        child: AnimatedOpacity(
                          opacity: _headerOpacity,
                          duration: const Duration(milliseconds: 100),
                          curve: Curves.easeInOut,
                          child: _buildHeader(episode),
                        ),
                      ),
                    ),

                    _buildTopButtonBar(),
                  ],
                ),
              ),

              Expanded(
                child: Stack(
                  children: [
                    NotificationListener<ScrollNotification>(
                      onNotification: (scrollNotification) {
                        _handleAutoCollapseOnRead(scrollNotification);
                        if (scrollNotification is ScrollUpdateNotification) {
                          final metrics = scrollNotification.metrics;
                          if (metrics.axis == Axis.vertical) {
                            final scrollPosition = metrics.pixels;
                            final maxScroll = metrics.maxScrollExtent;
                            final scrollPercent = maxScroll > 0
                                ? (scrollPosition / maxScroll)
                                : 0.0;

                            setState(() {
                              _scrollOffset = scrollPosition;
                              _tabScrollPositions[_selectedTabIndex] =
                                  scrollPosition;
                              _tabScrollPercentages[_selectedTabIndex] =
                                  scrollPercent;
                            });
                          }
                        }
                        return false;
                      },
                      child: PageView(
                        controller: _pageController,
                        onPageChanged: (index) {
                          setState(() {
                            _selectedTabIndex = index;
                            if (index == 2) {
                              _startSummaryPolling();
                            } else {
                              _stopSummaryPolling();
                            }
                            _updateHeaderStateForTab(index);
                          });
                        },
                        children: [
                          // 0 = Shownotes
                          _buildSingleTabContent(episode, 0),
                          // 1 = Transcript
                          _buildSingleTabContent(episode, 1),
                          // 2 = AI Summary
                          _buildSingleTabContent(episode, 2),
                          // 3 = Conversation
                          _buildSingleTabContent(episode, 3),
                        ],
                      ),
                    ),
                    if (_shouldShowScrollToTopButton())
                      Positioned(
                        right: 0,
                        bottom: 0,
                        child: _buildScrollToTopButton(),
                      ),
                  ],
                ),
              ),
            ],
          );
        }
      },
    );
  }

  Widget _buildHeader(dynamic episode) {
    final l10n = AppLocalizations.of(context)!;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      color: Theme.of(context).colorScheme.surface,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          PodcastImageWidget(
            imageUrl: episode.imageUrl,
            fallbackImageUrl: episode.subscriptionImageUrl,
            width: 60,
            height: 60,
            iconSize: 32,
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Flexible(
                            child: Text(
                              episode.title ?? l10n.episode_unknown_title,
                              style: TextStyle(
                                fontSize: 16,
                                fontWeight: FontWeight.bold,
                                color: Theme.of(context).colorScheme.onSurface,
                              ),
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          const SizedBox(width: 8),
                          InkWell(
                            onTap: () async {
                              try {
                                await _playOrResumeFromDetail(
                                  _episodeToModel(episode),
                                );
                              } catch (error) {
                                logger.AppLogger.debug(
                                  '[Error] Failed to play episode: $error',
                                );
                              }
                            },
                            child: Container(
                              key: const Key(
                                'podcast_episode_detail_play_button',
                              ),
                              padding: const EdgeInsets.symmetric(
                                horizontal: 10,
                                vertical: 4,
                              ),
                              decoration: BoxDecoration(
                                color: Theme.of(
                                  context,
                                ).colorScheme.primary.withValues(alpha: 0.1),
                                borderRadius: BorderRadius.circular(16),
                                border: Border.all(
                                  color: Theme.of(
                                    context,
                                  ).colorScheme.primary.withValues(alpha: 0.3),
                                  width: 1,
                                ),
                              ),
                              child: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Icon(
                                    Icons.play_arrow,
                                    size: 18,
                                    color: Theme.of(
                                      context,
                                    ).colorScheme.primary,
                                  ),
                                  const SizedBox(width: 4),
                                  Text(
                                    MediaQuery.of(context).size.width < 600
                                        ? l10n.podcast_play_episode
                                        : l10n.podcast_play_episode_full,
                                    style: TextStyle(
                                      fontSize: 13,
                                      fontWeight: FontWeight.w600,
                                      color: Theme.of(
                                        context,
                                      ).colorScheme.primary,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 8),
                    if (!_isMobilePlatform())
                      Container(
                        decoration: BoxDecoration(
                          color: Theme.of(
                            context,
                          ).colorScheme.primary.withValues(alpha: 0.1),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(
                            color: Theme.of(
                              context,
                            ).colorScheme.primary.withValues(alpha: 0.3),
                            width: 1,
                          ),
                        ),
                        child: IconButton(
                          icon: Icon(
                            Icons.arrow_back,
                            color: Theme.of(context).colorScheme.primary,
                            size: 20,
                          ),
                          onPressed: () => context.pop(),
                          tooltip: AppLocalizations.of(context)!.back_button,
                          constraints: const BoxConstraints(
                            minWidth: 36,
                            minHeight: 36,
                          ),
                          padding: EdgeInsets.zero,
                        ),
                      ),
                  ],
                ),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 16,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [
                    // Published date
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          Icons.calendar_today_outlined,
                          size: 14,
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                        const SizedBox(width: 6),
                        Text(
                          _formatDate(episode.publishedAt),
                          style: TextStyle(
                            fontSize: 13,
                            color: Theme.of(
                              context,
                            ).colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                    // Duration
                    if (episode.audioDuration != null)
                      Consumer(
                        builder: (context, ref, _) {
                          final audioPlayerState = ref.watch(
                            audioPlayerProvider,
                          );
                          // Use audio player duration if available (more accurate), otherwise fall back to episode duration
                          // CRITICAL: episode.audioDuration is in SECONDS, convert to MILLISECONDS
                          final displayDuration =
                              (audioPlayerState.currentEpisode?.id ==
                                      episode.id &&
                                  audioPlayerState.duration > 0)
                              ? audioPlayerState.duration
                              : (episode.audioDuration! *
                                    1000); // Convert seconds to milliseconds
                          final duration = Duration(
                            milliseconds: displayDuration,
                          );
                          final hours = duration.inHours;
                          final minutes = duration.inMinutes.remainder(60);
                          final seconds = duration.inSeconds.remainder(60);

                          // Format as H:MM:SS or MM:SS depending on whether hours exist
                          final formattedDuration = hours > 0
                              ? '$hours:${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}'
                              : '${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';

                          return Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Icon(
                                Icons.schedule_outlined,
                                size: 14,
                                color: Theme.of(
                                  context,
                                ).colorScheme.onSurfaceVariant,
                              ),
                              const SizedBox(width: 6),
                              Text(
                                formattedDuration,
                                style: TextStyle(
                                  fontSize: 13,
                                  color: Theme.of(
                                    context,
                                  ).colorScheme.onSurfaceVariant,
                                ),
                              ),
                            ],
                          );
                        },
                      ),
                    // Source link
                    if (episode.itemLink != null &&
                        episode.itemLink!.isNotEmpty)
                      InkWell(
                        onTap: () async {
                          final Uri linkUri = Uri.parse(episode.itemLink!);
                          if (await canLaunchUrl(linkUri)) {
                            await launchUrl(
                              linkUri,
                              mode: LaunchMode.externalApplication,
                            );
                          }
                        },
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.link,
                              size: 14,
                              color: Theme.of(context).colorScheme.primary,
                            ),
                            const SizedBox(width: 6),
                            Text(
                              l10n.podcast_source,
                              style: TextStyle(
                                fontSize: 13,
                                color: Theme.of(context).colorScheme.primary,
                              ),
                            ),
                          ],
                        ),
                      ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildAnimatedHeader(dynamic episode) {
    final l10n = AppLocalizations.of(context)!;

    if (_isHeaderExpanded) {
      return Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surface,
          border: Border(
            bottom: BorderSide(
              color: Theme.of(context).colorScheme.outlineVariant,
              width: 1,
            ),
          ),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            PodcastImageWidget(
              imageUrl: episode.imageUrl,
              fallbackImageUrl: episode.subscriptionImageUrl,
              width: 60,
              height: 60,
              iconSize: 32,
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          episode.title ?? l10n.episode_unknown_title,
                          style: TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                            color: Theme.of(context).colorScheme.onSurface,
                          ),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      const SizedBox(width: 12),
                      _buildPlayButton(episode, l10n),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Wrap(
                    spacing: 16,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      _buildDateChip(episode),
                      if (episode.audioDuration != null)
                        _buildDurationChip(episode),
                      if (episode.itemLink != null &&
                          episode.itemLink!.isNotEmpty)
                        _buildSourceLinkChip(episode, l10n),
                    ],
                  ),
                ],
              ),
            ),
            const SizedBox(width: 16),
            _buildBackButton(),
          ],
        ),
      );
    } else {
      return Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surface,
          border: Border(
            right: BorderSide(
              color: Theme.of(context).colorScheme.outlineVariant,
              width: 1,
            ),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Center(
              child: PodcastImageWidget(
                imageUrl: episode.imageUrl,
                fallbackImageUrl: episode.subscriptionImageUrl,
                width: 40,
                height: 40,
                iconSize: 24,
              ),
            ),
            const SizedBox(height: 6),
            Text(
              episode.title ?? 'Unknown',
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w600,
                color: Theme.of(context).colorScheme.onSurface,
              ),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              textAlign: TextAlign.center,
            ),
          ],
        ),
      );
    }
  }

  PodcastEpisodeModel _episodeToModel(dynamic episode) {
    return PodcastEpisodeModel(
      id: episode.id,
      subscriptionId: episode.subscriptionId,
      subscriptionImageUrl: episode.subscriptionImageUrl,
      title: episode.title,
      description: episode.description,
      audioUrl: episode.audioUrl,
      audioDuration: episode.audioDuration,
      audioFileSize: episode.audioFileSize,
      publishedAt: episode.publishedAt,
      imageUrl: episode.imageUrl,
      itemLink: episode.itemLink,
      transcriptUrl: episode.transcriptUrl,
      transcriptContent: episode.transcriptContent,
      aiSummary: episode.aiSummary,
      summaryVersion: episode.summaryVersion,
      aiConfidenceScore: episode.aiConfidenceScore,
      playCount: episode.playCount,
      lastPlayedAt: episode.lastPlayedAt,
      season: episode.season,
      episodeNumber: episode.episodeNumber,
      explicit: episode.explicit,
      status: episode.status,
      metadata: episode.metadata,
      playbackPosition: episode.playbackPosition,
      isPlaying: episode.isPlaying,
      playbackRate: episode.playbackRate,
      isPlayed: episode.isPlayed ?? false,
      createdAt: episode.createdAt,
      updatedAt: episode.updatedAt,
    );
  }

  Future<void> _playOrResumeFromDetail(PodcastEpisodeModel episodeModel) async {
    final notifier = ref.read(audioPlayerProvider.notifier);
    final playerState = ref.read(audioPlayerProvider);
    final isSameEpisode = playerState.currentEpisode?.id == episodeModel.id;
    final isCompleted =
        playerState.processingState == ProcessingState.completed;

    if (isSameEpisode && !isCompleted) {
      if (playerState.isPlaying) {
        return;
      }
      await notifier.resume();
      return;
    }

    await notifier.playEpisode(episodeModel);
  }

  Widget _buildPlayButton(dynamic episode, AppLocalizations l10n) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        InkWell(
          onTap: () async {
            try {
              await _playOrResumeFromDetail(_episodeToModel(episode));
            } catch (error) {
              logger.AppLogger.debug('[Error] Failed to play episode: $error');
            }
          },
          child: Container(
            key: const Key('podcast_episode_detail_play_button'),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: BoxDecoration(
              color: Theme.of(
                context,
              ).colorScheme.primary.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(20),
              border: Border.all(
                color: Theme.of(
                  context,
                ).colorScheme.primary.withValues(alpha: 0.3),
                width: 1,
              ),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  Icons.play_arrow,
                  size: 18,
                  color: Theme.of(context).colorScheme.primary,
                ),
                const SizedBox(width: 4),
                Text(
                  l10n.podcast_play_episode_full,
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(width: 8),
        InkWell(
          onTap: () async {
            try {
              await ref
                  .read(podcastQueueControllerProvider.notifier)
                  .addToQueue(widget.episodeId);
              if (mounted) {
                final l10n = AppLocalizations.of(context)!;
                ScaffoldMessenger.of(
                  context,
                ).showSnackBar(SnackBar(content: Text(l10n.added_to_queue)));
              }
            } catch (error) {
              if (mounted) {
                final l10n = AppLocalizations.of(context)!;
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text(
                      l10n.failed_to_add_to_queue(error.toString()),
                    ),
                  ),
                );
              }
            }
          },
          child: Container(
            padding: const EdgeInsets.all(6),
            decoration: BoxDecoration(
              color: Theme.of(
                context,
              ).colorScheme.primary.withValues(alpha: 0.08),
              borderRadius: BorderRadius.circular(18),
              border: Border.all(
                color: Theme.of(
                  context,
                ).colorScheme.primary.withValues(alpha: 0.3),
                width: 1,
              ),
            ),
            child: Icon(
              Icons.playlist_add,
              size: 18,
              color: Theme.of(context).colorScheme.primary,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildCollapsedFloatingActions(
    dynamic episode,
    AppLocalizations l10n,
  ) {
    return Container(
      key: const Key('podcast_episode_detail_collapsed_actions'),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          _buildBackButton(),
          const SizedBox(width: 8),
          _buildPlayButton(episode, l10n),
        ],
      ),
    );
  }

  Widget _buildBackButton() {
    return Container(
      width: 32,
      height: 32,
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
          width: 1,
        ),
      ),
      child: InkWell(
        onTap: () => context.pop(),
        borderRadius: BorderRadius.circular(8),
        child: Center(
          child: Icon(
            Icons.arrow_back,
            color: Theme.of(context).colorScheme.primary,
            size: 18,
          ),
        ),
      ),
    );
  }

  Widget _buildDateChip(dynamic episode) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(
          Icons.calendar_today_outlined,
          size: 14,
          color: Theme.of(context).colorScheme.onSurfaceVariant,
        ),
        const SizedBox(width: 6),
        Text(
          _formatDate(episode.publishedAt),
          style: TextStyle(
            fontSize: 13,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
      ],
    );
  }

  Widget _buildDurationChip(dynamic episode) {
    return Consumer(
      builder: (context, ref, _) {
        final audioPlayerState = ref.watch(audioPlayerProvider);
        final displayDuration =
            (audioPlayerState.currentEpisode?.id == episode.id &&
                audioPlayerState.duration > 0)
            ? audioPlayerState.duration
            : (episode.audioDuration! * 1000);
        final duration = Duration(milliseconds: displayDuration);
        final hours = duration.inHours;
        final minutes = duration.inMinutes.remainder(60);
        final seconds = duration.inSeconds.remainder(60);

        final formattedDuration = hours > 0
            ? '$hours:${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}'
            : '${minutes.toString().padLeft(2, '0')}:${seconds.toString().padLeft(2, '0')}';

        return Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.schedule_outlined,
              size: 14,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            const SizedBox(width: 6),
            Text(
              formattedDuration,
              style: TextStyle(
                fontSize: 13,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        );
      },
    );
  }

  Widget _buildSourceLinkChip(dynamic episode, AppLocalizations l10n) {
    return InkWell(
      onTap: () async {
        final Uri linkUri = Uri.parse(episode.itemLink!);
        if (await canLaunchUrl(linkUri)) {
          await launchUrl(linkUri, mode: LaunchMode.externalApplication);
        }
      },
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.link,
            size: 14,
            color: Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(width: 6),
          Text(
            l10n.podcast_source,
            style: TextStyle(
              fontSize: 13,
              color: Theme.of(context).colorScheme.primary,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTopButtonBar() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.fromLTRB(8, 0, 8, 0),
      decoration: BoxDecoration(
        border: Border(
          bottom: BorderSide(
            color: Theme.of(context).colorScheme.outlineVariant,
            width: 1,
          ),
        ),
      ),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: Row(
          mainAxisAlignment: MainAxisAlignment.start,
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            // Shownotes Tab
            _buildTabButton(
              tabIndex: 0,
              text: AppLocalizations.of(context)!.podcast_tab_shownotes,
              isSelected: _selectedTabIndex == 0,
              onTap: () {
                if (_selectedTabIndex != 0) {
                  setState(() {
                    _updateHeaderStateForTab(0);
                  });
                  _pageController.animateToPage(
                    0,
                    duration: const Duration(milliseconds: 300),
                    curve: Curves.easeInOut,
                  );
                }
              },
            ),
            // Transcript Tab
            _buildTabButton(
              tabIndex: 1,
              text: AppLocalizations.of(context)!.podcast_tab_transcript,
              isSelected: _selectedTabIndex == 1,
              onTap: () {
                if (_selectedTabIndex != 1) {
                  setState(() {
                    _updateHeaderStateForTab(1);
                  });
                  _pageController.animateToPage(
                    1,
                    duration: const Duration(milliseconds: 300),
                    curve: Curves.easeInOut,
                  );
                }
              },
            ),
            // AI Summary Tab
            _buildTabButton(
              tabIndex: 2,
              text: AppLocalizations.of(context)!.podcast_filter_with_summary,
              isSelected: _selectedTabIndex == 2,
              onTap: () {
                if (_selectedTabIndex != 2) {
                  setState(() {
                    _updateHeaderStateForTab(2);
                  });
                  _pageController.animateToPage(
                    2,
                    duration: const Duration(milliseconds: 300),
                    curve: Curves.easeInOut,
                  );
                }
              },
            ),
            // Conversation Tab
            _buildTabButton(
              tabIndex: 3,
              text: AppLocalizations.of(context)!.podcast_tab_chat,
              isSelected: _selectedTabIndex == 3,
              onTap: () {
                if (_selectedTabIndex != 3) {
                  setState(() {
                    _updateHeaderStateForTab(3);
                  });
                  _pageController.animateToPage(
                    3,
                    duration: const Duration(milliseconds: 300),
                    curve: Curves.easeInOut,
                  );
                }
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildLeftSidebar() {
    return Container(
      width: 200,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      decoration: BoxDecoration(
        border: Border(
          right: BorderSide(
            color: Theme.of(context).colorScheme.outlineVariant,
            width: 1,
          ),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Shownotes Tab
          _buildSidebarTabButton(
            AppLocalizations.of(context)!.podcast_tab_shownotes,
            _selectedTabIndex == 0,
            () {
              if (_selectedTabIndex != 0) {
                setState(() {
                  _selectedTabIndex = 0;
                  _stopSummaryPolling();
                  _updateHeaderStateForTab(0);
                });
              }
            },
          ),
          const SizedBox(height: 8),
          // Transcript Tab
          _buildSidebarTabButton(
            AppLocalizations.of(context)!.podcast_tab_transcript,
            _selectedTabIndex == 1,
            () {
              if (_selectedTabIndex != 1) {
                setState(() {
                  _selectedTabIndex = 1;
                  _stopSummaryPolling();
                  _updateHeaderStateForTab(1);
                });
              }
            },
          ),
          const SizedBox(height: 8),
          // AI Summary Tab
          _buildSidebarTabButton(
            AppLocalizations.of(context)!.podcast_filter_with_summary,
            _selectedTabIndex == 2,
            () {
              if (_selectedTabIndex != 2) {
                setState(() {
                  _selectedTabIndex = 2;
                  _startSummaryPolling();
                  _updateHeaderStateForTab(2);
                });
              }
            },
          ),
          const SizedBox(height: 8),
          // Conversation Tab
          _buildSidebarTabButton(
            AppLocalizations.of(context)!.podcast_tab_chat,
            _selectedTabIndex == 3,
            () {
              if (_selectedTabIndex != 3) {
                setState(() {
                  _selectedTabIndex = 3;
                  _stopSummaryPolling();
                  _updateHeaderStateForTab(3);
                });
              }
            },
          ),
        ],
      ),
    );
  }

  Widget _buildSidebarTabButton(
    String text,
    bool isSelected,
    VoidCallback onTap,
  ) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
        decoration: BoxDecoration(
          color: isSelected
              ? Theme.of(context).colorScheme.primaryContainer
              : Colors.transparent,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: isSelected
                ? Theme.of(context).colorScheme.primary
                : Colors.transparent,
            width: 1,
          ),
        ),
        child: Text(
          text,
          textAlign: TextAlign.center,
          style: TextStyle(
            color: isSelected
                ? Theme.of(context).colorScheme.onPrimaryContainer
                : Theme.of(context).colorScheme.onSurfaceVariant,
            fontSize: 13,
            fontWeight: isSelected ? FontWeight.w600 : FontWeight.w500,
          ),
        ),
      ),
    );
  }

  Widget _buildTabButton({
    required int tabIndex,
    required String text,
    required bool isSelected,
    required VoidCallback onTap,
  }) {
    final colorScheme = Theme.of(context).colorScheme;
    final textStyle = DefaultTextStyle.of(context).style.copyWith(
      color: isSelected ? colorScheme.onSurface : colorScheme.onSurfaceVariant,
      fontSize: 13,
      fontWeight: isSelected ? FontWeight.w600 : FontWeight.w500,
      decoration: TextDecoration.none,
      decorationColor: Colors.transparent,
    );
    final textPainter = TextPainter(
      text: TextSpan(text: text, style: textStyle),
      textDirection: Directionality.of(context),
      textScaler: MediaQuery.textScalerOf(context),
      locale: Localizations.maybeLocaleOf(context),
      maxLines: 1,
    )..layout(minWidth: 0, maxWidth: double.infinity);
    final indicatorWidth = textPainter.width;

    return GestureDetector(
      key: Key('episode_detail_mobile_tab_$tabIndex'),
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.only(left: 10, right: 10, top: 6),
        color: Colors.transparent,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(text, style: textStyle),
            const SizedBox(height: 6),
            Container(
              key: Key('episode_detail_mobile_tab_indicator_$tabIndex'),
              width: indicatorWidth,
              height: 3,
              decoration: BoxDecoration(
                color: isSelected ? colorScheme.primary : Colors.transparent,
                borderRadius: BorderRadius.circular(999),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTabContent(dynamic episode) {
    switch (_selectedTabIndex) {
      case 0:
        return ShownotesDisplayWidget(key: _shownotesKey, episode: episode);
      case 1:
        return _buildTranscriptContent(episode);
      case 2:
        return _buildAiSummaryContent(episode);
      case 3:
        return _buildConversationContent(episode);
      default:
        return ShownotesDisplayWidget(key: _shownotesKey, episode: episode);
    }
  }

  Widget _buildSingleTabContent(dynamic episode, int index) {
    switch (index) {
      case 0:
        return ShownotesDisplayWidget(key: _shownotesKey, episode: episode);
      case 1:
        return _buildTranscriptContent(episode);
      case 2:
        return _buildAiSummaryContent(episode);
      case 3:
        return _buildConversationContent(episode);
      default:
        return ShownotesDisplayWidget(key: _shownotesKey, episode: episode);
    }
  }

  Widget _buildTranscriptContent(dynamic episode) {
    final transcriptionProvider = getTranscriptionProvider(widget.episodeId);
    final transcriptionState = ref.watch(transcriptionProvider);

    return transcriptionState.when(
      data: (transcription) {
        // If transcription is completed, show the text
        if (transcription != null && isTranscriptionCompleted(transcription)) {
          return TranscriptDisplayWidget(
            key: _transcriptKey,
            episodeId: widget.episodeId,
            episodeTitle: episode.title ?? '',
            transcription: transcription,
          );
        }

        // Otherwise (pending, processing, failed, or null), show the status widget
        return TranscriptionStatusWidget(
          episodeId: widget.episodeId,
          transcription: transcription,
        );
      },
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (error, stack) => _buildTranscriptErrorState(context, error),
    );
  }

  Widget _buildTranscriptErrorState(BuildContext context, dynamic error) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.error_outline,
            size: 64,
            color: Theme.of(context).colorScheme.error,
          ),
          const SizedBox(height: 16),
          Text(
            AppLocalizations.of(context)!.podcast_transcription_failed,
            style: TextStyle(
              fontSize: 16,
              color: Theme.of(context).colorScheme.onSurface,
            ),
          ),
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 32),
            child: Text(
              error.toString(),
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 14,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ),
        ],
      ),
    );
  }

  void _showShareErrorSnackBar(String message) {
    if (!mounted) {
      return;
    }
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _shareSelectedSummaryAsImage(
    String episodeTitle,
    String fullSummaryMarkdown,
  ) async {
    final l10n = AppLocalizations.of(context)!;
    final markdownSelection = extractMarkdownSelection(
      markdown: fullSummaryMarkdown,
      selectedText: _selectedSummaryText,
    );
    try {
      await ContentImageShareService.shareAsImage(
        context,
        ShareImagePayload(
          episodeTitle: episodeTitle,
          contentType: ShareContentType.summary,
          content: markdownSelection,
          sourceLabel: l10n.podcast_filter_with_summary,
          renderMode: ShareImageRenderMode.markdown,
        ),
      );
    } on ContentImageShareException catch (e) {
      _showShareErrorSnackBar(e.message);
    }
  }

  Future<void> _shareAllSummaryAsImage(
    String episodeTitle,
    String summary,
  ) async {
    final l10n = AppLocalizations.of(context)!;
    try {
      await ContentImageShareService.shareAsImage(
        context,
        ShareImagePayload(
          episodeTitle: episodeTitle,
          contentType: ShareContentType.summary,
          content: summary,
          sourceLabel: l10n.podcast_filter_with_summary,
          renderMode: ShareImageRenderMode.markdown,
        ),
      );
    } on ContentImageShareException catch (e) {
      _showShareErrorSnackBar(e.message);
    }
  }

  Widget _buildAiSummaryContent(dynamic episode) {
    final provider = getSummaryProvider(widget.episodeId);
    final summaryState = ref.watch(provider);
    final summaryNotifier = ref.read(provider.notifier);
    final transcriptionProvider = getTranscriptionProvider(widget.episodeId);
    final transcriptionState = ref.watch(transcriptionProvider);

    if (episode.aiSummary != null &&
        episode.aiSummary!.isNotEmpty &&
        !summaryState.hasSummary &&
        !summaryState.isLoading) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        summaryNotifier.updateSummary(episode.aiSummary!);
      });
    }

    return ScrollableContentWrapper(
      key: _aiSummaryKey,
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          AISummaryControlWidget(
            episodeId: widget.episodeId,
            hasTranscript:
                transcriptionState.value?.transcriptContent != null &&
                transcriptionState.value!.transcriptContent!.isNotEmpty,
          ),

          const SizedBox(height: 16),

          if (summaryState.isLoading) ...[
            Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const CircularProgressIndicator(),
                  const SizedBox(height: 16),
                  Text(
                    AppLocalizations.of(context)!.podcast_generating_summary,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                      fontSize: 14,
                    ),
                  ),
                ],
              ),
            ),
          ] else if (summaryState.hasError) ...[
            Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.error_outline,
                    size: 48,
                    color: Theme.of(context).colorScheme.error,
                  ),
                  const SizedBox(height: 16),
                  Text(
                    summaryState.errorMessage ??
                        AppLocalizations.of(
                          context,
                        )!.podcast_summary_generate_failed,
                    style: TextStyle(
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ],
              ),
            ),
          ] else if (summaryState.hasSummary) ...[
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Theme.of(
                  context,
                ).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(
                        Icons.auto_awesome,
                        size: 20,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                      const SizedBox(width: 8),
                      Text(
                        AppLocalizations.of(
                          context,
                        )!.podcast_filter_with_summary,
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                      ),
                      const Spacer(),
                      TextButton.icon(
                        onPressed: () => unawaited(
                          _shareAllSummaryAsImage(
                            episode.title ?? '',
                            summaryState.summary!,
                          ),
                        ),
                        icon: const Icon(Icons.ios_share_outlined, size: 16),
                        label: Text(
                          AppLocalizations.of(
                            context,
                          )!.podcast_share_all_content,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  SelectionArea(
                    onSelectionChanged: (selectedContent) {
                      _selectedSummaryText =
                          selectedContent?.plainText.trim() ?? '';
                    },
                    contextMenuBuilder: (context, selectableRegionState) {
                      return AdaptiveTextSelectionToolbar.buttonItems(
                        anchors: selectableRegionState.contextMenuAnchors,
                        buttonItems: [
                          ...selectableRegionState.contextMenuButtonItems,
                          ContextMenuButtonItem(
                            label: AppLocalizations.of(
                              context,
                            )!.podcast_share_as_image,
                            onPressed: () {
                              ContextMenuController.removeAny();
                              unawaited(
                                _shareSelectedSummaryAsImage(
                                  episode.title ?? '',
                                  summaryState.summary!,
                                ),
                              );
                            },
                          ),
                        ],
                      );
                    },
                    child: MarkdownBody(
                      data: summaryState.summary!,
                      styleSheet: MarkdownStyleSheet(
                        p: TextStyle(
                          fontSize: 15,
                          height: 1.6,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                        h1: TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                        h2: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                        h3: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                        listBullet: TextStyle(
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                        strong: TextStyle(
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ] else if (episode.aiSummary != null &&
              episode.aiSummary!.isNotEmpty) ...[
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Theme.of(
                  context,
                ).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(
                        Icons.auto_awesome,
                        size: 20,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                      const SizedBox(width: 8),
                      Text(
                        AppLocalizations.of(
                          context,
                        )!.podcast_filter_with_summary,
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                      ),
                      const Spacer(),
                      TextButton.icon(
                        onPressed: () => unawaited(
                          _shareAllSummaryAsImage(
                            episode.title ?? '',
                            episode.aiSummary!,
                          ),
                        ),
                        icon: const Icon(Icons.ios_share_outlined, size: 16),
                        label: Text(
                          AppLocalizations.of(
                            context,
                          )!.podcast_share_all_content,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  SelectionArea(
                    onSelectionChanged: (selectedContent) {
                      _selectedSummaryText =
                          selectedContent?.plainText.trim() ?? '';
                    },
                    contextMenuBuilder: (context, selectableRegionState) {
                      return AdaptiveTextSelectionToolbar.buttonItems(
                        anchors: selectableRegionState.contextMenuAnchors,
                        buttonItems: [
                          ...selectableRegionState.contextMenuButtonItems,
                          ContextMenuButtonItem(
                            label: AppLocalizations.of(
                              context,
                            )!.podcast_share_as_image,
                            onPressed: () {
                              ContextMenuController.removeAny();
                              unawaited(
                                _shareSelectedSummaryAsImage(
                                  episode.title ?? '',
                                  episode.aiSummary!,
                                ),
                              );
                            },
                          ),
                        ],
                      );
                    },
                    child: MarkdownBody(
                      data: episode.aiSummary!,
                      styleSheet: MarkdownStyleSheet(
                        p: TextStyle(
                          fontSize: 15,
                          height: 1.6,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                        h1: TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                        h2: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                        h3: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                        listBullet: TextStyle(
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                        strong: TextStyle(
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ] else ...[
            _buildAiSummaryEmptyState(context),
          ],
        ],
      ),
    );
  }

  Widget _buildAiSummaryEmptyState(BuildContext context) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.auto_awesome,
            size: 64,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(height: 16),
          Text(
            AppLocalizations.of(context)!.podcast_summary_no_summary,
            style: TextStyle(
              fontSize: 16,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            AppLocalizations.of(context)!.podcast_summary_empty_hint,
            style: TextStyle(
              fontSize: 14,
              color: Theme.of(
                context,
              ).colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildConversationContent(dynamic episode) {
    final episodeDetailAsync = ref.watch(
      episodeDetailProvider(widget.episodeId),
    );

    return episodeDetailAsync.when(
      data: (episode) {
        if (episode == null) {
          return Center(
            child: Text(
              AppLocalizations.of(context)!.podcast_episode_not_found,
            ),
          );
        }
        return ConversationChatWidget(
          key: _conversationKey,
          episodeId: widget.episodeId,
          episodeTitle: episode.title,
          aiSummary: episode.aiSummary,
        );
      },
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (error, stack) => Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.error_outline,
              size: 64,
              color: Theme.of(context).colorScheme.error,
            ),
            const SizedBox(height: 16),
            Text(
              AppLocalizations.of(context)!.podcast_load_failed,
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              error.toString(),
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }

  String _formatDate(DateTime date) {
    final localDate = date.isUtc ? date.toLocal() : date;
    final year = localDate.year;
    final month = localDate.month.toString().padLeft(2, '0');
    final day = localDate.day.toString().padLeft(2, '0');
    final l10n = AppLocalizations.of(context)!;
    return l10n.date_format(year, month, day);
  }

  Widget _buildErrorState(BuildContext context, dynamic error) {
    final l10n = AppLocalizations.of(context)!;
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.error_outline, size: 64, color: Colors.red),
          const SizedBox(height: 16),
          Text(
            l10n.podcast_error_loading,
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 32),
            child: Text(
              error.toString(),
              textAlign: TextAlign.center,
              style: Theme.of(
                context,
              ).textTheme.bodyMedium?.copyWith(color: Colors.grey[600]),
            ),
          ),
          const SizedBox(height: 24),
          ElevatedButton(
            onPressed: () {
              context.pop();
            },
            child: Text(l10n.podcast_go_back),
          ),
        ],
      ),
    );
  }

  @override
  void didUpdateWidget(PodcastEpisodeDetailPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    // Check if episodeId has changed
    if (oldWidget.episodeId != widget.episodeId) {
      logger.AppLogger.debug(
        '[Playback] ===== didUpdateWidget: Episode ID changed =====',
      );
      logger.AppLogger.debug(
        '[Playback] Old Episode ID: ${oldWidget.episodeId}',
      );
      logger.AppLogger.debug('[Playback] New Episode ID: ${widget.episodeId}');
      logger.AppLogger.debug(
        '[Playback] Reloading episode data and auto-playing new episode',
      );

      // Invalidate old episode detail provider to force refresh
      logger.AppLogger.debug(
        '[Playback] Invalidating old episode detail provider',
      );
      ref.invalidate(episodeDetailProvider(oldWidget.episodeId));
      _hasTrackedEpisodeView = false;

      // Reset tab selection
      _selectedTabIndex = 0;

      // Stop any ongoing polling
      _summaryPollingTimer?.cancel();
      _isPolling = false;

      // Reload data for the new episode
      WidgetsBinding.instance.addPostFrameCallback((_) {
        logger.AppLogger.debug(
          '[Playback] Calling _loadAndPlayEpisode for new episode',
        );
        _loadAndPlayEpisode();
        _loadTranscriptionStatus();
      });
      logger.AppLogger.debug('[Playback] ===== didUpdateWidget complete =====');
    }
  }

  void _startSummaryPolling() async {
    _summaryPollingTimer?.cancel();
    _isPolling = false;

    try {
      final episodeDetailAsync = await ref.read(
        episodeDetailProvider(widget.episodeId).future,
      );
      if (episodeDetailAsync != null &&
          episodeDetailAsync.aiSummary != null &&
          episodeDetailAsync.aiSummary!.isNotEmpty) {
        logger.AppLogger.debug(
          '[AI Summary] Summary already exists, skipping polling',
        );
        return;
      }
    } catch (e) {
      logger.AppLogger.debug(
        '[AI Summary] Failed to check initial summary state: $e',
      );
    }

    _isPolling = true;
    logger.AppLogger.debug('[AI Summary] Starting polling...');

    _summaryPollingTimer = Timer.periodic(const Duration(seconds: 5), (
      timer,
    ) async {
      if (!mounted || !_isPolling) {
        timer.cancel();
        return;
      }

      try {
        final episodeDetailAsync = await ref.read(
          episodeDetailProvider(widget.episodeId).future,
        );

        if (episodeDetailAsync != null) {
          if (episodeDetailAsync.aiSummary != null &&
              episodeDetailAsync.aiSummary!.isNotEmpty) {
            logger.AppLogger.debug(
              '[AI Summary] Summary generated, stopping polling',
            );
            _stopSummaryPolling();
            return;
          }
        }

        ref.invalidate(episodeDetailProvider(widget.episodeId));
      } catch (e) {
        logger.AppLogger.debug('[AI Summary] Error during polling: $e');
      }
    });
  }

  void _stopSummaryPolling() {
    _summaryPollingTimer?.cancel();
    _summaryPollingTimer = null;
    _isPolling = false;
    logger.AppLogger.debug('[AI Summary] Stopped polling');
  }

  // Use actual platform type instead of width breakpoints.
  // Mobile platforms return true, desktop/web-like targets return false.
  bool _isMobilePlatform() {
    switch (Theme.of(context).platform) {
      case TargetPlatform.iOS:
      case TargetPlatform.android:
        return true;
      case TargetPlatform.windows:
      case TargetPlatform.macOS:
      case TargetPlatform.linux:
      case TargetPlatform.fuchsia:
        return false;
    }
  }

  bool _shouldShowScrollToTopButton() {
    final scrollPosition = _tabScrollPositions[_selectedTabIndex] ?? 0.0;
    return scrollPosition > 0;
  }

  Widget _buildScrollToTopButton() {
    final screenSize = MediaQuery.of(context).size;
    final isMobile = screenSize.width < 600;

    final rightMargin = isMobile ? 32.0 : (screenSize.width * 0.1);
    final bottomMargin = isMobile ? (screenSize.height * 0.1) : 32.0;

    return Padding(
      padding: EdgeInsets.only(right: rightMargin, bottom: bottomMargin),
      child: Material(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(16),
        elevation: 2,
        child: InkWell(
          onTap: _scrollToTop,
          borderRadius: BorderRadius.circular(16),
          child: Container(
            width: 32,
            height: 32,
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: Theme.of(
                  context,
                ).colorScheme.outline.withValues(alpha: 0.5),
                width: 1,
              ),
            ),
            child: Icon(
              Icons.arrow_upward,
              color: Theme.of(context).colorScheme.onSurface,
              size: 18,
            ),
          ),
        ),
      ),
    );
  }

  void _scrollToTop() {
    // Reset scroll offset to expand header
    setState(() {
      _scrollOffset = 0.0;
      _tabScrollPositions[_selectedTabIndex] = 0.0;
      _tabScrollPercentages[_selectedTabIndex] = 0.0;
    });

    // Call scrollToTop on the appropriate widget based on the current tab
    switch (_selectedTabIndex) {
      case 0: // Shownotes
        _shownotesKey.currentState?.scrollToTop();
        break;
      case 1: // Transcript
        _transcriptKey.currentState?.scrollToTop();
        break;
      case 2: // AI Summary
        _aiSummaryKey.currentState?.scrollToTop();
        break;
      case 3: // Conversation
        _conversationKey.currentState?.scrollToTop();
        break;
    }
  }
}
