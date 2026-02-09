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
  Timer? _summaryPollingTimer; // AI鎽樿杞瀹氭椂鍣?
  bool _isPolling = false; // Guard flag to prevent multiple polls

  // Sticky header animation
  final ScrollController _scrollController = ScrollController();
  final PageController _pageController = PageController(); // 鐢ㄤ簬绉诲姩绔〉闈㈠垏鎹?
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
    const maxHeaderHeight = 100.0; // 鏈€澶ц鍓珮搴︼紙瓒冲鏄剧ず瀹屾暣 header锛?
    if (_scrollOffset <= 0) return maxHeaderHeight;
    if (_scrollOffset >= _headerScrollThreshold) return 0.0;
    return maxHeaderHeight * (1 - _scrollOffset / _headerScrollThreshold);
  }

  // Check if header should be in expanded state (妯法鏁翠釜椤堕儴)
  bool get _isHeaderExpanded {
    return _scrollOffset < _headerScrollThreshold;
  }

  Future<void> _loadAndPlayEpisode() async {
    logger.AppLogger.debug('馃幍 ===== _loadAndPlayEpisode called =====');
    logger.AppLogger.debug('馃幍 widget.episodeId: ${widget.episodeId}');

    try {
      // Wait for episode detail to be loaded
      final episodeDetailAsync = await ref.read(
        episodeDetailProvider(widget.episodeId).future,
      );

      logger.AppLogger.debug(
        '馃幍 Loaded episode detail: ID=${episodeDetailAsync?.id}, Title=${episodeDetailAsync?.title}',
      );

      // Debug: Log itemLink from API response
      if (episodeDetailAsync != null) {
        logger.AppLogger.debug(
          '馃敆 [API Response] itemLink: ${episodeDetailAsync.itemLink ?? "NULL"}',
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
          itemLink: episodeDetailAsync.itemLink, // 鈫?娣诲姞杩欎竴琛?
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
          '馃幍 Auto-playing episode: ${episodeModel.title}',
        );
        await ref.read(audioPlayerProvider.notifier).playEpisode(episodeModel);
      }
    } catch (error) {
      logger.AppLogger.debug('鉂?Failed to auto-play episode: $error');
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
      logger.AppLogger.debug('鉂?Failed to load transcription status: $error');
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
      bottomNavigationBar: const PodcastBottomPlayerWidget(),
      body: episodeDetailAsync.when(
        data: (episodeDetail) {
          if (episodeDetail == null) {
            return _buildErrorState(context, 'Episode not found');
          }
          return _buildNewLayout(context, episodeDetail);
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => _buildErrorState(context, error),
      ),
    );
  }

  // 鏂扮殑椤甸潰甯冨眬锛堝甫鍚搁《鏁堟灉锛?
  Widget _buildNewLayout(BuildContext context, dynamic episode) {
    return LayoutBuilder(
      builder: (context, layoutConstraints) {
        final isWideScreen = layoutConstraints.maxWidth > 800;

        if (isWideScreen) {
          // 瀹藉睆锛氬甫鍙粴鍔ㄦ敹缂?Header 鐨勫竷灞€
          return Stack(
            children: [
              // 涓诲唴瀹硅锛氬乏渚ц竟鏍?+ 鍙充晶鍐呭鍖?
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // 宸︿晶杈规爮锛堝寘鍚爣绛炬寜閽紝椤堕儴棰勭暀 Header 绌洪棿锛?
                  SizedBox(
                    width: 200,
                    child: Column(
                      children: [
                        // 棰勭暀绌洪棿锛氭牴鎹?Header 鐘舵€佸姩鎬佽皟鏁?
                        AnimatedContainer(
                          duration: const Duration(milliseconds: 200),
                          curve: Curves.easeInOut,
                          height: _isHeaderExpanded ? 90 : 100,
                        ),
                        // 宸︿晶鏍囩鏍忥紙鍙粴鍔級
                        Expanded(
                          child: SingleChildScrollView(
                            child: _buildLeftSidebar(),
                          ),
                        ),
                      ],
                    ),
                  ),
                  // 鍙充晶鍐呭鍖?
                  Expanded(
                    child: Stack(
                      children: [
                        // 鍐呭鍖?
                        NotificationListener<ScrollNotification>(
                          onNotification: (scrollNotification) {
                            _handleAutoCollapseOnRead(scrollNotification);
                            // 鐩戝惉鎵€鏈夐〉闈㈢殑婊氬姩鏇存柊浠ュ疄鐜?header 鏀惰捣鏁堟灉鍜屾樉绀烘诞鍔ㄦ寜閽?
                            if (scrollNotification
                                is ScrollUpdateNotification) {
                              final metrics = scrollNotification.metrics;
                              // 鐩戝惉鎵€鏈夋爣绛鹃〉鐨勫瀭鐩存粴鍔?
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
                        // 娴姩鍚戜笂鎸夐挳
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
              // 鍙Щ鍔ㄧ殑 Header (浣跨敤 AnimatedPositioned 瀹炵幇骞虫粦绉诲姩)
              AnimatedPositioned(
                duration: const Duration(milliseconds: 200),
                curve: Curves.easeInOut,
                top: 0,
                left: 0,
                right: _isHeaderExpanded ? 0 : null,
                width: _isHeaderExpanded ? null : 200,
                child: _buildAnimatedHeader(episode),
              ),
              // 娴姩鐨勮繑鍥炴寜閽紙鏀剁缉鐘舵€佹椂鏄剧ず鍦ㄥ彸涓婃柟锛?
              if (!_isHeaderExpanded)
                Positioned(top: 16, right: 16, child: _buildBackButton()),
              // 娴姩鐨勬挱鏀炬寜閽紙鏀剁缉鐘舵€佹椂鏄剧ず锛?
              if (!_isHeaderExpanded)
                Positioned(
                  top: 16,
                  right: 80,
                  child: _buildPlayButton(
                    episode,
                    AppLocalizations.of(context)!,
                  ),
                ),
            ],
          );
        } else {
          // 绐勫睆锛氬瀭鐩村竷灞€
          // 鑾峰彇椤堕儴瀹夊叏鍖哄煙楂樺害锛堢姸鎬佹爮楂樺害锛?
          final topPadding = MediaQuery.of(context).padding.top;
          // 纭繚鑷冲皯鏈?8 鍍忕礌鐨勫熀纭€闂磋窛
          final totalTopPadding = topPadding > 0 ? topPadding + 8.0 : 8.0;

          return Column(
            children: [
              // 娣诲姞缁熶竴鐨勫畨鍏ㄥ尯鍩熼棿璺濓紝鍖呰９ header 鍜屾寜閽爮
              Padding(
                padding: EdgeInsets.only(top: totalTopPadding),
                child: Column(
                  children: [
                    // A. 椤堕儴鍏冩暟鎹尯 (Header) - 甯︽贰鍑哄拰鏀惰捣鍔ㄧ敾
                    ClipRect(
                      child: Align(
                        alignment: Alignment.topCenter,
                        heightFactor: _headerClipHeight / 100.0, // 褰掍竴鍖栭珮搴﹀洜瀛?
                        child: AnimatedOpacity(
                          opacity: _headerOpacity,
                          duration: const Duration(milliseconds: 100),
                          curve: Curves.easeInOut,
                          child: _buildHeader(episode),
                        ),
                      ),
                    ),

                    // B. 鍥哄畾鐨勬爣绛炬爮 - 鍚搁《鏁堟灉锛堢揣鎺ュ湪 header 涓嬫柟锛?
                    _buildTopButtonBar(),
                  ],
                ),
              ),

              // C. 涓棿涓讳綋鍐呭鍖?(Body) - 浣跨敤 PageView 鏀寔婊戝姩鍒囨崲
              Expanded(
                child: Stack(
                  children: [
                    // 鍐呭鍖?
                    NotificationListener<ScrollNotification>(
                      onNotification: (scrollNotification) {
                        _handleAutoCollapseOnRead(scrollNotification);
                        // 鐩戝惉婊氬姩鏇存柊浠ュ疄鐜?header 鏀惰捣鏁堟灉鍜屾樉绀烘诞鍔ㄦ寜閽?
                        if (scrollNotification is ScrollUpdateNotification) {
                          final metrics = scrollNotification.metrics;
                          // 鑾峰彇褰撳墠椤甸潰鐨勬粴鍔ㄤ綅缃?
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
                            // 鍒囨崲鏍囩鏃剁殑杞鎺у埗
                            if (index == 2) {
                              _startSummaryPolling();
                            } else {
                              _stopSummaryPolling();
                            }
                            // 閲嶇疆婊氬姩鍋忕Щ
                            _scrollOffset = 0;
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
                    // 娴姩鍚戜笂鎸夐挳
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

  // A. 椤堕儴鍏冩暟鎹尯 (Header) - 鏃犲簳閮ㄥ垎鍓茬嚎
  Widget _buildHeader(dynamic episode) {
    final l10n = AppLocalizations.of(context)!;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      color: Theme.of(context).colorScheme.surface,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // 宸︿晶锛歀ogo锛堢嫭鍗犱袱琛岋級
          PodcastImageWidget(
            imageUrl: episode.imageUrl,
            fallbackImageUrl: episode.subscriptionImageUrl,
            width: 60,
            height: 60,
            iconSize: 32,
          ),
          const SizedBox(width: 16),
          // 鍙充晶锛氭爣棰樺拰鍙戝竷鏃堕棿
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                // 绗竴琛岋細鏍囬 + 鎾斁鎸夐挳
                Row(
                  children: [
                    // 鏍囬鍜屾挱鏀炬寜閽斁鍦ㄤ竴璧?
                    Expanded(
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Flexible(
                            child: Text(
                              episode.title ?? 'Unknown Episode',
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
                          // 鎾斁鎸夐挳
                          InkWell(
                            onTap: () async {
                              try {
                                await _playOrResumeFromDetail(
                                  _episodeToModel(episode),
                                );
                              } catch (error) {
                                logger.AppLogger.debug(
                                  '鉂?Failed to play episode: $error',
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
                                    // 鏍规嵁灞忓箷瀹藉害鏄剧ず涓嶅悓鏂囨湰锛氱Щ鍔ㄧ鏄剧ず"鎾斁"锛屾闈㈢鏄剧ず"鎾斁姝ら泦"
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
                    // 杩斿洖鎸夐挳 - 浠呭湪闈炵Щ鍔ㄨ澶囦笂鏄剧ず
                    // 娉ㄦ剰锛氳繖閲屾娴嬬殑鏄湡姝ｇ殑骞冲彴绫诲瀷锛岃€屼笉鏄睆骞曞搴?
                    // 杩欐牱鍙互纭繚鍦ㄦ闈㈠簲鐢ㄧ缉灏忕獥鍙ｆ椂浠嶇劧鏄剧ず杩斿洖鎸夐挳
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
                // 绗簩琛岋細鍙戝竷鏃堕棿銆佹椂闀垮拰婧愰摼鎺?
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

  // 鍙姩鐢荤殑 Header锛堟闈㈢锛? 鏍规嵁婊氬姩浣嶇疆鏀瑰彉甯冨眬
  Widget _buildAnimatedHeader(dynamic episode) {
    final l10n = AppLocalizations.of(context)!;

    if (_isHeaderExpanded) {
      // 灞曞紑鐘舵€侊細妯法鏁翠釜椤堕儴锛屽畬鏁翠俊鎭?
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
            // 宸︿晶锛歀ogo
            PodcastImageWidget(
              imageUrl: episode.imageUrl,
              fallbackImageUrl: episode.subscriptionImageUrl,
              width: 60,
              height: 60,
              iconSize: 32,
            ),
            const SizedBox(width: 16),
            // 涓棿锛氭爣棰樺拰淇℃伅
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  // 鏍囬琛?
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          episode.title ?? 'Unknown Episode',
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
                      // 鎾斁鎸夐挳
                      _buildPlayButton(episode, l10n),
                    ],
                  ),
                  const SizedBox(height: 8),
                  // 鍏冩暟鎹
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
            // 杩斿洖鎸夐挳
            _buildBackButton(),
          ],
        ),
      );
    } else {
      // 鏀剁缉鐘舵€侊細绱у噾甯冨眬锛屾樉绀哄湪宸︿晶杈规爮
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
            // Logo锛堝皬灏哄锛?
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
            // 鏍囬锛堟埅鏂級
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

  // 鎾斁鎸夐挳缁勪欢
  Widget _buildPlayButton(dynamic episode, AppLocalizations l10n) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        InkWell(
          onTap: () async {
            try {
              await _playOrResumeFromDetail(_episodeToModel(episode));
            } catch (error) {
              logger.AppLogger.debug('鉂?Failed to play episode: $error');
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
                ScaffoldMessenger.of(
                  context,
                ).showSnackBar(const SnackBar(content: Text('Added to queue')));
              }
            } catch (error) {
              if (mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text('Failed to add to queue: $error')),
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

  // 杩斿洖鎸夐挳缁勪欢
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

  // 鏃ユ湡鑺墖缁勪欢
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

  // 鏃堕暱鑺墖缁勪欢
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

  // 婧愰摼鎺ヨ姱鐗囩粍浠?
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

  // 椤堕儴鎸夐挳琛岋紙绉诲姩绔級
  Widget _buildTopButtonBar() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
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
          children: [
            // Shownotes Tab
            _buildTabButton(
              AppLocalizations.of(context)!.podcast_tab_shownotes,
              _selectedTabIndex == 0,
              () {
                if (_selectedTabIndex != 0) {
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
              AppLocalizations.of(context)!.podcast_tab_transcript,
              _selectedTabIndex == 1,
              () {
                if (_selectedTabIndex != 1) {
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
              AppLocalizations.of(context)!.podcast_filter_with_summary,
              _selectedTabIndex == 2,
              () {
                if (_selectedTabIndex != 2) {
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
              AppLocalizations.of(context)!.podcast_tab_chat,
              _selectedTabIndex == 3,
              () {
                if (_selectedTabIndex != 3) {
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

  // 宸︿晶鎸夐挳鍒楋紙瀹藉睆锛?
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
                  _stopSummaryPolling(); // 鍒囨崲绂诲紑AI Summary tab鏃跺仠姝㈣疆璇?
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
                  _stopSummaryPolling(); // 鍒囨崲绂诲紑AI Summary tab鏃跺仠姝㈣疆璇?
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
                  _startSummaryPolling(); // 鍒囨崲鍒癆I Summary tab鏃跺惎鍔ㄨ疆璇?
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
                  _stopSummaryPolling(); // 鍒囨崲绂诲紑AI Summary tab鏃跺仠姝㈣疆璇?
                });
              }
            },
          ),
        ],
      ),
    );
  }

  // 宸︿晶杈规爮鎸夐挳缁勪欢锛堝灞忥級
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

  // 椤堕儴鑳跺泭鐘舵寜閽粍浠?
  Widget _buildTabButton(String text, bool isSelected, VoidCallback onTap) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        decoration: BoxDecoration(
          color: isSelected
              ? Theme.of(context).colorScheme.primary
              : Colors.transparent,
          borderRadius: BorderRadius.circular(20),
        ),
        child: Text(
          text,
          style: TextStyle(
            color: isSelected
                ? Theme.of(context).colorScheme.onPrimary
                : Theme.of(context).colorScheme.onSurfaceVariant,
            fontSize: 13,
            fontWeight: isSelected ? FontWeight.w600 : FontWeight.w500,
          ),
        ),
      ),
    );
  }

  // Tab鍐呭鏍规嵁閫夋嫨鏄剧ず
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

  // 鏋勫缓鍗曚釜鏍囩椤靛唴瀹癸紙鐢ㄤ簬 PageView锛?
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

  // 杞綍鍐呭
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

  // AI Summary 鍐呭
  Widget _buildAiSummaryContent(dynamic episode) {
    final provider = getSummaryProvider(widget.episodeId);
    final summaryState = ref.watch(provider);
    final summaryNotifier = ref.read(provider.notifier);
    final transcriptionProvider = getTranscriptionProvider(widget.episodeId);
    final transcriptionState = ref.watch(transcriptionProvider);

    // 鍒濆鍖栨€荤粨鐘舵€侊細濡傛灉鍚庣杩斿洖浜哸iSummary锛屽悓姝ュ埌鐘舵€佷腑
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
          // AI鎬荤粨鎺у埗鍖哄煙
          AISummaryControlWidget(
            episodeId: widget.episodeId,
            hasTranscript:
                transcriptionState.value?.transcriptContent != null &&
                transcriptionState.value!.transcriptContent!.isNotEmpty,
          ),

          const SizedBox(height: 16),

          // 鎬荤粨鍐呭鏄剧ず
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
                    ],
                  ),
                  const SizedBox(height: 12),
                  SelectionArea(
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
            // 鍏煎鏃х増鏈細濡傛灉episode鏈塧iSummary浣唖tate杩樻病鏈夛紝鏄剧ずepisode鐨刟iSummary
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
                    ],
                  ),
                  const SizedBox(height: 12),
                  SelectionArea(
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

  // 瀵硅瘽鍐呭
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

  // 鏍煎紡鍖栨棩鏈?
  String _formatDate(DateTime date) {
    // 纭繚浣跨敤鏈湴鏃堕棿锛岃€屼笉鏄?UTC 鏃堕棿
    final localDate = date.isUtc ? date.toLocal() : date;
    final year = localDate.year;
    final month = localDate.month.toString().padLeft(2, '0');
    final day = localDate.day.toString().padLeft(2, '0');
    final l10n = AppLocalizations.of(context)!;
    return l10n.date_format(year, month, day);
  }

  // 閿欒鐘舵€?
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
        '馃攧 ===== didUpdateWidget: Episode ID changed =====',
      );
      logger.AppLogger.debug('馃攧 Old Episode ID: ${oldWidget.episodeId}');
      logger.AppLogger.debug('馃攧 New Episode ID: ${widget.episodeId}');
      logger.AppLogger.debug(
        '馃攧 Reloading episode data and auto-playing new episode',
      );

      // Invalidate old episode detail provider to force refresh
      logger.AppLogger.debug('馃攧 Invalidating old episode detail provider');
      ref.invalidate(episodeDetailProvider(oldWidget.episodeId));

      // Reset tab selection
      _selectedTabIndex = 0;

      // Stop any ongoing polling
      _summaryPollingTimer?.cancel();
      _isPolling = false;

      // Reload data for the new episode
      WidgetsBinding.instance.addPostFrameCallback((_) {
        logger.AppLogger.debug(
          '馃攧 Calling _loadAndPlayEpisode for new episode',
        );
        _loadAndPlayEpisode();
        _loadTranscriptionStatus();
      });
      logger.AppLogger.debug('馃攧 ===== didUpdateWidget complete =====');
    }
  }

  // 鍚姩AI鎽樿杞
  void _startSummaryPolling() async {
    // 鍋滄鐜版湁鐨勮疆璇?
    _summaryPollingTimer?.cancel();
    _isPolling = false;

    // 棣栧厛妫€鏌ユ槸鍚﹀凡缁忔湁鎽樿锛屽鏋滄湁鍒欎笉寮€濮嬭疆璇?
    try {
      final episodeDetailAsync = await ref.read(
        episodeDetailProvider(widget.episodeId).future,
      );
      if (episodeDetailAsync != null &&
          episodeDetailAsync.aiSummary != null &&
          episodeDetailAsync.aiSummary!.isNotEmpty) {
        logger.AppLogger.debug(
          '鉁?[AI SUMMARY] Summary already exists, skipping polling',
        );
        return;
      }
    } catch (e) {
      logger.AppLogger.debug(
        '鈿狅笍 [AI SUMMARY] Failed to check initial summary state: $e',
      );
    }

    // 寮€濮嬭疆璇?
    _isPolling = true;
    logger.AppLogger.debug('馃攧 [AI SUMMARY] Starting polling...');

    // 姣?绉掕疆璇竴娆★紝妫€鏌I鎽樿鏄惁宸茬敓鎴?
    _summaryPollingTimer = Timer.periodic(const Duration(seconds: 5), (
      timer,
    ) async {
      if (!mounted || !_isPolling) {
        timer.cancel();
        return;
      }

      try {
        // 妫€鏌ュ綋鍓峞pisode鐨凙I鎽樿鐘舵€?
        final episodeDetailAsync = await ref.read(
          episodeDetailProvider(widget.episodeId).future,
        );

        if (episodeDetailAsync != null) {
          // 濡傛灉AI鎽樿宸插瓨鍦紝鍋滄杞
          if (episodeDetailAsync.aiSummary != null &&
              episodeDetailAsync.aiSummary!.isNotEmpty) {
            logger.AppLogger.debug(
              '鉁?[AI SUMMARY] Summary generated, stopping polling',
            );
            _stopSummaryPolling();
            return;
          }
        }

        // 鍒锋柊episode detail鏁版嵁
        ref.invalidate(episodeDetailProvider(widget.episodeId));
      } catch (e) {
        logger.AppLogger.debug('鈿狅笍 [AI SUMMARY] Error during polling: $e');
      }
    });
  }

  // 鍋滄AI鎽樿杞
  void _stopSummaryPolling() {
    _summaryPollingTimer?.cancel();
    _summaryPollingTimer = null;
    _isPolling = false;
    logger.AppLogger.debug('鈴癸笍 [AI SUMMARY] Stopped polling');
  }

  /// 妫€娴嬫槸鍚︽槸鐪熸鐨勭Щ鍔ㄨ澶囧钩鍙?
  ///
  /// 娉ㄦ剰锛氳繖閲屾娴嬬殑鏄钩鍙扮被鍨嬶紝鑰屼笉鏄睆骞曞搴?
  /// - iOS 鍜?Android 骞冲彴杩斿洖 true锛堢Щ鍔ㄨ澶囷級
  /// - Windows銆乵acOS銆丩inux銆乄eb 骞冲彴杩斿洖 false锛堟闈?Web锛?
  ///
  /// 杩欐牱鍙互纭繚鍦ㄦ闈㈠簲鐢ㄧ缉灏忕獥鍙ｆ椂浠嶇劧鏄剧ず杩斿洖鎸夐挳
  bool _isMobilePlatform() {
    // 浣跨敤 Theme.of(context).platform 妫€娴嬪钩鍙扮被鍨?
    // 杩欐娴嬬殑鏄湡姝ｇ殑骞冲彴锛岃€屼笉鏄睆骞曞搴?
    // 鍥犳鍦ㄦ闈㈠簲鐢ㄧ缉灏忕獥鍙ｆ椂浠嶇劧浼氳繑鍥?false
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

  // 鍒ゆ柇鏄惁搴旇鏄剧ず娴姩鍚戜笂鎸夐挳锛堝彧瑕佸悜涓嬫粴鍔ㄥ氨鏄剧ず锛?
  bool _shouldShowScrollToTopButton() {
    final scrollPosition = _tabScrollPositions[_selectedTabIndex] ?? 0.0;
    return scrollPosition > 0;
  }

  // 鏋勫缓娴姩鍚戜笂鎸夐挳
  Widget _buildScrollToTopButton() {
    final screenSize = MediaQuery.of(context).size;
    final isMobile = screenSize.width < 600;

    // 璁＄畻璺濈鍙充笅瑙掔殑浣嶇疆
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

  // 婊氬姩鍥為《閮?
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
