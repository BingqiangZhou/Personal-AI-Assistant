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
import '../widgets/transcript_display_widget.dart';
import '../widgets/shownotes_display_widget.dart';
import '../widgets/transcription_status_widget.dart';
import '../widgets/ai_summary_control_widget.dart';
import '../widgets/conversation_chat_widget.dart';
import '../widgets/podcast_image_widget.dart';
import '../widgets/side_floating_player_widget.dart';
import '../widgets/scrollable_content_wrapper.dart';

class PodcastEpisodeDetailPage extends ConsumerStatefulWidget {
  final int episodeId;

  const PodcastEpisodeDetailPage({super.key, required this.episodeId});

  @override
  ConsumerState<PodcastEpisodeDetailPage> createState() =>
      _PodcastEpisodeDetailPageState();
}

class _PodcastEpisodeDetailPageState
    extends ConsumerState<PodcastEpisodeDetailPage> {
  int _selectedTabIndex = 0; // 0 = Shownotes, 1 = Transcript, 2 = AI Summary, 3 = Conversation
  Timer? _summaryPollingTimer; // AI摘要轮询定时器
  bool _isPolling = false; // Guard flag to prevent multiple polls

  // Sticky header animation
  final ScrollController _scrollController = ScrollController();
  final PageController _pageController = PageController(); // 用于移动端页面切换
  double _scrollOffset = 0.0;
  static const double _headerScrollThreshold = 50.0; // Header starts fading after 50px scroll

  // Scroll to top button
  final Map<int, double> _tabScrollPositions = {0: 0.0, 1: 0.0, 2: 0.0, 3: 0.0}; // Track scroll position for each tab
  final Map<int, double> _tabScrollPercentages = {0: 0.0, 1: 0.0, 2: 0.0, 3: 0.0}; // Track scroll percentage for each tab
  final Map<int, ScrollController> _tabScrollControllers = {}; // ScrollController for each tab

  // GlobalKeys for accessing child widget states to call scrollToTop
  final GlobalKey<ShownotesDisplayWidgetState> _shownotesKey = GlobalKey<ShownotesDisplayWidgetState>();
  final GlobalKey<TranscriptDisplayWidgetState> _transcriptKey = GlobalKey<TranscriptDisplayWidgetState>();
  final GlobalKey<ScrollableContentWrapperState> _aiSummaryKey = GlobalKey<ScrollableContentWrapperState>();
  final GlobalKey<ConversationChatWidgetState> _conversationKey = GlobalKey<ConversationChatWidgetState>();

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
    const maxHeaderHeight = 100.0; // 最大裁剪高度（足够显示完整 header）
    if (_scrollOffset <= 0) return maxHeaderHeight;
    if (_scrollOffset >= _headerScrollThreshold) return 0.0;
    return maxHeaderHeight * (1 - _scrollOffset / _headerScrollThreshold);
  }

  // Check if header should be in expanded state (横跨整个顶部)
  bool get _isHeaderExpanded {
    return _scrollOffset < _headerScrollThreshold;
  }

  Future<void> _loadAndPlayEpisode() async {
    debugPrint('🎵 ===== _loadAndPlayEpisode called =====');
    debugPrint('🎵 widget.episodeId: ${widget.episodeId}');

    try {
      // Wait for episode detail to be loaded
      final episodeDetailAsync = await ref.read(
        episodeDetailProvider(widget.episodeId).future,
      );

      debugPrint('🎵 Loaded episode detail: ID=${episodeDetailAsync?.id}, Title=${episodeDetailAsync?.title}');

      // Debug: Log itemLink from API response
      if (episodeDetailAsync != null) {
        debugPrint('🔗 [API Response] itemLink: ${episodeDetailAsync.itemLink ?? "NULL"}');
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
          itemLink: episodeDetailAsync.itemLink,  // ← 添加这一行
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

        debugPrint('🎵 Auto-playing episode: ${episodeModel.title}');
        await ref.read(audioPlayerProvider.notifier).playEpisode(episodeModel);
      }
    } catch (error) {
      debugPrint('❌ Failed to auto-play episode: $error');
    }
  }

  Future<void> _loadTranscriptionStatus() async {
    try {
      final transcriptionProvider = getTranscriptionProvider(widget.episodeId);
      // Automatically check/start transcription if missing
      await ref.read(transcriptionProvider.notifier).checkOrStartTranscription();
    } catch (error) {
      debugPrint('❌ Failed to load transcription status: $error');
    }
  }

  @override
  Widget build(BuildContext context) {
    // Debug: Print current episode ID being loaded
    debugPrint('🏗️ ===== Building PodcastEpisodeDetailPage =====');
    debugPrint('🏗️ widget.episodeId: ${widget.episodeId}');

    final episodeDetailAsync = ref.watch(
      episodeDetailProvider(widget.episodeId),
    );

    debugPrint('🏗️ episodeDetailAsync value: ${episodeDetailAsync.value?.id}');

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
                    child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2),
                  ),
                  const SizedBox(width: 12),
                  Text(AppLocalizations.of(context)!.podcast_transcription_processing),
                ],
              ),
              backgroundColor: Theme.of(context).colorScheme.primary,
              duration: const Duration(seconds: 2),
            ),
          );
        }
      } else if (nextData != null && prevData == null && nextData.isProcessing) {
         // Auto-start case
         ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Row(
                children: [
                  const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2),
                  ),
                  const SizedBox(width: 12),
                  Text(AppLocalizations.of(context)!.podcast_transcription_auto_starting),
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
      body: Stack(
        children: [
          // Main content
          episodeDetailAsync.when(
            data: (episodeDetail) {
              if (episodeDetail == null) {
                return _buildErrorState(context, 'Episode not found');
              }
              return _buildNewLayout(context, episodeDetail);
            },
            loading: () => const Center(child: CircularProgressIndicator()),
            error: (error, stack) => _buildErrorState(context, error),
          ),

          // Side floating player
          const SideFloatingPlayerWidget(),
        ],
      ),
    );
  }

  // 新的页面布局（带吸顶效果）
  Widget _buildNewLayout(BuildContext context, dynamic episode) {
    return LayoutBuilder(
      builder: (context, layoutConstraints) {
        final isWideScreen = layoutConstraints.maxWidth > 800;

        if (isWideScreen) {
          // 宽屏：带可滚动收缩 Header 的布局
          return Stack(
            children: [
              // 主内容行：左侧边栏 + 右侧内容区
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // 左侧边栏（包含标签按钮，顶部预留 Header 空间）
                  SizedBox(
                    width: 200,
                    child: Column(
                      children: [
                        // 预留空间：根据 Header 状态动态调整
                        AnimatedContainer(
                          duration: const Duration(milliseconds: 200),
                          curve: Curves.easeInOut,
                          height: _isHeaderExpanded ? 90 : 100,
                        ),
                        // 左侧标签栏（可滚动）
                        Expanded(
                          child: SingleChildScrollView(
                            child: _buildLeftSidebar(),
                          ),
                        ),
                      ],
                    ),
                  ),
                  // 右侧内容区
                  Expanded(
                    child: Stack(
                      children: [
                        // 内容区
                        NotificationListener<ScrollNotification>(
                          onNotification: (scrollNotification) {
                            // 监听所有页面的滚动更新以实现 header 收起效果和显示浮动按钮
                            if (scrollNotification is ScrollUpdateNotification) {
                              final metrics = scrollNotification.metrics;
                              // 监听所有标签页的垂直滚动
                              if (metrics.axis == Axis.vertical) {
                                final scrollPosition = metrics.pixels;
                                final maxScroll = metrics.maxScrollExtent;
                                final scrollPercent = maxScroll > 0 ? (scrollPosition / maxScroll) : 0.0;

                                setState(() {
                                  _scrollOffset = scrollPosition;
                                  _tabScrollPositions[_selectedTabIndex] = scrollPosition;
                                  _tabScrollPercentages[_selectedTabIndex] = scrollPercent;
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
                        // 浮动向上按钮
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
              // 可移动的 Header (使用 AnimatedPositioned 实现平滑移动)
              AnimatedPositioned(
                duration: const Duration(milliseconds: 200),
                curve: Curves.easeInOut,
                top: 0,
                left: 0,
                right: _isHeaderExpanded ? 0 : null,
                width: _isHeaderExpanded ? null : 200,
                child: _buildAnimatedHeader(episode),
              ),
              // 浮动的返回按钮（收缩状态时显示在右上方）
              if (!_isHeaderExpanded)
                Positioned(
                  top: 16,
                  right: 16,
                  child: _buildBackButton(),
                ),
              // 浮动的播放按钮（收缩状态时显示）
              if (!_isHeaderExpanded)
                Positioned(
                  top: 16,
                  right: 80,
                  child: _buildPlayButton(episode, AppLocalizations.of(context)!),
                ),
            ],
          );
        } else {
          // 窄屏：垂直布局
          // 获取顶部安全区域高度（状态栏高度）
          final topPadding = MediaQuery.of(context).padding.top;
          // 确保至少有 8 像素的基础间距
          final totalTopPadding = topPadding > 0 ? topPadding + 8.0 : 8.0;

          return Column(
            children: [
              // 添加统一的安全区域间距，包裹 header 和按钮栏
              Padding(
                padding: EdgeInsets.only(top: totalTopPadding),
                child: Column(
                  children: [
                    // A. 顶部元数据区 (Header) - 带淡出和收起动画
                    ClipRect(
                      child: Align(
                        alignment: Alignment.topCenter,
                        heightFactor: _headerClipHeight / 100.0, // 归一化高度因子
                        child: AnimatedOpacity(
                          opacity: _headerOpacity,
                          duration: const Duration(milliseconds: 100),
                          curve: Curves.easeInOut,
                          child: _buildHeader(episode),
                        ),
                      ),
                    ),

                    // B. 固定的标签栏 - 吸顶效果（紧接在 header 下方）
                    _buildTopButtonBar(),
                  ],
                ),
              ),

              // C. 中间主体内容区 (Body) - 使用 PageView 支持滑动切换
              Expanded(
                child: Stack(
                  children: [
                    // 内容区
                    NotificationListener<ScrollNotification>(
                      onNotification: (scrollNotification) {
                        // 监听滚动更新以实现 header 收起效果和显示浮动按钮
                        if (scrollNotification is ScrollUpdateNotification) {
                          final metrics = scrollNotification.metrics;
                          // 获取当前页面的滚动位置
                          if (metrics.axis == Axis.vertical) {
                            final scrollPosition = metrics.pixels;
                            final maxScroll = metrics.maxScrollExtent;
                            final scrollPercent = maxScroll > 0 ? (scrollPosition / maxScroll) : 0.0;

                            setState(() {
                              _scrollOffset = scrollPosition;
                              _tabScrollPositions[_selectedTabIndex] = scrollPosition;
                              _tabScrollPercentages[_selectedTabIndex] = scrollPercent;
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
                            // 切换标签时的轮询控制
                            if (index == 2) {
                              _startSummaryPolling();
                            } else {
                              _stopSummaryPolling();
                            }
                            // 重置滚动偏移
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
                    // 浮动向上按钮
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

  // A. 顶部元数据区 (Header) - 无底部分割线
  Widget _buildHeader(dynamic episode) {
    final l10n = AppLocalizations.of(context)!;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      color: Theme.of(context).colorScheme.surface,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
            // 左侧：Logo（独占两行）
            PodcastImageWidget(
              imageUrl: episode.imageUrl,
              fallbackImageUrl: episode.subscriptionImageUrl,
              width: 60,
              height: 60,
              iconSize: 32,
            ),
            const SizedBox(width: 16),
            // 右侧：标题和发布时间
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  // 第一行：标题 + 播放按钮
                  Row(
                    children: [
                      // 标题和播放按钮放在一起
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
                            // 播放按钮
                            InkWell(
                              onTap: () async {
                                try {
                                  final episodeDetailAsync = await ref.read(
                                    episodeDetailProvider(widget.episodeId).future,
                                  );
                                  if (episodeDetailAsync != null) {
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
                                    await ref.read(audioPlayerProvider.notifier).playEpisode(episodeModel);
                                  }
                                } catch (error) {
                                  debugPrint('❌ Failed to play episode: $error');
                                }
                              },
                              child: Container(
                                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                                decoration: BoxDecoration(
                                  color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
                                  borderRadius: BorderRadius.circular(16),
                                  border: Border.all(
                                    color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
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
                                      // 根据屏幕宽度显示不同文本：移动端显示"播放"，桌面端显示"播放此集"
                                      MediaQuery.of(context).size.width < 600
                                          ? l10n.podcast_play_episode
                                          : l10n.podcast_play_episode_full,
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
                          ],
                        ),
                      ),
                      const SizedBox(width: 8),
                      // 返回按钮 - 仅在非移动设备上显示
                      // 注意：这里检测的是真正的平台类型，而不是屏幕宽度
                      // 这样可以确保在桌面应用缩小窗口时仍然显示返回按钮
                      if (!_isMobilePlatform())
                        Container(
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
                  // 第二行：发布时间、时长和源链接
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
                              color: Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ],
                      ),
                      // Duration
                      if (episode.audioDuration != null)
                        Consumer(
                          builder: (context, ref, _) {
                            final audioPlayerState = ref.watch(audioPlayerProvider);
                            // Use audio player duration if available (more accurate), otherwise fall back to episode duration
                            // CRITICAL: episode.audioDuration is in SECONDS, convert to MILLISECONDS
                            final displayDuration = (audioPlayerState.currentEpisode?.id == episode.id &&
                                audioPlayerState.duration > 0)
                                ? audioPlayerState.duration
                                : (episode.audioDuration! * 1000); // Convert seconds to milliseconds
                            final duration = Duration(milliseconds: displayDuration);
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
                        ),
                      // Source link
                      if (episode.itemLink != null && episode.itemLink!.isNotEmpty)
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

  // 可动画的 Header（桌面端）- 根据滚动位置改变布局
  Widget _buildAnimatedHeader(dynamic episode) {
    final l10n = AppLocalizations.of(context)!;

    if (_isHeaderExpanded) {
      // 展开状态：横跨整个顶部，完整信息
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
            // 左侧：Logo
            PodcastImageWidget(
              imageUrl: episode.imageUrl,
              fallbackImageUrl: episode.subscriptionImageUrl,
              width: 60,
              height: 60,
              iconSize: 32,
            ),
            const SizedBox(width: 16),
            // 中间：标题和信息
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  // 标题行
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
                      // 播放按钮
                      _buildPlayButton(episode, l10n),
                    ],
                  ),
                  const SizedBox(height: 8),
                  // 元数据行
                  Wrap(
                    spacing: 16,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      _buildDateChip(episode),
                      if (episode.audioDuration != null) _buildDurationChip(episode),
                      if (episode.itemLink != null && episode.itemLink!.isNotEmpty)
                        _buildSourceLinkChip(episode, l10n),
                    ],
                  ),
                ],
              ),
            ),
            const SizedBox(width: 16),
            // 返回按钮
            _buildBackButton(),
          ],
        ),
      );
    } else {
      // 收缩状态：紧凑布局，显示在左侧边栏
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
            // Logo（小尺寸）
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
            // 标题（截断）
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

  // 播放按钮组件
  Widget _buildPlayButton(dynamic episode, AppLocalizations l10n) {
    return InkWell(
      onTap: () async {
        try {
          final episodeDetailAsync = await ref.read(
            episodeDetailProvider(widget.episodeId).future,
          );
          if (episodeDetailAsync != null) {
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
            await ref.read(audioPlayerProvider.notifier).playEpisode(episodeModel);
          }
        } catch (error) {
          debugPrint('❌ Failed to play episode: $error');
        }
      },
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
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
    );
  }

  // 返回按钮组件
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

  // 日期芯片组件
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

  // 时长芯片组件
  Widget _buildDurationChip(dynamic episode) {
    return Consumer(
      builder: (context, ref, _) {
        final audioPlayerState = ref.watch(audioPlayerProvider);
        final displayDuration = (audioPlayerState.currentEpisode?.id == episode.id &&
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

  // 源链接芯片组件
  Widget _buildSourceLinkChip(dynamic episode, AppLocalizations l10n) {
    return InkWell(
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
    );
  }

  // 顶部按钮行（移动端）
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
            _buildTabButton(AppLocalizations.of(context)!.podcast_tab_shownotes, _selectedTabIndex == 0, () {
              if (_selectedTabIndex != 0) {
                _pageController.animateToPage(
                  0,
                  duration: const Duration(milliseconds: 300),
                  curve: Curves.easeInOut,
                );
              }
            }),
            // Transcript Tab
            _buildTabButton(AppLocalizations.of(context)!.podcast_tab_transcript, _selectedTabIndex == 1, () {
              if (_selectedTabIndex != 1) {
                _pageController.animateToPage(
                  1,
                  duration: const Duration(milliseconds: 300),
                  curve: Curves.easeInOut,
                );
              }
            }),
            // AI Summary Tab
            _buildTabButton(AppLocalizations.of(context)!.podcast_filter_with_summary, _selectedTabIndex == 2, () {
              if (_selectedTabIndex != 2) {
                _pageController.animateToPage(
                  2,
                  duration: const Duration(milliseconds: 300),
                  curve: Curves.easeInOut,
                );
              }
            }),
            // Conversation Tab
            _buildTabButton(AppLocalizations.of(context)!.podcast_tab_chat, _selectedTabIndex == 3, () {
              if (_selectedTabIndex != 3) {
                _pageController.animateToPage(
                  3,
                  duration: const Duration(milliseconds: 300),
                  curve: Curves.easeInOut,
                );
              }
            }),
          ],
        ),
      ),
    );
  }

  // 左侧按钮列（宽屏）
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
          _buildSidebarTabButton(AppLocalizations.of(context)!.podcast_tab_shownotes, _selectedTabIndex == 0, () {
            if (_selectedTabIndex != 0) {
              setState(() {
                _selectedTabIndex = 0;
                _stopSummaryPolling(); // 切换离开AI Summary tab时停止轮询
              });
            }
          }),
          const SizedBox(height: 8),
          // Transcript Tab
          _buildSidebarTabButton(AppLocalizations.of(context)!.podcast_tab_transcript, _selectedTabIndex == 1, () {
            if (_selectedTabIndex != 1) {
              setState(() {
                _selectedTabIndex = 1;
                _stopSummaryPolling(); // 切换离开AI Summary tab时停止轮询
              });
            }
          }),
          const SizedBox(height: 8),
          // AI Summary Tab
          _buildSidebarTabButton(AppLocalizations.of(context)!.podcast_filter_with_summary, _selectedTabIndex == 2, () {
            if (_selectedTabIndex != 2) {
              setState(() {
                _selectedTabIndex = 2;
                _startSummaryPolling(); // 切换到AI Summary tab时启动轮询
              });
            }
          }),
          const SizedBox(height: 8),
          // Conversation Tab
          _buildSidebarTabButton(AppLocalizations.of(context)!.podcast_tab_chat, _selectedTabIndex == 3, () {
            if (_selectedTabIndex != 3) {
              setState(() {
                _selectedTabIndex = 3;
                _stopSummaryPolling(); // 切换离开AI Summary tab时停止轮询
              });
            }
          }),
        ],
      ),
    );
  }

  // 左侧边栏按钮组件（宽屏）
  Widget _buildSidebarTabButton(String text, bool isSelected, VoidCallback onTap) {
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

  // 顶部胶囊状按钮组件
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

  // Tab内容根据选择显示
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

  // 构建单个标签页内容（用于 PageView）
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

  // 转录内容
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

  // AI Summary 内容
  Widget _buildAiSummaryContent(dynamic episode) {
    final provider = getSummaryProvider(widget.episodeId);
    final summaryState = ref.watch(provider);
    final summaryNotifier = ref.read(provider.notifier);
    final transcriptionProvider = getTranscriptionProvider(widget.episodeId);
    final transcriptionState = ref.watch(transcriptionProvider);

    // 初始化总结状态：如果后端返回了aiSummary，同步到状态中
    if (episode.aiSummary != null && episode.aiSummary!.isNotEmpty && !summaryState.hasSummary && !summaryState.isLoading) {
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
          // AI总结控制区域
          AISummaryControlWidget(
            episodeId: widget.episodeId,
            hasTranscript: transcriptionState.value?.transcriptContent != null &&
                transcriptionState.value!.transcriptContent!.isNotEmpty,
          ),

          const SizedBox(height: 16),

          // 总结内容显示
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
                    summaryState.errorMessage ?? AppLocalizations.of(context)!.podcast_summary_generate_failed,
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
                color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
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
                        AppLocalizations.of(context)!.podcast_filter_with_summary,
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
          ] else if (episode.aiSummary != null && episode.aiSummary!.isNotEmpty) ...[
            // 兼容旧版本：如果episode有aiSummary但state还没有，显示episode的aiSummary
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
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
                        AppLocalizations.of(context)!.podcast_filter_with_summary,
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

  // 对话内容
  Widget _buildConversationContent(dynamic episode) {
    final episodeDetailAsync = ref.watch(episodeDetailProvider(widget.episodeId));

    return episodeDetailAsync.when(
      data: (episode) {
        if (episode == null) {
          return Center(child: Text(AppLocalizations.of(context)!.podcast_episode_not_found));
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

  // 格式化日期
  String _formatDate(DateTime date) {
    // 确保使用本地时间，而不是 UTC 时间
    final localDate = date.isUtc ? date.toLocal() : date;
    final year = localDate.year;
    final month = localDate.month.toString().padLeft(2, '0');
    final day = localDate.day.toString().padLeft(2, '0');
    final l10n = AppLocalizations.of(context)!;
    return l10n.date_format(year, month, day);
  }

  // 错误状态
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
      debugPrint('🔄 ===== didUpdateWidget: Episode ID changed =====');
      debugPrint('🔄 Old Episode ID: ${oldWidget.episodeId}');
      debugPrint('🔄 New Episode ID: ${widget.episodeId}');
      debugPrint('🔄 Reloading episode data and auto-playing new episode');

      // Invalidate old episode detail provider to force refresh
      debugPrint('🔄 Invalidating old episode detail provider');
      ref.invalidate(episodeDetailProvider(oldWidget.episodeId));

      // Reset tab selection
      _selectedTabIndex = 0;

      // Stop any ongoing polling
      _summaryPollingTimer?.cancel();
      _isPolling = false;

      // Reload data for the new episode
      WidgetsBinding.instance.addPostFrameCallback((_) {
        debugPrint('🔄 Calling _loadAndPlayEpisode for new episode');
        _loadAndPlayEpisode();
        _loadTranscriptionStatus();
      });
      debugPrint('🔄 ===== didUpdateWidget complete =====');
    }
  }

  // 启动AI摘要轮询
  void _startSummaryPolling() async {
    // 停止现有的轮询
    _summaryPollingTimer?.cancel();
    _isPolling = false;

    // 首先检查是否已经有摘要，如果有则不开始轮询
    try {
      final episodeDetailAsync = await ref.read(episodeDetailProvider(widget.episodeId).future);
      if (episodeDetailAsync != null &&
          episodeDetailAsync.aiSummary != null &&
          episodeDetailAsync.aiSummary!.isNotEmpty) {
        debugPrint('✅ [AI SUMMARY] Summary already exists, skipping polling');
        return;
      }
    } catch (e) {
      debugPrint('⚠️ [AI SUMMARY] Failed to check initial summary state: $e');
    }

    // 开始轮询
    _isPolling = true;
    debugPrint('🔄 [AI SUMMARY] Starting polling...');

    // 每5秒轮询一次，检查AI摘要是否已生成
    _summaryPollingTimer = Timer.periodic(const Duration(seconds: 5), (timer) async {
      if (!mounted || !_isPolling) {
        timer.cancel();
        return;
      }

      try {
        // 检查当前episode的AI摘要状态
        final episodeDetailAsync = await ref.read(episodeDetailProvider(widget.episodeId).future);

        if (episodeDetailAsync != null) {
          // 如果AI摘要已存在，停止轮询
          if (episodeDetailAsync.aiSummary != null && episodeDetailAsync.aiSummary!.isNotEmpty) {
            debugPrint('✅ [AI SUMMARY] Summary generated, stopping polling');
            _stopSummaryPolling();
            return;
          }
        }

        // 刷新episode detail数据
        ref.invalidate(episodeDetailProvider(widget.episodeId));
      } catch (e) {
        debugPrint('⚠️ [AI SUMMARY] Error during polling: $e');
      }
    });
  }

  // 停止AI摘要轮询
  void _stopSummaryPolling() {
    _summaryPollingTimer?.cancel();
    _summaryPollingTimer = null;
    _isPolling = false;
    debugPrint('⏹️ [AI SUMMARY] Stopped polling');
  }

  /// 检测是否是真正的移动设备平台
  ///
  /// 注意：这里检测的是平台类型，而不是屏幕宽度
  /// - iOS 和 Android 平台返回 true（移动设备）
  /// - Windows、macOS、Linux、Web 平台返回 false（桌面/Web）
  ///
  /// 这样可以确保在桌面应用缩小窗口时仍然显示返回按钮
  bool _isMobilePlatform() {
    // 使用 Theme.of(context).platform 检测平台类型
    // 这检测的是真正的平台，而不是屏幕宽度
    // 因此在桌面应用缩小窗口时仍然会返回 false
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

  // 判断是否应该显示浮动向上按钮（只要向下滚动就显示）
  bool _shouldShowScrollToTopButton() {
    final scrollPosition = _tabScrollPositions[_selectedTabIndex] ?? 0.0;
    return scrollPosition > 0;
  }

  // 构建浮动向上按钮
  Widget _buildScrollToTopButton() {
    final screenSize = MediaQuery.of(context).size;
    final isMobile = screenSize.width < 600;

    // 计算距离右下角的位置
    final rightMargin = isMobile ? 32.0 : (screenSize.width * 0.1);
    final bottomMargin = isMobile ? (screenSize.height * 0.1) : 32.0;

    return Padding(
      padding: EdgeInsets.only(
        right: rightMargin,
        bottom: bottomMargin,
      ),
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
                color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.5),
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

  // 滚动回顶部
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
