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

  @override
  void initState() {
    super.initState();
    // Don't auto-play episode when page loads - user must click play button
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _loadTranscriptionStatus();
    });
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
                  const Text('Processing transcription...'),
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
                  const Text('Starting transcription automatically...'),
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

  // 新的页面布局
  Widget _buildNewLayout(BuildContext context, dynamic episode) {
    return Column(
      children: [
        // A. 顶部元数据区 (Header)
        _buildHeader(episode),

        // B. 中间主体内容区 (Body)
        Expanded(child: _buildMainContent(episode)),
      ],
    );
  }

  // A. 顶部元数据区 (Header) - 无底部分割线
  Widget _buildHeader(dynamic episode) {
    // 获取顶部安全区域高度（状态栏高度）
    final topPadding = MediaQuery.of(context).padding.top;
    // 确保至少有 8 像素的基础间距
    final totalTopPadding = topPadding > 0 ? topPadding + 8.0 : 8.0;
    final l10n = AppLocalizations.of(context)!;

    return Padding(
      padding: EdgeInsets.only(top: totalTopPadding),
      child: Container(
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
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
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
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.schedule_outlined,
                              size: 14,
                              color: Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 6),
                            Text(
                              episode.formattedDuration,
                              style: TextStyle(
                                fontSize: 13,
                                color: Theme.of(context).colorScheme.onSurfaceVariant,
                              ),
                            ),
                          ],
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
      ),
    );
  }

  // B. 主内容区域 - 响应式布局
  Widget _buildMainContent(dynamic episode) {
    return LayoutBuilder(
      builder: (context, constraints) {
        // 判断是否为宽屏（大于800px使用左侧边栏，否则使用顶部按钮）
        final isWideScreen = constraints.maxWidth > 800;

        if (isWideScreen) {
          // 宽屏：左侧边栏布局
          return Container(
            color: Theme.of(context).colorScheme.surface,
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // 左侧：按钮列
                _buildLeftSidebar(),

                // 右侧：内容区域
                Expanded(child: _buildTabContent(episode)),
              ],
            ),
          );
        } else {
          // 窄屏：顶部按钮布局
          return Container(
            color: Theme.of(context).colorScheme.surface,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // 顶部：按钮行
                _buildTopButtonBar(),

                // 下方：内容区域
                Expanded(child: _buildTabContent(episode)),
              ],
            ),
          );
        }
      },
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
            _buildTabButton('Shownotes', _selectedTabIndex == 0, () {
              if (_selectedTabIndex != 0) {
                setState(() {
                  _selectedTabIndex = 0;
                  _stopSummaryPolling(); // 切换离开AI Summary tab时停止轮询
                });
              }
            }),
            const SizedBox(width: 8),
            // Transcript Tab
            _buildTabButton('Transcript', _selectedTabIndex == 1, () {
              if (_selectedTabIndex != 1) {
                setState(() {
                  _selectedTabIndex = 1;
                  _stopSummaryPolling(); // 切换离开AI Summary tab时停止轮询
                });
              }
            }),
            const SizedBox(width: 8),
            // AI Summary Tab
            _buildTabButton(AppLocalizations.of(context)!.podcast_filter_with_summary, _selectedTabIndex == 2, () {
              if (_selectedTabIndex != 2) {
                setState(() {
                  _selectedTabIndex = 2;
                  _startSummaryPolling(); // 切换到AI Summary tab时启动轮询
                });
              }
            }),
            const SizedBox(width: 8),
            // Conversation Tab
            _buildTabButton('Chat', _selectedTabIndex == 3, () {
              if (_selectedTabIndex != 3) {
                setState(() {
                  _selectedTabIndex = 3;
                  _stopSummaryPolling(); // 切换离开AI Summary tab时停止轮询
                });
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
          _buildSidebarTabButton('Shownotes', _selectedTabIndex == 0, () {
            if (_selectedTabIndex != 0) {
              setState(() {
                _selectedTabIndex = 0;
                _stopSummaryPolling(); // 切换离开AI Summary tab时停止轮询
              });
            }
          }),
          const SizedBox(height: 8),
          // Transcript Tab
          _buildSidebarTabButton('Transcript', _selectedTabIndex == 1, () {
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
          _buildSidebarTabButton('Chat', _selectedTabIndex == 3, () {
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
          border: Border.all(
            color: isSelected
                ? Theme.of(context).colorScheme.primary
                : Theme.of(context).colorScheme.outline,
            width: 1,
          ),
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
        return ShownotesDisplayWidget(episode: episode);
      case 1:
        return _buildTranscriptContent(episode);
      case 2:
        return _buildAiSummaryContent(episode);
      case 3:
        return _buildConversationContent(episode);
      default:
        return ShownotesDisplayWidget(episode: episode);
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
            'Failed to load transcript',
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

    return Container(
      padding: const EdgeInsets.all(16),
      child: SingleChildScrollView(
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
              const Center(child: CircularProgressIndicator()),
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
                      summaryState.errorMessage ?? 'Failed to generate summary',
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
            'No AI summary',
            style: TextStyle(
              fontSize: 16,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Complete transcription first, then click the button above to generate AI summary',
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
          return const Center(child: Text('Episode not found'));
        }
        return ConversationChatWidget(
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
              'Failed to load',
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
    return '$year年$month月$day日';
  }

  // 错误状态
  Widget _buildErrorState(BuildContext context, dynamic error) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.error_outline, size: 64, color: Colors.red),
          const SizedBox(height: 16),
          Text(
            'Error loading episode',
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
            child: const Text('Go Back'),
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

  @override
  void dispose() {
    // 停止AI摘要轮询
    _summaryPollingTimer?.cancel();
    super.dispose();
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
}
