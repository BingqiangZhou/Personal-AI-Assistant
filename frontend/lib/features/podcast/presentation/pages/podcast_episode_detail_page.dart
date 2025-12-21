import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/podcast_providers.dart';
import '../providers/transcription_providers.dart';
import '../../data/models/podcast_episode_model.dart';
import '../../data/models/podcast_transcription_model.dart';
import '../widgets/transcript_display_widget.dart';
import '../widgets/shownotes_display_widget.dart';
import '../widgets/transcription_status_widget.dart';

class PodcastEpisodeDetailPage extends ConsumerStatefulWidget {
  final int episodeId;

  const PodcastEpisodeDetailPage({super.key, required this.episodeId});

  @override
  ConsumerState<PodcastEpisodeDetailPage> createState() =>
      _PodcastEpisodeDetailPageState();
}

class _PodcastEpisodeDetailPageState
    extends ConsumerState<PodcastEpisodeDetailPage> {
  int _selectedTabIndex = 0; // 0 = 节目简介, 1 = 文字转录, 2 = 转录状态

  @override
  void initState() {
    super.initState();
    // Auto-play episode when page loads
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _loadAndPlayEpisode();
      _loadTranscriptionStatus();
    });
  }

  Future<void> _loadAndPlayEpisode() async {
    try {
      // Wait for episode detail to be loaded
      final episodeDetailAsync = await ref.read(
        episodeDetailProviderProvider(widget.episodeId).future,
      );

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
      await ref.read(transcriptionProvider.notifier).loadTranscription();
    } catch (error) {
      debugPrint('❌ Failed to load transcription status: $error');
    }
  }

  @override
  Widget build(BuildContext context) {
    final episodeDetailAsync = ref.watch(
      episodeDetailProviderProvider(widget.episodeId),
    );

    return Scaffold(
      backgroundColor: Theme.of(context).colorScheme.surface,
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
      bottomNavigationBar: _buildBottomPlayer(context),
    );
  }

  // 新的页面布局
  Widget _buildNewLayout(BuildContext context, dynamic episode) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final isWideScreen = constraints.maxWidth > 840;

        return Column(
          children: [
            // A. 顶部元数据区 (Header)
            _buildHeader(episode),

            // B. 中间主体内容区 (Body - 响应式布局)
            Expanded(
              child: isWideScreen
                  ? Row(
                      children: [
                        // 左侧主内容 (Flex 7)
                        Expanded(flex: 7, child: _buildMainContent(episode)),
                        // 右侧侧边栏 (Flex 3)
                        Expanded(flex: 3, child: _buildSidebar(episode)),
                      ],
                    )
                  : _buildMainContent(episode),
            ),
          ],
        );
      },
    );
  }

  // A. 顶部元数据区 (Header) - 无底部分割线
  Widget _buildHeader(dynamic episode) {
    // Debug: 输出分集图像链接信息（已注释）
    // debugPrint('📺 PodcastEpisodeDetailPage - Episode image debug:');
    // debugPrint('  Episode ID: ${episode.id}');
    // debugPrint('  Episode Title: ${episode.title}');
    // debugPrint('  Image URL: ${episode.imageUrl}');
    // debugPrint('  Subscription Image URL: ${episode.subscriptionImageUrl}');
    // debugPrint('  Has episode image: ${episode.imageUrl != null}');
    // debugPrint('  Has subscription image: ${episode.subscriptionImageUrl != null}');

    return Padding(
      padding: const EdgeInsets.only(top: 16),
      child: SizedBox(
        height: 56,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          color: Theme.of(context).colorScheme.surface,
          child: Row(
            children: [
              // 左侧：返回按钮 + Logo + 文本
              Expanded(
                child: Row(
                  children: [
                    // 返回按钮
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
                        tooltip: '返回',
                        constraints: const BoxConstraints(
                          minWidth: 36,
                          minHeight: 36,
                        ),
                        padding: EdgeInsets.zero,
                      ),
                    ),
                    const SizedBox(width: 12),
                    // Episode icon: 50x50px, rounded 8px - prioritize episode image over subscription image
                    Container(
                      width: 50,
                      height: 50,
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(
                          color: Theme.of(
                            context,
                          ).colorScheme.primary.withValues(alpha: 0.3),
                          width: 1,
                        ),
                      ),
                      child: ClipRRect(
                        borderRadius: BorderRadius.circular(7),
                        child: episode.imageUrl != null
                            ? Image.network(
                                episode.imageUrl!,
                                width: 50,
                                height: 50,
                                fit: BoxFit.cover,
                                errorBuilder: (context, error, stackTrace) {
                                  debugPrint(
                                    '❌ Failed to load episode image: $error',
                                  );
                                  // Fallback to subscription image
                                  if (episode.subscriptionImageUrl != null) {
                                    return ClipRRect(
                                      borderRadius: BorderRadius.circular(7),
                                      child: Image.network(
                                        episode.subscriptionImageUrl!,
                                        width: 50,
                                        height: 50,
                                        fit: BoxFit.cover,
                                        errorBuilder: (context, error, stackTrace) {
                                          debugPrint(
                                            '❌ Failed to load subscription image: $error',
                                          );
                                          return Container(
                                            color: Theme.of(context)
                                                .colorScheme
                                                .primary
                                                .withValues(alpha: 0.1),
                                            child: Icon(
                                              Icons.headphones_outlined,
                                              color: Theme.of(
                                                context,
                                              ).colorScheme.primary,
                                              size: 28,
                                            ),
                                          );
                                        },
                                      ),
                                    );
                                  }
                                  return Container(
                                    color: Theme.of(context).colorScheme.primary
                                        .withValues(alpha: 0.1),
                                    child: Icon(
                                      Icons.headphones_outlined,
                                      color: Theme.of(
                                        context,
                                      ).colorScheme.primary,
                                      size: 28,
                                    ),
                                  );
                                },
                              )
                            : episode.subscriptionImageUrl != null
                            ? ClipRRect(
                                borderRadius: BorderRadius.circular(7),
                                child: Image.network(
                                  episode.subscriptionImageUrl!,
                                  width: 50,
                                  height: 50,
                                  fit: BoxFit.cover,
                                  errorBuilder: (context, error, stackTrace) {
                                    debugPrint(
                                      '❌ Failed to load subscription image: $error',
                                    );
                                    return Container(
                                      color: Theme.of(context)
                                          .colorScheme
                                          .primary
                                          .withValues(alpha: 0.1),
                                      child: Icon(
                                        Icons.podcasts,
                                        color: Theme.of(
                                          context,
                                        ).colorScheme.primary,
                                        size: 28,
                                      ),
                                    );
                                  },
                                ),
                              )
                            : Container(
                                color: Theme.of(
                                  context,
                                ).colorScheme.primary.withValues(alpha: 0.1),
                                child: Icon(
                                  Icons.headphones_outlined,
                                  color: Theme.of(context).colorScheme.primary,
                                  size: 28,
                                ),
                              ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    // 文本：垂直排列的Column
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          // 标题: 16px, FontWeight.bold, 主题色
                          Text(
                            episode.title ?? 'Unknown Episode',
                            style: TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                              color: Theme.of(context).colorScheme.onSurface,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                          const SizedBox(height: 4),
                          // 副标题: 12px, 次要文字颜色, 单行省略
                          Text(
                            episode.description?.substring(
                                  0,
                                  min(40, episode.description?.length ?? 0),
                                ) ??
                                'No description',
                            style: TextStyle(
                              fontSize: 12,
                              color: Theme.of(
                                context,
                              ).colorScheme.onSurfaceVariant,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  // B. 左侧主内容
  Widget _buildMainContent(dynamic episode) {
    return Container(
      color: Theme.of(context).colorScheme.surface,
      child: Column(
        children: [
          // Tabs：节目简介 / 文字转录 / 转录状态
          _buildTabs(),

          // 内容区域
          Expanded(child: _buildTabContent(episode)),
        ],
      ),
    );
  }

  // Tabs 组件 - 胶囊状按钮
  Widget _buildTabs() {
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
            // 节目简介 Tab
            _buildTabButton('节目简介', _selectedTabIndex == 0, () {
              setState(() {
                _selectedTabIndex = 0;
              });
            }),
            const SizedBox(width: 8),
            // 文字转录 Tab
            _buildTabButton('文字转录', _selectedTabIndex == 1, () {
              setState(() {
                _selectedTabIndex = 1;
              });
            }),
            const SizedBox(width: 8),
            // 转录状态 Tab
            _buildTabButton('转录状态', _selectedTabIndex == 2, () {
              setState(() {
                _selectedTabIndex = 2;
              });
            }),
          ],
        ),
      ),
    );
  }

  // Tab 按钮组件 - 胶囊状
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
        return _buildTranscriptionStatusContent(episode);
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
        if (transcription == null || !isTranscriptionCompleted(transcription)) {
          return _buildTranscriptEmptyState(context);
        }
        return TranscriptDisplayWidget(
          episodeId: widget.episodeId,
          transcription: transcription,
        );
      },
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (error, stack) => _buildTranscriptErrorState(context, error),
    );
  }

  // 转录状态内容
  Widget _buildTranscriptionStatusContent(dynamic episode) {
    final transcriptionProvider = getTranscriptionProvider(widget.episodeId);
    final transcriptionState = ref.watch(transcriptionProvider);

    return transcriptionState.when(
      data: (transcription) {
        return TranscriptionStatusWidget(
          episodeId: widget.episodeId,
          transcription: transcription,
        );
      },
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (error, stack) => _buildTranscriptErrorState(context, error),
    );
  }

  Widget _buildTranscriptEmptyState(BuildContext context) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.transcribe,
            size: 64,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(height: 16),
          Text(
            '暂无转录内容',
            style: TextStyle(
              fontSize: 16,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            '请先在"转录状态"标签页中开始转录',
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
            '加载转录失败',
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

  // B. 右侧侧边栏 - 节目AI总结和转录信息
  Widget _buildSidebar(dynamic episode) {
    final transcriptionProvider = getTranscriptionProvider(widget.episodeId);
    final transcriptionState = ref.watch(transcriptionProvider);

    return Container(
      color: Theme.of(context).colorScheme.surface,
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          // 节目AI总结
          _buildSidebarSection(
            '节目AI总结',
            episode.aiSummary ??
                '这是一期关于AI技术应用的深度讨论节目。我们邀请了行业专家，分享了他们在实际项目中的经验和见解。内容涵盖了从技术架构到商业应用的各个方面，对于想要了解AI落地实践的听众来说非常有价值。',
          ),

          const SizedBox(height: 24),

          // 转录信息
          transcriptionState.when(
            data: (transcription) {
              return _buildTranscriptionSidebarSection(transcription);
            },
            loading: () => _buildTranscriptionSidebarLoadingSection(),
            error: (error, stack) =>
                _buildTranscriptionSidebarErrorSection(error),
          ),
        ],
      ),
    );
  }

  Widget _buildTranscriptionSidebarSection(
    PodcastTranscriptionResponse? transcription,
  ) {
    if (transcription == null) {
      return _buildSidebarSection('转录状态', '暂未开始转录');
    }

    String statusText = getTranscriptionStatusDescription(transcription);
    String infoText = '';

    if (isTranscriptionCompleted(transcription)) {
      final wordCount = transcription.wordCount ?? 0;
      infoText = '转录已完成\n字数: ${wordCount.toString()}';
    } else if (isTranscriptionProcessing(transcription)) {
      infoText = '进度: ${transcription.progressPercentage.toStringAsFixed(1)}%';
    } else if (isTranscriptionFailed(transcription)) {
      infoText = '转录失败\n${transcription.errorMessage ?? '未知错误'}';
    }

    return _buildSidebarSection('转录状态', '$statusText\n\n$infoText');
  }

  Widget _buildTranscriptionSidebarLoadingSection() {
    return _buildSidebarSection('转录状态', '加载中...');
  }

  Widget _buildTranscriptionSidebarErrorSection(dynamic error) {
    return _buildSidebarSection('转录状态', '加载失败\n${error.toString()}');
  }

  // 侧边栏通用部分组件
  Widget _buildSidebarSection(String title, String content) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.bold,
            color: Theme.of(context).colorScheme.onSurface,
          ),
        ),
        const SizedBox(height: 8),
        Text(
          content,
          style: TextStyle(
            fontSize: 13,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
            height: 1.5,
          ),
        ),
      ],
    );
  }

  // C. 底部沉浸式播放条
  Widget _buildBottomPlayer(BuildContext context) {
    final audioPlayerState = ref.watch(audioPlayerProvider);

    // Only show the player if we have an episode loaded
    if (audioPlayerState.currentEpisode == null) {
      return const SizedBox.shrink();
    }

    return Container(
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.1),
            blurRadius: 8,
            offset: const Offset(0, -2),
          ),
        ],
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // 1. 进度条 - 横跨整个宽度，细轨道
          _buildProgressBar(audioPlayerState),

          // 2. 控制区
          _buildControlArea(audioPlayerState),
        ],
      ),
    );
  }

  // 进度条 - 轨道高度2px，主题色
  Widget _buildProgressBar(dynamic audioPlayerState) {
    final progress = audioPlayerState.duration > 0
        ? audioPlayerState.position / audioPlayerState.duration
        : 0.0;

    return SliderTheme(
      data: SliderTheme.of(context).copyWith(
        trackHeight: 2,
        thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 6),
        overlayShape: const RoundSliderOverlayShape(overlayRadius: 12),
      ),
      child: Slider(
        value: progress.clamp(0.0, 1.0),
        onChanged: (value) async {
          final newPosition = (value * audioPlayerState.duration).round();
          await ref.read(audioPlayerProvider.notifier).seekTo(newPosition);
        },
        min: 0,
        max: 1,
        activeColor: Theme.of(context).colorScheme.primary,
        inactiveColor: Theme.of(
          context,
        ).colorScheme.outline.withValues(alpha: 0.3),
        thumbColor: Theme.of(context).colorScheme.primary,
        overlayColor: WidgetStateProperty.all(
          Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
        ),
      ),
    );
  }

  // 控制区
  Widget _buildControlArea(dynamic audioPlayerState) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          // 左边：当前时间
          Text(
            audioPlayerState.formattedPosition,
            style: TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w500,
              color: Theme.of(context).colorScheme.onSurface,
            ),
          ),

          // 中间：播放控制组
          Row(
            children: [
              // 回退15s
              Container(
                decoration: BoxDecoration(
                  color: Theme.of(
                    context,
                  ).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(
                    color: Theme.of(
                      context,
                    ).colorScheme.outline.withValues(alpha: 0.3),
                    width: 1,
                  ),
                ),
                child: IconButton(
                  onPressed: () async {
                    final newPosition = (audioPlayerState.position - 15000)
                        .clamp(0, audioPlayerState.duration);
                    await ref
                        .read(audioPlayerProvider.notifier)
                        .seekTo(newPosition);
                  },
                  icon: Icon(
                    Icons.replay_10,
                    size: 24,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                  constraints: const BoxConstraints(
                    minWidth: 40,
                    minHeight: 40,
                  ),
                  padding: EdgeInsets.zero,
                ),
              ),
              const SizedBox(width: 16),

              // 播放/暂停主按钮 - 圆形，主题色
              Container(
                width: 56,
                height: 56,
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.primary,
                  shape: BoxShape.circle,
                  boxShadow: [
                    BoxShadow(
                      color: Theme.of(
                        context,
                      ).colorScheme.primary.withValues(alpha: 0.3),
                      blurRadius: 8,
                      offset: const Offset(0, 3),
                    ),
                  ],
                ),
                child: IconButton(
                  onPressed: audioPlayerState.isLoading
                      ? null
                      : () async {
                          if (audioPlayerState.isPlaying) {
                            await ref
                                .read(audioPlayerProvider.notifier)
                                .pause();
                          } else {
                            await ref
                                .read(audioPlayerProvider.notifier)
                                .resume();
                          }
                        },
                  icon: audioPlayerState.isLoading
                      ? SizedBox(
                          width: 24,
                          height: 24,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            valueColor: AlwaysStoppedAnimation<Color>(
                              Theme.of(context).colorScheme.onPrimary,
                            ),
                          ),
                        )
                      : Icon(
                          audioPlayerState.isPlaying
                              ? Icons.pause
                              : Icons.play_arrow,
                          color: Theme.of(context).colorScheme.onPrimary,
                          size: 32,
                        ),
                  constraints: const BoxConstraints(
                    minWidth: 56,
                    minHeight: 56,
                  ),
                  padding: EdgeInsets.zero,
                ),
              ),
              const SizedBox(width: 16),

              // 前进30s
              Container(
                decoration: BoxDecoration(
                  color: Theme.of(
                    context,
                  ).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(
                    color: Theme.of(
                      context,
                    ).colorScheme.outline.withValues(alpha: 0.3),
                    width: 1,
                  ),
                ),
                child: IconButton(
                  onPressed: () async {
                    final newPosition = (audioPlayerState.position + 30000)
                        .clamp(0, audioPlayerState.duration);
                    await ref
                        .read(audioPlayerProvider.notifier)
                        .seekTo(newPosition);
                  },
                  icon: Icon(
                    Icons.forward_30,
                    size: 24,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                  constraints: const BoxConstraints(
                    minWidth: 40,
                    minHeight: 40,
                  ),
                  padding: EdgeInsets.zero,
                ),
              ),
            ],
          ),

          // 右边：总时间 + 倍速按钮（圆角矩形边框）
          Row(
            children: [
              Text(
                audioPlayerState.formattedDuration,
                style: TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w500,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
              ),
              const SizedBox(width: 12),
              Container(
                decoration: BoxDecoration(
                  border: Border.all(
                    color: Theme.of(
                      context,
                    ).colorScheme.outline.withValues(alpha: 0.5),
                  ),
                  borderRadius: BorderRadius.circular(16),
                  color: Theme.of(
                    context,
                  ).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
                ),
                child: PopupMenuButton<double>(
                  padding: EdgeInsets.zero,
                  child: Padding(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 12,
                      vertical: 6,
                    ),
                    child: Text(
                      '${audioPlayerState.playbackRate}x',
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ),
                  onSelected: (speed) async {
                    await ref
                        .read(audioPlayerProvider.notifier)
                        .setPlaybackRate(speed);
                  },
                  itemBuilder: (context) => [
                    const PopupMenuItem(value: 0.5, child: Text('0.5x')),
                    const PopupMenuItem(value: 0.75, child: Text('0.75x')),
                    const PopupMenuItem(value: 1.0, child: Text('1.0x')),
                    const PopupMenuItem(value: 1.25, child: Text('1.25x')),
                    const PopupMenuItem(value: 1.5, child: Text('1.5x')),
                    const PopupMenuItem(value: 1.75, child: Text('1.75x')),
                    const PopupMenuItem(value: 2.0, child: Text('2.0x')),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // 工具方法：取最小值
  int min(int a, int b) => a < b ? a : b;

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
}
