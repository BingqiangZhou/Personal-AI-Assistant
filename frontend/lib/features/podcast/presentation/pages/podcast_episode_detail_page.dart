import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/podcast_providers.dart';
import '../../data/models/podcast_episode_model.dart';

class PodcastEpisodeDetailPage extends ConsumerStatefulWidget {
  final int episodeId;

  const PodcastEpisodeDetailPage({
    super.key,
    required this.episodeId,
  });

  @override
  ConsumerState<PodcastEpisodeDetailPage> createState() => _PodcastEpisodeDetailPageState();
}

class _PodcastEpisodeDetailPageState extends ConsumerState<PodcastEpisodeDetailPage> {
  bool _isTranscriptTab = true; // true = 文字转录, false = 节目简介

  // 模拟转录对话数据（根据用户要求的精确格式）
  final List<Map<String, String>> _dialogueItems = [
    {'speaker': '主持人', 'time': '00:00', 'content': '大家好，欢迎收听本期节目。今天我们来聊聊AI应用的最新发展。'},
    {'speaker': '嘉宾A', 'time': '00:15', 'content': '很高兴来到这里。AI技术确实在快速发展，特别是在自然语言处理领域。'},
    {'speaker': '主持人', 'time': '00:32', 'content': '没错，我们看到很多创新应用。能分享一下你们的具体实践吗？'},
    {'speaker': '嘉宾B', 'time': '00:48', 'content': '当然。我们主要关注企业级应用，帮助客户提升效率的同时降低成本。'},
    {'speaker': '主持人', 'time': '01:05', 'content': '听起来很有价值。听众朋友们，如果你们有任何问题，欢迎在评论区留言。'},
  ];

  @override
  void initState() {
    super.initState();
    // Auto-play episode when page loads
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _loadAndPlayEpisode();
    });
  }

  Future<void> _loadAndPlayEpisode() async {
    try {
      // Wait for episode detail to be loaded
      final episodeDetailAsync = await ref.read(episodeDetailProviderProvider(widget.episodeId).future);

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

  @override
  Widget build(BuildContext context) {
    final episodeDetailAsync = ref.watch(episodeDetailProviderProvider(widget.episodeId));

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
                        Expanded(
                          flex: 7,
                          child: _buildMainContent(episode),
                        ),
                        // 右侧侧边栏 (Flex 3)
                        Expanded(
                          flex: 3,
                          child: _buildSidebar(episode),
                        ),
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

    return Container(
      padding: const EdgeInsets.all(16),
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
                      color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
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
                              debugPrint('❌ Failed to load episode image: $error');
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
                                      debugPrint('❌ Failed to load subscription image: $error');
                                      return Container(
                                        color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
                                        child: Icon(
                                          Icons.headphones_outlined,
                                          color: Theme.of(context).colorScheme.primary,
                                          size: 28,
                                        ),
                                      );
                                    },
                                  ),
                                );
                              }
                              return Container(
                                color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
                                child: Icon(
                                  Icons.headphones_outlined,
                                  color: Theme.of(context).colorScheme.primary,
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
                                    debugPrint('❌ Failed to load subscription image: $error');
                                    return Container(
                                      color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
                                      child: Icon(
                                        Icons.podcasts,
                                        color: Theme.of(context).colorScheme.primary,
                                        size: 28,
                                      ),
                                    );
                                  },
                                ),
                              )
                            : Container(
                                color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
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
                        episode.description?.substring(0, min(40, episode.description?.length ?? 0)) ?? 'No description',
                        style: TextStyle(
                          fontSize: 12,
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
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
    );
  }

  // B. 左侧主内容
  Widget _buildMainContent(dynamic episode) {
    return Container(
      color: Theme.of(context).colorScheme.surface,
      child: Column(
        children: [
          // Tabs：文字转录 / 节目简介
          _buildTabs(),

          // 内容区域
          Expanded(
            child: _isTranscriptTab
                ? _buildTranscriptContent(episode)
                : _buildDescriptionContent(episode),
          ),
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
          bottom: BorderSide(color: Theme.of(context).colorScheme.outlineVariant, width: 1),
        ),
      ),
      child: Row(
        children: [
          // 文字转录 Tab
          _buildTabButton('文字转录', _isTranscriptTab, () {
            setState(() {
              _isTranscriptTab = true;
            });
          }),
          const SizedBox(width: 8),
          // 节目简介 Tab
          _buildTabButton('节目简介', !_isTranscriptTab, () {
            setState(() {
              _isTranscriptTab = false;
            });
          }),
        ],
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
          color: isSelected ? Theme.of(context).colorScheme.primary : Colors.transparent,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: isSelected ? Theme.of(context).colorScheme.primary : Theme.of(context).colorScheme.outline,
            width: 1,
          ),
        ),
        child: Text(
          text,
          style: TextStyle(
            color: isSelected ? Theme.of(context).colorScheme.onPrimary : Theme.of(context).colorScheme.onSurfaceVariant,
            fontSize: 13,
            fontWeight: isSelected ? FontWeight.w600 : FontWeight.w500,
          ),
        ),
      ),
    );
  }

  // 文字转录内容 - 多人对话脚本
  Widget _buildTranscriptContent(dynamic episode) {
    return Container(
      padding: const EdgeInsets.all(16),
      child: ListView.builder(
        itemCount: _dialogueItems.length,
        itemBuilder: (context, index) {
          final item = _dialogueItems[index];
          return Column(
            children: [
              _buildDialogueItem(
                item['speaker']!,
                item['content']!,
                item['time']!,
              ),
              if (index < _dialogueItems.length - 1) const SizedBox(height: 16),
            ],
          );
        },
      ),
    );
  }

  // 对话项组件
  Widget _buildDialogueItem(String speaker, String content, String time) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(
                  color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
                  width: 1,
                ),
              ),
              child: Text(
                speaker,
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: Theme.of(context).colorScheme.primary,
                ),
              ),
            ),
            const SizedBox(width: 8),
            Text(
              time,
              style: TextStyle(
                fontSize: 11,
                color: Theme.of(context).colorScheme.onSurfaceVariant.withValues(alpha: 0.6),
              ),
            ),
          ],
        ),
        const SizedBox(height: 6),
        Text(
          content,
          style: TextStyle(
            fontSize: 15,
            height: 1.6,
            color: Theme.of(context).colorScheme.onSurface,
          ),
        ),
      ],
    );
  }

  // 节目简介内容
  Widget _buildDescriptionContent(dynamic episode) {
    return Container(
      padding: const EdgeInsets.all(16),
      child: Text(
        episode.aiSummary ?? '这是一期关于AI技术应用的深度讨论节目。我们邀请了行业专家，分享了他们在实际项目中的经验和见解。内容涵盖了从技术架构到商业应用的各个方面，对于想要了解AI落地实践的听众来说非常有价值。',
        style: TextStyle(
          fontSize: 15,
          height: 1.8,
          color: Theme.of(context).colorScheme.onSurface,
        ),
      ),
    );
  }

  // B. 右侧侧边栏 - 只有节目AI总结
  Widget _buildSidebar(dynamic episode) {
    return Container(
      color: Theme.of(context).colorScheme.surface,
      padding: const EdgeInsets.all(16),
      child: _buildSidebarSection(
        '节目AI总结',
        episode.aiSummary ?? '这是一期关于AI技术应用的深度讨论节目。我们邀请了行业专家，分享了他们在实际项目中的经验和见解。内容涵盖了从技术架构到商业应用的各个方面，对于想要了解AI落地实践的听众来说非常有价值。',
      ),
    );
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
        inactiveColor: Theme.of(context).colorScheme.outline.withValues(alpha: 0.3),
        thumbColor: Theme.of(context).colorScheme.primary,
        overlayColor: WidgetStateProperty.all(Theme.of(context).colorScheme.primary.withValues(alpha: 0.1)),
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
                  color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(
                    color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.3),
                    width: 1,
                  ),
                ),
                child: IconButton(
                  onPressed: () async {
                    final newPosition = (audioPlayerState.position - 15000).clamp(0, audioPlayerState.duration);
                    await ref.read(audioPlayerProvider.notifier).seekTo(newPosition);
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
                      color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
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
                            await ref.read(audioPlayerProvider.notifier).pause();
                          } else {
                            await ref.read(audioPlayerProvider.notifier).resume();
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
                          audioPlayerState.isPlaying ? Icons.pause : Icons.play_arrow,
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
                  color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(
                    color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.3),
                    width: 1,
                  ),
                ),
                child: IconButton(
                  onPressed: () async {
                    final newPosition = (audioPlayerState.position + 30000).clamp(0, audioPlayerState.duration);
                    await ref.read(audioPlayerProvider.notifier).seekTo(newPosition);
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
                  border: Border.all(color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.5)),
                  borderRadius: BorderRadius.circular(16),
                  color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
                ),
                child: PopupMenuButton<double>(
                  padding: EdgeInsets.zero,
                  child: Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
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
                    await ref.read(audioPlayerProvider.notifier).setPlaybackRate(speed);
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
          const Icon(
            Icons.error_outline,
            size: 64,
            color: Colors.red,
          ),
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
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Colors.grey[600],
                  ),
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
