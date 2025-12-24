import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/podcast_providers.dart';
import '../providers/transcription_providers.dart';
import '../providers/summary_providers.dart';
import '../providers/conversation_providers.dart';
import '../../data/models/podcast_episode_model.dart';
import '../../data/models/podcast_transcription_model.dart';
import '../widgets/transcript_display_widget.dart';
import '../widgets/shownotes_display_widget.dart';
import '../widgets/transcription_status_widget.dart';
import '../widgets/ai_summary_control_widget.dart';
import '../widgets/conversation_chat_widget.dart';

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
        episodeDetailProvider(widget.episodeId).future,
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
      // Automatically check/start transcription if missing
      await ref.read(transcriptionProvider.notifier).checkOrStartTranscription();
    } catch (error) {
      debugPrint('❌ Failed to load transcription status: $error');
    }
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
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
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
                                  color: Theme.of(
                                    context,
                                  ).colorScheme.primary.withValues(alpha: 0.1),
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
                                    color: Theme.of(context).colorScheme.primary
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
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        // 标题: 16px, FontWeight.bold, 主题色
                        Text(
                          episode.title ?? 'Unknown Episode',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                            color: Theme.of(context).colorScheme.onSurface,
                          ),
                        ),
                        const SizedBox(height: 4),
                        // 副标题: 12px, 次要文字颜色, 支持多行显示
                        Text(
                          episode.description ?? 'No description',
                          style: TextStyle(
                            fontSize: 12,
                            color: Theme.of(
                              context,
                            ).colorScheme.onSurfaceVariant,
                          ),
                          maxLines: 2,
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
    );
  }

  // B. 左侧主内容
  Widget _buildMainContent(dynamic episode) {
    return Container(
      color: Theme.of(context).colorScheme.surface,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Tabs：节目简介 / 文字转录 / 转录状态
          _buildTabs(),

          // 内容区域
          Expanded(child: _buildTabContent(episode)),
        ],
      ),
    );
  }

  // Tabs 组件 - 胶囊状按钮，右侧显示发布时间和时长
  Widget _buildTabs() {
    final episodeDetailAsync = ref.watch(
      episodeDetailProvider(widget.episodeId),
    );

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
      child: LayoutBuilder(
        builder: (context, constraints) {
          final isWide = constraints.maxWidth > 600;

          final timeWidget = episodeDetailAsync.when(
            data: (episode) {
              if (episode == null) return const SizedBox.shrink();
              return Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  // Published date
                  Row(
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
                  const SizedBox(width: 16),
                  // Duration
                  if (episode.audioDuration != null)
                    Row(
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
                            color: Theme.of(
                              context,
                            ).colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                ],
              );
            },
            loading: () => const SizedBox.shrink(),
            error: (_, __) => const SizedBox.shrink(),
          );

          final buttonsWidget = Row(
            mainAxisSize: MainAxisSize.min,
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
              _buildTabButton('AI Summary', _selectedTabIndex == 2, () {
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
          );

          if (isWide) {
            return Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [timeWidget, buttonsWidget],
            );
          } else {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(children: [timeWidget]),
                const SizedBox(height: 12),
                Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [buttonsWidget],
                ),
              ],
            );
          }
        },
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
            'No transcript content',
            style: TextStyle(
              fontSize: 16,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Please start transcription in the Transcript tab first',
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
                          'AI Summary',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                            color: Theme.of(context).colorScheme.onSurface,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    SelectableText(
                      summaryState.summary!,
                      style: TextStyle(
                        fontSize: 15,
                        height: 1.6,
                        color: Theme.of(context).colorScheme.onSurface,
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
                          'AI Summary',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                            color: Theme.of(context).colorScheme.onSurface,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    SelectableText(
                      episode.aiSummary!,
                      style: TextStyle(
                        fontSize: 15,
                        height: 1.6,
                        color: Theme.of(context).colorScheme.onSurface,
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
    return LayoutBuilder(
      builder: (context, constraints) {
        // 判断是否宽屏 (大于800px为宽屏，以便在平板和桌面上横向显示)
        final isWideScreen = constraints.maxWidth > 800;

        if (isWideScreen) {
          // 宽屏布局:横向排列
          return Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                // 左边:当前时间
                SizedBox(
                  width: 70,
                  child: Text(
                    audioPlayerState.formattedPosition,
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w500,
                      color: Theme.of(context).colorScheme.onSurface,
                    ),
                  ),
                ),

                // 中间:播放控制组
                _buildPlaybackControls(audioPlayerState),

                // 右边:剩余时间 + 倍速按钮
                _buildTimeAndSpeed(audioPlayerState),
              ],
            ),
          );
        } else {
          // 窄屏布局:按钮在时间下方 (手机模式)
          return Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                // 第一行:时间信息
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    // 当前时间 - 使用Flexible防止溢出
                    Flexible(
                      child: Text(
                        audioPlayerState.formattedPosition,
                        style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w500,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),

                    const SizedBox(width: 8),

                    // 剩余时间 + 倍速 - 使用Flexible防止溢出
                    Flexible(child: _buildTimeAndSpeed(audioPlayerState)),
                  ],
                ),

                const SizedBox(height: 16),

                // 第二行:播放控制按钮 (居中)
                Center(child: _buildPlaybackControls(audioPlayerState)),
              ],
            ),
          );
        }
      },
    );
  }

  // 播放控制按钮组
  Widget _buildPlaybackControls(dynamic audioPlayerState) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        // 回退10s
        Container(
          decoration: BoxDecoration(
            color: Theme.of(
              context,
            ).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
            shape: BoxShape.circle,
            border: Border.all(
              color: Theme.of(
                context,
              ).colorScheme.outline.withValues(alpha: 0.3),
              width: 1,
            ),
          ),
          child: IconButton(
            onPressed: () async {
              final newPosition = (audioPlayerState.position - 10000).clamp(
                0,
                audioPlayerState.duration,
              );
              await ref.read(audioPlayerProvider.notifier).seekTo(newPosition);
            },
            icon: Icon(
              Icons.replay_10,
              size: 24,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            constraints: const BoxConstraints(minWidth: 40, minHeight: 40),
            padding: EdgeInsets.zero,
          ),
        ),
        const SizedBox(width: 16),

        // 播放/暂停主按钮
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
            constraints: const BoxConstraints(minWidth: 56, minHeight: 56),
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
            shape: BoxShape.circle,
            border: Border.all(
              color: Theme.of(
                context,
              ).colorScheme.outline.withValues(alpha: 0.3),
              width: 1,
            ),
          ),
          child: IconButton(
            onPressed: () async {
              final newPosition = (audioPlayerState.position + 30000).clamp(
                0,
                audioPlayerState.duration,
              );
              await ref.read(audioPlayerProvider.notifier).seekTo(newPosition);
            },
            icon: Icon(
              Icons.forward_30,
              size: 24,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            constraints: const BoxConstraints(minWidth: 40, minHeight: 40),
            padding: EdgeInsets.zero,
          ),
        ),
      ],
    );
  }

  // 时间和倍速控件
  Widget _buildTimeAndSpeed(dynamic audioPlayerState) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Flexible(
          child: Text(
            _formatRemainingTime(audioPlayerState),
            style: TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w500,
              color: Theme.of(context).colorScheme.onSurface,
            ),
            textAlign: TextAlign.right,
            overflow: TextOverflow.ellipsis,
            maxLines: 1,
          ),
        ),
        const SizedBox(width: 8),
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
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
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
              const PopupMenuItem(value: 2.5, child: Text('2.5x')),
              const PopupMenuItem(value: 3.0, child: Text('3.0x')),
            ],
          ),
        ),
      ],
    );
  }

  // 格式化剩余时长
  String _formatRemainingTime(dynamic audioPlayerState) {
    final remaining = audioPlayerState.duration - audioPlayerState.position;
    if (remaining <= 0) {
      return '00:00';
    }

    final seconds = (remaining / 1000).floor();
    final hours = seconds ~/ 3600;
    final minutes = (seconds % 3600) ~/ 60;
    final secs = seconds % 60;

    if (hours > 0) {
      return '-${hours.toString().padLeft(1, '0')}:${minutes.toString().padLeft(2, '0')}:${secs.toString().padLeft(2, '0')}';
    } else {
      return '-${minutes.toString().padLeft(2, '0')}:${secs.toString().padLeft(2, '0')}';
    }
  }

  // 格式化日期
  String _formatDate(DateTime date) {
    final year = date.year;
    final month = date.month.toString().padLeft(2, '0');
    final day = date.day.toString().padLeft(2, '0');
    return '$year年$month月$day日';
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
}
