import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../providers/transcription_providers.dart';
import '../../data/models/podcast_transcription_model.dart';

class TranscriptionStatusWidget extends ConsumerWidget {
  final int episodeId;
  final PodcastTranscriptionResponse? transcription;

  const TranscriptionStatusWidget({
    super.key,
    required this.episodeId,
    this.transcription,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    if (transcription == null) {
      return _buildNotStartedState(context, ref);
    }

    switch (transcription!.transcriptionStatus) {
      case TranscriptionStatus.pending:
        return _buildPendingState(context);
      case TranscriptionStatus.downloading:
      case TranscriptionStatus.converting:
      case TranscriptionStatus.transcribing:
      case TranscriptionStatus.processing:
        return _buildProcessingState(context, transcription!);
      case TranscriptionStatus.completed:
        return _buildCompletedState(context, transcription!, ref);
      case TranscriptionStatus.failed:
        return _buildFailedState(context, transcription!, ref);
    }
  }

  Widget _buildNotStartedState(BuildContext context, WidgetRef ref) {
    return Card(
      elevation: 0,
      color: Theme.of(context).colorScheme.surfaceContainerHighest,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(
          color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.2),
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            // Icon
            Container(
              width: 80,
              height: 80,
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(40),
              ),
              child: Icon(
                Icons.transcribe,
                size: 40,
                color: Theme.of(context).colorScheme.primary,
              ),
            ),

            const SizedBox(height: 16),

            // Title
            Text(
              '开始转录',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Theme.of(context).colorScheme.onSurface,
              ),
            ),

            const SizedBox(height: 8),

            // Description
            Text(
              '为这个播客分集生成完整的文字转录\n支持多语言识别和高精度转录',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 14,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
                height: 1.5,
              ),
            ),

            const SizedBox(height: 24),

            // Start button
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: () => _startTranscription(ref),
                icon: const Icon(Icons.play_arrow),
                label: const Text('开始转录'),
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 12),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPendingState(BuildContext context) {
    return Card(
      elevation: 0,
      color: Theme.of(context).colorScheme.surfaceContainerHighest,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(
          color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.2),
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            // Icon
            Container(
              width: 80,
              height: 80,
              decoration: BoxDecoration(
                color: Colors.orange.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(40),
              ),
              child: Icon(
                Icons.pending_actions,
                size: 40,
                color: Colors.orange,
              ),
            ),

            const SizedBox(height: 16),

            // Title
            Text(
              '等待开始',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Theme.of(context).colorScheme.onSurface,
              ),
            ),

            const SizedBox(height: 8),

            // Description
            Text(
              '转录任务已添加到队列中\n将尽快开始处理',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 14,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
                height: 1.5,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildProcessingState(BuildContext context, PodcastTranscriptionResponse transcription) {
    final progress = transcription.progressPercentage;
    final statusText = transcription.statusDescription;

    return Card(
      elevation: 0,
      color: Theme.of(context).colorScheme.surfaceContainerHighest,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(
          color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.2),
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            // Animated icon
            Container(
              width: 80,
              height: 80,
              decoration: BoxDecoration(
                color: Colors.blue.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(40),
              ),
              child: Stack(
                alignment: Alignment.center,
                children: [
                  // Progress ring
                  SizedBox(
                    width: 60,
                    height: 60,
                    child: CircularProgressIndicator(
                      value: progress / 100,
                      strokeWidth: 4,
                      backgroundColor: Colors.blue.withValues(alpha: 0.2),
                      valueColor: AlwaysStoppedAnimation<Color>(Colors.blue),
                    ),
                  ),
                  // Center icon
                  Icon(
                    Icons.autorenew,
                    size: 24,
                    color: Colors.blue,
                  ),
                ],
              ),
            ),

            const SizedBox(height: 16),

            // Status text
            Text(
              statusText,
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Theme.of(context).colorScheme.onSurface,
              ),
            ),

            const SizedBox(height: 8),

            // Progress text
            Text(
              '${progress.toStringAsFixed(1)}% 完成',
              style: TextStyle(
                fontSize: 14,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
                fontWeight: FontWeight.w500,
              ),
            ),

            const SizedBox(height: 16),

            // Progress bar
            LinearProgressIndicator(
              value: progress / 100,
              backgroundColor: Theme.of(context).colorScheme.outline.withValues(alpha: 0.2),
              valueColor: AlwaysStoppedAnimation<Color>(Theme.of(context).colorScheme.primary),
              borderRadius: BorderRadius.circular(4),
            ),

            const SizedBox(height: 16),

            // Additional info
            if (transcription.wordCount != null)
              Text(
                '预计字数: ${transcription.wordCount}',
                style: TextStyle(
                  fontSize: 12,
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),

            if (transcription.durationSeconds != null)
              Text(
                '音频时长: ${_formatDuration(transcription.durationSeconds!)}',
                style: TextStyle(
                  fontSize: 12,
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildCompletedState(BuildContext context, PodcastTranscriptionResponse transcription, WidgetRef ref) {
    final wordCount = transcription.wordCount ?? 0;
    final duration = transcription.durationSeconds ?? 0;
    final completedAt = transcription.completedAt;

    return Card(
      elevation: 0,
      color: Colors.green.withValues(alpha: 0.05),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(
          color: Colors.green.withValues(alpha: 0.2),
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            // Success icon
            Container(
              width: 80,
              height: 80,
              decoration: BoxDecoration(
                color: Colors.green.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(40),
              ),
              child: Icon(
                Icons.check_circle,
                size: 40,
                color: Colors.green,
              ),
            ),

            const SizedBox(height: 16),

            // Title
            Text(
              '转录完成',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Theme.of(context).colorScheme.onSurface,
              ),
            ),

            const SizedBox(height: 8),

            // Description
            Text(
              '转录文本已生成完成\n可以开始阅读和搜索内容',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 14,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
                height: 1.5,
              ),
            ),

            const SizedBox(height: 16),

            // Stats
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surface,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                  color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.2),
                ),
              ),
              child: Column(
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceAround,
                    children: [
                      _buildStatItem(
                        context,
                        '${(wordCount / 1000).toStringAsFixed(1)}K',
                        '转录字数',
                        Icons.text_fields,
                      ),
                      _buildStatItem(
                        context,
                        _formatDuration(duration),
                        '音频时长',
                        Icons.schedule,
                      ),
                      _buildStatItem(
                        context,
                        _formatAccuracy(null),
                        '准确率',
                        Icons.speed,
                      ),
                    ],
                  ),
                ],
              ),
            ),

            if (completedAt != null) ...[
              const SizedBox(height: 8),
              Text(
                '完成时间: ${_formatDateTime(completedAt)}',
                style: TextStyle(
                  fontSize: 12,
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
            ],

            const SizedBox(height: 16),

            // Actions
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: () => _deleteTranscription(ref),
                    icon: const Icon(Icons.delete_outline),
                    label: const Text('删除转录'),
                    style: OutlinedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                      side: BorderSide(
                        color: Theme.of(context).colorScheme.error,
                      ),
                      foregroundColor: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: () => _viewTranscription(ref),
                    icon: const Icon(Icons.visibility),
                    label: const Text('查看转录'),
                    style: ElevatedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFailedState(BuildContext context, PodcastTranscriptionResponse transcription, WidgetRef ref) {
    final errorMessage = transcription.errorMessage ?? '未知错误';

    return Card(
      elevation: 0,
      color: Colors.red.withValues(alpha: 0.05),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(
          color: Colors.red.withValues(alpha: 0.2),
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            // Error icon
            Container(
              width: 80,
              height: 80,
              decoration: BoxDecoration(
                color: Colors.red.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(40),
              ),
              child: Icon(
                Icons.error_outline,
                size: 40,
                color: Colors.red,
              ),
            ),

            const SizedBox(height: 16),

            // Title
            Text(
              '转录失败',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Theme.of(context).colorScheme.onSurface,
              ),
            ),

            const SizedBox(height: 8),

            // Error message
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.red.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                  color: Colors.red.withValues(alpha: 0.2),
                ),
              ),
              child: Column(
                children: [
                  Text(
                    '错误信息',
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                      color: Colors.red.shade700,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    errorMessage,
                    style: TextStyle(
                      fontSize: 14,
                      color: Colors.red.shade700,
                    ),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 16),

            // Retry button
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: () => _retryTranscription(ref),
                icon: const Icon(Icons.refresh),
                label: const Text('重新尝试'),
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 12),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatItem(BuildContext context, String value, String label, IconData icon) {
    return Column(
      children: [
        Icon(
          icon,
          size: 20,
          color: Theme.of(context).colorScheme.primary,
        ),
        const SizedBox(height: 4),
        Text(
          value,
          style: TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: Theme.of(context).colorScheme.onSurface,
          ),
        ),
        Text(
          label,
          style: TextStyle(
            fontSize: 12,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
      ],
    );
  }

  Future<void> _startTranscription(WidgetRef ref) async {
    try {
      final provider = getTranscriptionProvider(episodeId);
      await ref.read(provider.notifier).startTranscription();
    } catch (e) {
      // Error will be handled by the provider
    }
  }

  Future<void> _deleteTranscription(WidgetRef ref) async {
    try {
      final provider = getTranscriptionProvider(episodeId);
      await ref.read(provider.notifier).deleteTranscription();
    } catch (e) {
      // Error will be handled by the provider
    }
  }

  void _viewTranscription(WidgetRef ref) {
    // This will be handled by the parent widget
    // Just update the tab to show transcription
  }

  Future<void> _retryTranscription(WidgetRef ref) async {
    try {
      final provider = getTranscriptionProvider(episodeId);
      await ref.read(provider.notifier).startTranscription();
    } catch (e) {
      // Error will be handled by the provider
    }
  }

  String _formatDuration(int seconds) {
    final hours = seconds ~/ 3600;
    final minutes = (seconds % 3600) ~/ 60;
    final secs = seconds % 60;

    if (hours > 0) {
      return '${hours}:${minutes.toString().padLeft(2, '0')}:${secs.toString().padLeft(2, '0')}';
    }
    return '${minutes}:${secs.toString().padLeft(2, '0')}';
  }

  String _formatAccuracy(double? accuracy) {
    if (accuracy == null) return '--';
    return '${(accuracy * 100).toStringAsFixed(0)}%';
  }

  String _formatDateTime(DateTime dateTime) {
    final year = dateTime.year;
    final month = dateTime.month.toString().padLeft(2, '0');
    final day = dateTime.day.toString().padLeft(2, '0');
    final hour = dateTime.hour.toString().padLeft(2, '0');
    final minute = dateTime.minute.toString().padLeft(2, '0');
    return '$year-$month-$day $hour:$minute';
  }
}