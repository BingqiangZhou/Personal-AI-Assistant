import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';

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
          mainAxisAlignment: MainAxisAlignment.center,
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
              'Start Transcription',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Theme.of(context).colorScheme.onSurface,
              ),
            ),

            const SizedBox(height: 8),

            // Description
            Text(
              'Generate full text transcription for this episode\nSupports multi-language and high accuracy',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 14,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
                height: 1.5,
              ),
            ),

            const SizedBox(height: 24),

            // Start button with enhanced feedback
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: () => _startTranscriptionWithFeedback(ref, context),
                icon: const Icon(Icons.play_arrow),
                label: const Text('Start Transcription'),
                style: ElevatedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 12),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8),
                  ),
                ),
              ),
            ),

            const SizedBox(height: 12),

            // Auto-start info text
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.3),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.info_outline,
                    size: 14,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                  const SizedBox(width: 6),
                  Flexible(
                    child: Text(
                      'Or enable auto-transcription in settings',
                      style: TextStyle(
                        fontSize: 12,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                  ),
                ),
              ]),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _startTranscriptionWithFeedback(WidgetRef ref, BuildContext context) async {
    // Show immediate feedback
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Row(
          children: [
            const SizedBox(
              width: 16,
              height: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            ),
            const SizedBox(width: 12),
            const Text('Starting transcription...'),
          ],
        ),
        duration: const Duration(seconds: 2),
        behavior: SnackBarBehavior.floating,
      ),
    );

    try {
      final provider = getTranscriptionProvider(episodeId);
      await ref.read(provider.notifier).startTranscription();

      // Show success feedback
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: const Text('✓ Transcription started successfully'),
            duration: const Duration(seconds: 2),
            behavior: SnackBarBehavior.floating,
            backgroundColor: Colors.green,
          ),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('✗ Failed to start: $e'),
            duration: const Duration(seconds: 3),
            behavior: SnackBarBehavior.floating,
            backgroundColor: Colors.red,
          ),
        );
      }
    }
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
          mainAxisAlignment: MainAxisAlignment.center,
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
              'Pending',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Theme.of(context).colorScheme.onSurface,
              ),
            ),

            const SizedBox(height: 8),

            // Description
            Text(
              'Transcription task has been queued\nProcessing will start shortly',
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
    final currentStep = _getCurrentStep(transcription);

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
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // Animated icon with progress ring
            Container(
              width: 100,
              height: 100,
              decoration: BoxDecoration(
                color: Colors.blue.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(50),
              ),
              child: Stack(
                alignment: Alignment.center,
                children: [
                  // Progress ring
                  SizedBox(
                    width: 80,
                    height: 80,
                    child: CircularProgressIndicator(
                      value: progress / 100,
                      strokeWidth: 6,
                      backgroundColor: Colors.blue.withValues(alpha: 0.2),
                      valueColor: AlwaysStoppedAnimation<Color>(Colors.blue),
                    ),
                  ),
                  // Center percentage
                  Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(
                    '${progress.toStringAsFixed(0)}%',
                    style: TextStyle(
                      fontSize: 20,
                      fontWeight: FontWeight.bold,
                      color: Colors.blue,
                    ),
                  ),
                  Text(
                    'Complete',
                    style: TextStyle(
                      fontSize: 10,
                      color: Colors.blue.withValues(alpha: 0.8),
                    ),
                  ),
                ],
              ),
                ],
              ),
            ),

            const SizedBox(height: 20),

            // Current status with icon
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.3),
                borderRadius: BorderRadius.circular(20),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  _getStatusIcon(currentStep),
                  const SizedBox(width: 8),
                  Text(
                    statusText,
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w600,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 20),

            // Step indicators
            _buildStepIndicators(context, transcription),

            const SizedBox(height: 16),

            // Progress bar
            ClipRRect(
              borderRadius: BorderRadius.circular(6),
              child: LinearProgressIndicator(
                value: progress / 100,
                backgroundColor: Theme.of(context).colorScheme.outline.withValues(alpha: 0.2),
                valueColor: AlwaysStoppedAnimation<Color>(Theme.of(context).colorScheme.primary),
                minHeight: 6,
              ),
            ),

            // Debug info (if available)
            if (transcription.debugMessage != null) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.surface,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.1),
                  ),
                ),
                child: Row(
                  children: [
                    Icon(
                      Icons.info_outline,
                      size: 14,
                      color: Theme.of(context).colorScheme.secondary,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        transcription.debugMessage!,
                        style: TextStyle(
                          fontSize: 11,
                          fontFamily: 'monospace',
                          color: Theme.of(context).colorScheme.secondary,
                        ),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ],
                ),
              ),
            ],

            // Additional info
            if (transcription.wordCount != null || transcription.durationSeconds != null) ...[
              const SizedBox(height: 12),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  if (transcription.durationSeconds != null) ...[
                    Icon(
                      Icons.schedule,
                      size: 14,
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      'Duration: ${_formatDuration(transcription.durationSeconds!)}',
                      style: TextStyle(
                        fontSize: 12,
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                  if (transcription.wordCount != null && transcription.durationSeconds != null)
                    const SizedBox(width: 16),
                  if (transcription.wordCount != null) ...[
                    Icon(
                      Icons.text_fields,
                      size: 14,
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      '~${(transcription.wordCount! / 1000).toStringAsFixed(1)}K words',
                      style: TextStyle(
                        fontSize: 12,
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildStepIndicators(BuildContext context, PodcastTranscriptionResponse transcription) {
    final steps = [
      {'icon': Icons.download, 'label': 'Download', 'status': _getStepStatus(transcription, 0)},
      {'icon': Icons.transform, 'label': 'Convert', 'status': _getStepStatus(transcription, 1)},
      {'icon': Icons.content_cut, 'label': 'Split', 'status': _getStepStatus(transcription, 2)},
      {'icon': Icons.transcribe, 'label': 'Transcribe', 'status': _getStepStatus(transcription, 3)},
      {'icon': Icons.merge_type, 'label': 'Merge', 'status': _getStepStatus(transcription, 4)},
    ];

    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceEvenly,
      children: steps.asMap().entries.map((entry) {
        final index = entry.key;
        final step = entry.value;
        final isLast = index == steps.length - 1;

        return Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            _buildStepIndicator(
              context,
              step['icon'] as IconData,
              step['label'] as String,
              step['status'] as String,
            ),
            if (!isLast) ...[
              SizedBox(
                width: 20,
                child: Center(
                  child: Container(
                    height: 2,
                    width: 16,
                    color: _getStepConnectorColor(context, index, steps.length, transcription.progressPercentage),
                  ),
                ),
              ),
            ],
          ],
        );
      }).toList(),
    );
  }

  Widget _buildStepIndicator(BuildContext context, IconData icon, String label, String status) {
    Color iconColor;
    Color bgColor;

    switch (status) {
      case 'completed':
        iconColor = Colors.green;
        bgColor = Colors.green.withValues(alpha: 0.1);
        break;
      case 'current':
        iconColor = Theme.of(context).colorScheme.primary;
        bgColor = Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.5);
        break;
      case 'pending':
      default:
        iconColor = Theme.of(context).colorScheme.onSurfaceVariant.withValues(alpha: 0.4);
        bgColor = Theme.of(context).colorScheme.surface;
        break;
    }

    return Column(
      children: [
        Container(
          width: 36,
          height: 36,
          decoration: BoxDecoration(
            color: bgColor,
            shape: BoxShape.circle,
            border: Border.all(
              color: iconColor.withValues(alpha: 0.3),
              width: 1,
            ),
          ),
          child: Icon(
            status == 'completed' ? Icons.check : icon,
            size: 18,
            color: iconColor,
          ),
        ),
        const SizedBox(height: 4),
        Text(
          label,
          style: TextStyle(
            fontSize: 10,
            color: iconColor,
            fontWeight: status == 'current' ? FontWeight.w600 : FontWeight.w500,
          ),
        ),
      ],
    );
  }

  String _getStepStatus(PodcastTranscriptionResponse transcription, int stepIndex) {
    final progress = transcription.progressPercentage;

    // Step thresholds based on backend progress percentages
    // Download: 5-20% (Index 0)
    // Convert: 20-35% (Index 1)
    // Split: 35-45% (Index 2)
    // Transcribe: 45-95% (Index 3)
    // Merge: 95-100% (Index 4)
    
    // Determine the current active step index based on progress
    int currentActiveIndex = 0;
    if (progress >= 95) {
      currentActiveIndex = 4;
    } else if (progress >= 45) {
      currentActiveIndex = 3;
    } else if (progress >= 35) {
      currentActiveIndex = 2;
    } else if (progress >= 20) {
      currentActiveIndex = 1;
    } else {
      currentActiveIndex = 0;
    }

    if (stepIndex < currentActiveIndex) {
      return 'completed';
    } else if (stepIndex == currentActiveIndex) {
      return 'current';
    } else {
      return 'pending';
    }
  }

  Color _getStepConnectorColor(BuildContext context, int stepIndex, int totalSteps, double progress) {
    // Determine current active step index
    int currentActiveIndex = 0;
    if (progress >= 95) {
      currentActiveIndex = 4;
    } else if (progress >= 45) {
      currentActiveIndex = 3;
    } else if (progress >= 35) {
      currentActiveIndex = 2;
    } else if (progress >= 20) {
      currentActiveIndex = 1;
    } else {
      currentActiveIndex = 0;
    }
    
    // Connector is colored if the step it originates from is completed or current
    // stepIndex is the index of the step BEFORE the connector
    if (stepIndex < currentActiveIndex) {
      return Theme.of(context).colorScheme.primary.withValues(alpha: 0.5);
    }
    return Colors.grey.withValues(alpha: 0.2);
  }

  int _getCurrentStep(PodcastTranscriptionResponse transcription) {
    final progress = transcription.progressPercentage;
    if (progress >= 95) return 5;
    if (progress >= 45) return 4;
    if (progress >= 35) return 3;
    if (progress >= 20) return 2;
    if (progress >= 5) return 1;
    return 0;
  }

  Widget _getStatusIcon(int step) {
    switch (step) {
      case 1:
        return Icon(Icons.download, size: 16, color: Colors.blue);
      case 2:
        return Icon(Icons.transform, size: 16, color: Colors.orange);
      case 3:
        return Icon(Icons.content_cut, size: 16, color: Colors.purple);
      case 4:
        return Icon(Icons.transcribe, size: 16, color: Colors.teal);
      case 5:
        return Icon(Icons.merge_type, size: 16, color: Colors.green);
      default:
        return Icon(Icons.pending, size: 16, color: Colors.grey);
    }
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
          mainAxisAlignment: MainAxisAlignment.center,
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
              'Transcription Complete',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Theme.of(context).colorScheme.onSurface,
              ),
            ),

            const SizedBox(height: 8),

            // Description
            Text(
              'Transcript generated successfully\nYou can now read and search the content',
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
                        'Words',
                        Icons.text_fields,
                      ),
                      _buildStatItem(
                        context,
                        _formatDuration(duration),
                        'Duration',
                        Icons.schedule,
                      ),
                      _buildStatItem(
                        context,
                        _formatAccuracy(null),
                        'Accuracy',
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
                'Completed at: ${_formatDateTime(completedAt)}',
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
                    label: Text(AppLocalizations.of(context)!.podcast_transcription_delete),
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
                    label: const Text('View Transcript'),
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
    final friendlyMessage = _getFriendlyErrorMessage(errorMessage);
    final suggestion = _getErrorSuggestion(errorMessage);

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
          mainAxisAlignment: MainAxisAlignment.center,
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
              'Transcription Failed',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Theme.of(context).colorScheme.onSurface,
              ),
            ),

            const SizedBox(height: 8),

            // Friendly error message
            Text(
              friendlyMessage,
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 14,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
                height: 1.5,
              ),
            ),

            const SizedBox(height: 12),

            // Suggestion
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.orange.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                  color: Colors.orange.withValues(alpha: 0.3),
                ),
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.lightbulb_outline,
                    size: 16,
                    color: Colors.orange.shade700,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      suggestion,
                      style: TextStyle(
                        fontSize: 13,
                        color: Colors.orange.shade700,
                        height: 1.4,
                      ),
                    ),
                  ),
                ],
              ),
            ),

            if (errorMessage != friendlyMessage) ...[
              const SizedBox(height: 12),
              // Technical details (expandable)
              ExpansionTile(
                tilePadding: EdgeInsets.zero,
                title: Text(
                  'Technical Details',
                  style: TextStyle(
                    fontSize: 12,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.surface,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Text(
                      errorMessage,
                      style: TextStyle(
                        fontSize: 11,
                        fontFamily: 'monospace',
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ),
                ],
              ),
            ],

            const SizedBox(height: 16),

            // Action buttons
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: () => _deleteTranscription(ref),
                    icon: const Icon(Icons.delete_outline),
                    label: Text(AppLocalizations.of(context)!.podcast_transcription_clear),
                    style: OutlinedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: () => _retryTranscription(ref),
                    icon: const Icon(Icons.refresh),
                    label: const Text('Retry'),
                    style: ElevatedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                      backgroundColor: Colors.green,
                      foregroundColor: Colors.white,
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

  String _getFriendlyErrorMessage(String error) {
    final lowerError = error.toLowerCase();

    if (lowerError.contains('already in progress') || lowerError.contains('already exists') || lowerError.contains('locked')) {
      return 'Transcription already in progress';
    }
    if (lowerError.contains('network') || lowerError.contains('connection') || lowerError.contains('timeout')) {
      return 'Network connection failed';
    }
    if (lowerError.contains('audio') || lowerError.contains('download')) {
      return 'Failed to download audio';
    }
    if (lowerError.contains('api') || lowerError.contains('transcription')) {
      return 'Transcription service error';
    }
    if (lowerError.contains('format') || lowerError.contains('convert')) {
      return 'Audio format conversion failed';
    }
    if (lowerError.contains('server restart')) {
      return 'Service was restarted';
    }

    return 'Transcription failed';
  }

  String _getErrorSuggestion(String error) {
    final lowerError = error.toLowerCase();

    if (lowerError.contains('network') || lowerError.contains('connection') || lowerError.contains('timeout')) {
      return 'Check your internet connection and try again';
    }
    if (lowerError.contains('audio') || lowerError.contains('download')) {
      return 'The audio file may be unavailable. Try again later';
    }
    if (lowerError.contains('api') || lowerError.contains('transcription')) {
      return 'The transcription service may be busy. Retry in a moment';
    }
    if (lowerError.contains('format') || lowerError.contains('convert')) {
      return 'The audio format may not be supported. Try a different episode';
    }
    if (lowerError.contains('server restart')) {
      return 'Click Retry to start a new transcription task';
    }

    return 'Try clicking Retry to start over';
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
    // Show retry feedback
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
      return '$hours:${minutes.toString().padLeft(2, '0')}:${secs.toString().padLeft(2, '0')}';
    }
    return '$minutes:${secs.toString().padLeft(2, '0')}';
  }

  String _formatAccuracy(double? accuracy) {
    if (accuracy == null) return '--';
    return '${(accuracy * 100).toStringAsFixed(0)}%';
  }

  String _formatDateTime(DateTime dateTime) {
    // 确保使用本地时间，而不是 UTC 时间
    final localDate = dateTime.isUtc ? dateTime.toLocal() : dateTime;
    final year = localDate.year;
    final month = localDate.month.toString().padLeft(2, '0');
    final day = localDate.day.toString().padLeft(2, '0');
    final hour = localDate.hour.toString().padLeft(2, '0');
    final minute = localDate.minute.toString().padLeft(2, '0');
    return '$year-$month-$day $hour:$minute';
  }
}