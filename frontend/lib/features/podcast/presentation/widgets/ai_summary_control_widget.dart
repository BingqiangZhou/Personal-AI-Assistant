import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../providers/summary_providers.dart';
import '../../../podcast/data/models/podcast_playback_model.dart';

/// AI总结控制widget - 提供生成、重新生成、模型选择等功能
class AISummaryControlWidget extends ConsumerStatefulWidget {
  final int episodeId;
  final bool hasTranscript;
  final VoidCallback? onSummaryGenerated;

  const AISummaryControlWidget({
    super.key,
    required this.episodeId,
    required this.hasTranscript,
    this.onSummaryGenerated,
  });

  @override
  ConsumerState<AISummaryControlWidget> createState() =>
      _AISummaryControlWidgetState();
}

class _AISummaryControlWidgetState
    extends ConsumerState<AISummaryControlWidget> {
  SummaryModelInfo? _selectedModel;
  bool _showOptions = false;
  final TextEditingController _promptController = TextEditingController();

  @override
  void initState() {
    super.initState();
    // 监听可用模型列表，自动选择默认模型
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final modelsAsync = ref.read(availableModelsProvider);
      modelsAsync.when(
        data: (models) {
          if (models.isNotEmpty) {
            final defaultModel = models.firstWhere(
              (m) => m.isDefault,
              orElse: () => models.first,
            );
            if (mounted) {
              setState(() => _selectedModel = defaultModel);
            }
          }
        },
        loading: () {},
        error: (_, __) {},
      );
    });
  }

  @override
  void dispose() {
    _promptController.dispose();
    super.dispose();
  }

  void _generateSummary() {
    final provider = getSummaryProvider(widget.episodeId);
    ref.read(provider.notifier).generateSummary(
      model: _selectedModel?.name,
      customPrompt: _promptController.text.isNotEmpty ? _promptController.text : null,
    );
  }

  void _regenerateSummary() {
    final provider = getSummaryProvider(widget.episodeId);
    ref.read(provider.notifier).regenerateSummary(
      model: _selectedModel?.name,
      customPrompt: _promptController.text.isNotEmpty ? _promptController.text : null,
    );
  }

  @override
  Widget build(BuildContext context) {
    final provider = getSummaryProvider(widget.episodeId);
    final summaryState = ref.watch(provider);
    final availableModelsAsync = ref.watch(availableModelsProvider);

    // 如果没有转录内容，显示提示
    if (!widget.hasTranscript) {
      return _buildNoTranscriptMessage(context);
    }

    return availableModelsAsync.when(
      data: (availableModels) {
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // 主操作区域
            if (!summaryState.hasSummary && !summaryState.isLoading)
              _buildGenerateControls(context, availableModels)
            else if (summaryState.hasSummary)
              _buildRegenerateControls(context, availableModels, summaryState)
            else
              _buildLoadingState(context),

            // 错误显示
            if (summaryState.hasError)
              Padding(
                padding: const EdgeInsets.only(top: 12),
                child: _buildErrorMessage(context, summaryState.errorMessage!),
              ),
          ],
        );
      },
      loading: () => _buildLoadingState(context),
      error: (_, __) => _buildLoadingState(context),
    );
  }

  Widget _buildNoTranscriptMessage(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.errorContainer.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: Theme.of(context).colorScheme.error.withValues(alpha: 0.3),
        ),
      ),
      child: Row(
        children: [
          Icon(
            Icons.error_outline,
            color: Theme.of(context).colorScheme.error,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              '需要先完成转录才能生成AI总结',
              style: TextStyle(
                color: Theme.of(context).colorScheme.onSurface,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildGenerateControls(
    BuildContext context,
    List<SummaryModelInfo> models,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // 生成按钮
        ElevatedButton.icon(
          onPressed: _generateSummary,
          icon: const Icon(Icons.auto_awesome),
          label: const Text('生成AI总结'),
          style: ElevatedButton.styleFrom(
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
            backgroundColor: Theme.of(context).colorScheme.primary,
            foregroundColor: Theme.of(context).colorScheme.onPrimary,
          ),
        ),

        // 选项展开按钮
        if (models.isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: TextButton.icon(
              onPressed: () => setState(() => _showOptions = !_showOptions),
              icon: Icon(
                _showOptions ? Icons.expand_less : Icons.expand_more,
                size: 18,
              ),
              label: const Text('高级选项'),
              style: TextButton.styleFrom(
                foregroundColor: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ),

        // 高级选项
        if (_showOptions && models.isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(top: 12),
            child: _buildAdvancedOptions(context, models),
          ),
      ],
    );
  }

  Widget _buildRegenerateControls(
    BuildContext context,
    List<SummaryModelInfo> models,
    SummaryState summaryState,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // 总结元数据
        if (summaryState.modelUsed != null || summaryState.processingTime != null)
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.secondaryContainer.withValues(alpha: 0.3),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Wrap(
              spacing: 16,
              children: [
                if (summaryState.modelUsed != null)
                  _buildMetadataItem(
                    context,
                    Icons.psychology_outlined,
                    summaryState.modelUsed!,
                  ),
                if (summaryState.processingTime != null)
                  _buildMetadataItem(
                    context,
                    Icons.schedule_outlined,
                    '${summaryState.processingTime!.toStringAsFixed(1)}s',
                  ),
                if (summaryState.wordCount != null)
                  _buildMetadataItem(
                    context,
                    Icons.text_fields,
                    '${summaryState.wordCount}字',
                  ),
              ],
            ),
          ),

        const SizedBox(height: 12),

        // 重新生成按钮和选项
        Row(
          children: [
            Expanded(
              child: OutlinedButton.icon(
                onPressed: _regenerateSummary,
                icon: const Icon(Icons.refresh, size: 18),
                label: const Text('重新生成'),
                style: OutlinedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                  foregroundColor: Theme.of(context).colorScheme.primary,
                ),
              ),
            ),
            const SizedBox(width: 8),
            IconButton(
              onPressed: () => setState(() => _showOptions = !_showOptions),
              icon: Icon(
                _showOptions ? Icons.expand_less : Icons.expand_more,
              ),
              tooltip: '高级选项',
            ),
          ],
        ),

        // 高级选项
        if (_showOptions && models.isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(top: 12),
            child: _buildAdvancedOptions(context, models),
          ),
      ],
    );
  }

  Widget _buildMetadataItem(BuildContext context, IconData icon, String text) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(
          icon,
          size: 14,
          color: Theme.of(context).colorScheme.onSurfaceVariant,
        ),
        const SizedBox(width: 4),
        Text(
          text,
          style: TextStyle(
            fontSize: 12,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
      ],
    );
  }

  Widget _buildAdvancedOptions(
    BuildContext context,
    List<SummaryModelInfo> models,
  ) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // 模型选择器
          if (models.length > 1)
            DropdownButtonFormField<SummaryModelInfo>(
              value: _selectedModel,
              decoration: InputDecoration(
                labelText: 'AI模型',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                ),
                contentPadding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 8,
                ),
              ),
              items: models.map((model) {
                return DropdownMenuItem<SummaryModelInfo>(
                  value: model,
                  child: Row(
                    children: [
                      Text(model.displayName),
                      if (model.isDefault)
                        Padding(
                          padding: const EdgeInsets.only(left: 8),
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 6,
                              vertical: 2,
                            ),
                            decoration: BoxDecoration(
                              color: Theme.of(context)
                                  .colorScheme
                                  .primary
                                  .withValues(alpha: 0.1),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: Text(
                              '默认',
                              style: TextStyle(
                                fontSize: 10,
                                color: Theme.of(context).colorScheme.primary,
                              ),
                            ),
                          ),
                        ),
                    ],
                  ),
                );
              }).toList(),
              onChanged: (value) {
                setState(() => _selectedModel = value);
              },
            ),

          const SizedBox(height: 12),

          // 自定义提示词输入
          TextField(
            controller: _promptController,
            decoration: InputDecoration(
              labelText: '自定义提示词（可选）',
              hintText: '例如：请重点总结技术要点...',
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
              ),
              contentPadding: const EdgeInsets.symmetric(
                horizontal: 12,
                vertical: 8,
              ),
            ),
            maxLines: 3,
            maxLength: 500,
          ),
        ],
      ),
    );
  }

  Widget _buildLoadingState(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 16),
      child: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            SizedBox(
              width: 24,
              height: 24,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: Theme.of(context).colorScheme.primary,
              ),
            ),
            const SizedBox(height: 12),
            Text(
              '正在生成AI总结...',
              style: TextStyle(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
                fontSize: 14,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildErrorMessage(BuildContext context, String message) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.errorContainer.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: Theme.of(context).colorScheme.error.withValues(alpha: 0.3),
        ),
      ),
      child: Row(
        children: [
          Icon(
            Icons.error_outline,
            size: 18,
            color: Theme.of(context).colorScheme.error,
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              message,
              style: TextStyle(
                color: Theme.of(context).colorScheme.error,
                fontSize: 13,
              ),
            ),
          ),
          IconButton(
            iconSize: 16,
            icon: const Icon(Icons.close),
            onPressed: () {
              final provider = getSummaryProvider(widget.episodeId);
              ref.read(provider.notifier).clearError();
            },
          ),
        ],
      ),
    );
  }
}
