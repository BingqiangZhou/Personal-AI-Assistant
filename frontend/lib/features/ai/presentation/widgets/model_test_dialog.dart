import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../models/ai_model_config_model.dart';
import '../providers/ai_model_provider.dart';

class ModelTestDialog extends ConsumerStatefulWidget {
  final AIModelConfigModel model;

  const ModelTestDialog({
    super.key,
    required this.model,
  });

  @override
  ConsumerState<ModelTestDialog> createState() => _ModelTestDialogState();
}

class _ModelTestDialogState extends ConsumerState<ModelTestDialog> {
  final _testPromptController = TextEditingController();
  bool _isTesting = false;
  String? _result;
  String? _error;
  double? _responseTime;

  @override
  void initState() {
    super.initState();
    // 设置默认测试内容 - 将在 build 中获取 l10n
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final l10n = AppLocalizations.of(context);
      if (l10n != null && mounted) {
        setState(() {
          if (widget.model.modelType == AIModelType.transcription) {
            _testPromptController.text = l10n.ai_test_prompt_transcription;
          } else {
            _testPromptController.text = l10n.ai_test_prompt_generation;
          }
        });
      }
    });
  }

  Future<void> _testModel() async {
    final l10n = AppLocalizations.of(context)!;
    if (_testPromptController.text.trim().isEmpty) {
      setState(() {
        _error = l10n.ai_enter_test_content;
      });
      return;
    }

    setState(() {
      _isTesting = true;
      _result = null;
      _error = null;
      _responseTime = null;
    });

    try {
      final testData = {
        'prompt': _testPromptController.text.trim(),
      };

      final response = await ref
          .read(modelNotifierProvider(widget.model.id).notifier)
          .testModel(testData: testData);

      if (response != null && mounted) {
        setState(() {
          _result = response.success ? response.result : null;
          _error = response.success ? null : response.errorMessage;
          _responseTime = response.responseTimeMs;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
        });
      }
    } finally {
      if (mounted) {
        setState(() {
          _isTesting = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    return AlertDialog(
      title: Text(l10n.settings_test_connection),
      content: SizedBox(
        width: double.maxFinite,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 模型信息
            _buildModelInfo(),
            const SizedBox(height: 16),

            // 测试输入
            Text(
              l10n.settings_test_connection,
              style: const TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _testPromptController,
              decoration: InputDecoration(
                hintText: l10n.settings_test_connection,
                border: const OutlineInputBorder(),
              ),
              maxLines: widget.model.modelType == AIModelType.transcription ? 1 : 3,
            ),
            const SizedBox(height: 16),

            // 测试结果
            if (_isTesting) ...[
              Center(
                child: Column(
                  children: [
                    const CircularProgressIndicator(),
                    const SizedBox(height: 8),
                    Text(l10n.settings_testing_connection),
                  ],
                ),
              ),
            ] else if (_result != null || _error != null) ...[
              _buildResult(l10n),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(l10n.close),
        ),
        ElevatedButton(
          onPressed: _isTesting ? null : _testModel,
          child: Text(l10n.settings_test_connection),
        ),
      ],
    );
  }

  Widget _buildModelInfo() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.grey.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Icon(
            widget.model.modelType == AIModelType.transcription ? Icons.record_voice_over : Icons.auto_awesome,
            color: Colors.blue,
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  widget.model.displayName,
                  style: const TextStyle(fontWeight: FontWeight.bold),
                ),
                Text(
                  '${widget.model.provider} | ${widget.model.modelId}',
                  style: TextStyle(fontSize: 12, color: Colors.grey[600]),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildResult(AppLocalizations l10n) {
    final hasError = _error != null;
    final color = hasError ? Colors.red : Colors.green;
    final icon = hasError ? Icons.error : Icons.check_circle;

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, color: color, size: 20),
              const SizedBox(width: 8),
              Text(
                hasError ? l10n.ai_test_failed : l10n.ai_test_success,
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  color: color,
                ),
              ),
              if (_responseTime != null) ...[
                const Spacer(),
                Text(
                  '${_responseTime!.toStringAsFixed(0)}ms',
                  style: TextStyle(
                    fontSize: 12,
                    color: Colors.grey[600],
                  ),
                ),
              ],
            ],
          ),
          if (hasError) ...[
            const SizedBox(height: 8),
            Text(
              _error!,
              style: const TextStyle(color: Colors.red),
            ),
          ] else ...[
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(4),
              ),
              child: SelectableText(
                _result!,
                style: const TextStyle(fontSize: 13),
              ),
            ),
          ],
          const SizedBox(height: 8),
          if (!hasError && _responseTime != null)
            Text(
              _responseTime! < 1000
                  ? '${l10n.settings_response_speed}: ${l10n.settings_response_very_fast}'
                  : _responseTime! < 3000
                      ? '${l10n.settings_response_speed}: ${l10n.settings_response_normal}'
                      : '${l10n.settings_response_speed}: ${l10n.settings_response_slow}',
              style: TextStyle(
                fontSize: 12,
                color: _responseTime! < 1000 ? Colors.green : _responseTime! < 3000 ? Colors.orange : Colors.red,
              ),
            ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _testPromptController.dispose();
    super.dispose();
  }
}