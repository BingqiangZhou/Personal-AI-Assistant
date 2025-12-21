import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

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
    // 设置默认测试内容
    if (widget.model.modelType == AIModelType.transcription) {
      _testPromptController.text = '测试音频转录功能';
    } else {
      _testPromptController.text = '请用中文简单介绍一下人工智能';
    }
  }

  Future<void> _testModel() async {
    if (_testPromptController.text.trim().isEmpty) {
      setState(() {
        _error = '请输入测试内容';
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
          .read(modelProvider(widget.model.id))
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
    return AlertDialog(
      title: const Text('测试模型连接'),
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
            const Text(
              '测试内容',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _testPromptController,
              decoration: const InputDecoration(
                hintText: '输入测试内容...',
                border: OutlineInputBorder(),
              ),
              maxLines: widget.model.modelType == AIModelType.transcription ? 1 : 3,
            ),
            const SizedBox(height: 16),

            // 测试结果
            if (_isTesting) ...[
              const Center(
                child: Column(
                  children: [
                    CircularProgressIndicator(),
                    SizedBox(height: 8),
                    Text('正在测试...'),
                  ],
                ),
              ),
            ] else if (_result != null || _error != null) ...[
              _buildResult(),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('关闭'),
        ),
        ElevatedButton(
          onPressed: _isTesting ? null : _testModel,
          child: const Text('开始测试'),
        ),
      ],
    );
  }

  Widget _buildModelInfo() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.grey.withOpacity(0.1),
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

  Widget _buildResult() {
    final hasError = _error != null;
    final color = hasError ? Colors.red : Colors.green;
    final icon = hasError ? Icons.error : Icons.check_circle;

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
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
                hasError ? '测试失败' : '测试成功',
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
                  ? '响应速度: 非常快'
                  : _responseTime! < 3000
                      ? '响应速度: 正常'
                      : '响应速度: 较慢',
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