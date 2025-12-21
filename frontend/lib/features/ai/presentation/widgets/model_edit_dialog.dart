import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../models/ai_model_config_model.dart';
import '../providers/ai_model_provider.dart';

class ModelEditDialog extends ConsumerStatefulWidget {
  final AIModelConfigModel model;
  final Function(AIModelConfigModel) onModelUpdated;

  const ModelEditDialog({
    super.key,
    required this.model,
    required this.onModelUpdated,
  });

  @override
  ConsumerState<ModelEditDialog> createState() => _ModelEditDialogState();
}

class _ModelEditDialogState extends ConsumerState<ModelEditDialog> {
  final _formKey = GlobalKey<FormState>();

  late final TextEditingController _displayNameController;
  late final TextEditingController _descriptionController;
  late final TextEditingController _apiUrlController;
  late final TextEditingController _modelIdController;
  late final TextEditingController _maxTokensController;
  late final TextEditingController _temperatureController;
  late final TextEditingController _timeoutController;
  late final TextEditingController _maxRetriesController;
  late final TextEditingController _maxConcurrentController;
  late final TextEditingController _rateLimitController;
  late final TextEditingController _costInputController;
  late final TextEditingController _costOutputController;

  bool _isLoading = false;
  String? _error;

  @override
  void initState() {
    super.initState();

    _displayNameController = TextEditingController(text: widget.model.displayName);
    _descriptionController = TextEditingController(text: widget.model.description ?? '');
    _apiUrlController = TextEditingController(text: widget.model.apiUrl);
    _modelIdController = TextEditingController(text: widget.model.modelId);
    _maxTokensController = TextEditingController(text: widget.model.maxTokens?.toString() ?? '');
    _temperatureController = TextEditingController(text: widget.model.temperature ?? '');
    _timeoutController = TextEditingController(text: widget.model.timeoutSeconds.toString());
    _maxRetriesController = TextEditingController(text: widget.model.maxRetries.toString());
    _maxConcurrentController = TextEditingController(text: widget.model.maxConcurrentRequests.toString());
    _rateLimitController = TextEditingController(text: widget.model.rateLimitPerMinute.toString());
    _costInputController = TextEditingController(text: widget.model.costPerInputToken ?? '');
    _costOutputController = TextEditingController(text: widget.model.costPerOutputToken ?? '');
  }

  Future<void> _updateModel() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() {
      _isLoading = true;
      _error = null;
    });

    final updateData = <String, dynamic>{
      'display_name': _displayNameController.text.trim(),
      'description': _descriptionController.text.trim().isEmpty ? null : _descriptionController.text.trim(),
      'api_url': _apiUrlController.text.trim(),
      'model_id': _modelIdController.text.trim(),
      'timeout_seconds': int.parse(_timeoutController.text),
      'max_retries': int.parse(_maxRetriesController.text),
      'max_concurrent_requests': int.parse(_maxConcurrentController.text),
      'rate_limit_per_minute': int.parse(_rateLimitController.text),
    };

    // 可选字段
    if (_maxTokensController.text.isNotEmpty) {
      updateData['max_tokens'] = int.parse(_maxTokensController.text);
    }
    if (_temperatureController.text.isNotEmpty) {
      updateData['temperature'] = _temperatureController.text;
    }
    if (_costInputController.text.isNotEmpty) {
      updateData['cost_per_input_token'] = _costInputController.text;
    }
    if (_costOutputController.text.isNotEmpty) {
      updateData['cost_per_output_token'] = _costOutputController.text;
    }

    try {
      final result = await ref.read(modelProvider(widget.model.id)).updateModel(updateData);

      if (result && mounted) {
        final updatedModel = ref.read(modelProvider(widget.model.id)).currentModel;
        if (updatedModel != null) {
          widget.onModelUpdated(updatedModel);
          Navigator.of(context).pop();
        }
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
          _isLoading = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('编辑模型配置'),
      content: SizedBox(
        width: double.maxFinite,
        child: Form(
          key: _formKey,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // 模型信息
                _buildInfoCard(),
                const SizedBox(height: 16),

                const Text(
                  '基本配置',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                ),
                const SizedBox(height: 8),

                _buildTextFormField(
                  controller: _displayNameController,
                  label: '显示名称 *',
                  validator: (value) => value?.isEmpty ?? true ? '请输入显示名称' : null,
                ),
                const SizedBox(height: 12),

                _buildTextFormField(
                  controller: _descriptionController,
                  label: '描述',
                  hint: '可选',
                  maxLines: 2,
                ),
                const SizedBox(height: 16),

                const Text(
                  'API配置',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                ),
                const SizedBox(height: 8),

                _buildTextFormField(
                  controller: _apiUrlController,
                  label: 'API URL *',
                  validator: (value) => value?.isEmpty ?? true ? '请输入API URL' : null,
                ),
                const SizedBox(height: 12),

                _buildTextFormField(
                  controller: _modelIdController,
                  label: '模型ID *',
                  validator: (value) => value?.isEmpty ?? true ? '请输入模型ID' : null,
                ),
                const SizedBox(height: 16),

                const Text(
                  '性能配置',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                ),
                const SizedBox(height: 8),

                Row(
                  children: [
                    Expanded(
                      child: _buildTextFormField(
                        controller: _maxTokensController,
                        label: '最大令牌数',
                        hint: '可选',
                        keyboardType: TextInputType.number,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: _buildTextFormField(
                        controller: _temperatureController,
                        label: '温度',
                        hint: '0.0-2.0',
                        keyboardType: TextInputType.number,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),

                Row(
                  children: [
                    Expanded(
                      child: _buildTextFormField(
                        controller: _timeoutController,
                        label: '超时(秒)',
                        keyboardType: TextInputType.number,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: _buildTextFormField(
                        controller: _maxRetriesController,
                        label: '最大重试',
                        keyboardType: TextInputType.number,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 12),

                Row(
                  children: [
                    Expanded(
                      child: _buildTextFormField(
                        controller: _maxConcurrentController,
                        label: '并发数',
                        keyboardType: TextInputType.number,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: _buildTextFormField(
                        controller: _rateLimitController,
                        label: '速率限制',
                        keyboardType: TextInputType.number,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),

                const Text(
                  '成本配置',
                  style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                ),
                const SizedBox(height: 8),

                Row(
                  children: [
                    Expanded(
                      child: _buildTextFormField(
                        controller: _costInputController,
                        label: '输入令牌成本',
                        hint: '可选',
                        keyboardType: const TextInputType.numberWithOptions(decimal: true),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: _buildTextFormField(
                        controller: _costOutputController,
                        label: '输出令牌成本',
                        hint: '可选',
                        keyboardType: const TextInputType.numberWithOptions(decimal: true),
                      ),
                    ),
                  ],
                ),

                if (_error != null) ...[
                  const SizedBox(height: 16),
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Colors.red.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Colors.red),
                    ),
                    child: Row(
                      children: [
                        const Icon(Icons.error, color: Colors.red, size: 20),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            _error!,
                            style: const TextStyle(color: Colors.red),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: _isLoading ? null : () => Navigator.of(context).pop(),
          child: const Text('取消'),
        ),
        ElevatedButton(
          onPressed: _isLoading ? null : _updateModel,
          child: _isLoading
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                )
              : const Text('保存'),
        ),
      ],
    );
  }

  Widget _buildInfoCard() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.blue.withOpacity(0.05),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.blue.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                widget.model.modelType == AIModelType.transcription ? Icons.record_voice_over : Icons.auto_awesome,
                color: Colors.blue,
              ),
              const SizedBox(width: 8),
              Text(
                widget.model.name,
                style: const TextStyle(
                  fontWeight: FontWeight.bold,
                  fontSize: 16,
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          Text(
            'ID: ${widget.model.id} | ${widget.model.provider} | ${widget.model.modelId}',
            style: TextStyle(
              fontSize: 12,
              color: Colors.grey[600],
            ),
          ),
          if (widget.model.isSystem) ...[
            const SizedBox(height: 4),
            const Text(
              '⚠️ 系统预设模型，部分字段不可修改',
              style: TextStyle(
                color: Colors.orange,
                fontSize: 12,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildTextFormField({
    required TextEditingController controller,
    required String label,
    String? hint,
    int maxLines = 1,
    bool isPassword = false,
    TextInputType? keyboardType,
    String? Function(String?)? validator,
  }) {
    return TextFormField(
      controller: controller,
      decoration: InputDecoration(
        labelText: label,
        hintText: hint,
        border: const OutlineInputBorder(),
        contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      ),
      maxLines: maxLines,
      keyboardType: keyboardType,
      obscureText: isPassword,
      validator: validator,
    );
  }

  @override
  void dispose() {
    _displayNameController.dispose();
    _descriptionController.dispose();
    _apiUrlController.dispose();
    _modelIdController.dispose();
    _maxTokensController.dispose();
    _temperatureController.dispose();
    _timeoutController.dispose();
    _maxRetriesController.dispose();
    _maxConcurrentController.dispose();
    _rateLimitController.dispose();
    _costInputController.dispose();
    _costOutputController.dispose();
    super.dispose();
  }
}