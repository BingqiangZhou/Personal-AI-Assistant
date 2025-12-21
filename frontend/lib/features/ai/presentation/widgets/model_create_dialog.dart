import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../models/ai_model_config_model.dart';
import '../providers/ai_model_provider.dart';

class ModelCreateDialog extends ConsumerStatefulWidget {
  final AIModelType initialType;
  final Function(AIModelConfigModel) onModelCreated;

  const ModelCreateDialog({
    super.key,
    required this.initialType,
    required this.onModelCreated,
  });

  @override
  ConsumerState<ModelCreateDialog> createState() => _ModelCreateDialogState();
}

class _ModelCreateDialogState extends ConsumerState<ModelCreateDialog> {
  final _formKey = GlobalKey<FormState>();

  late AIModelType _modelType;
  final _nameController = TextEditingController();
  final _displayNameController = TextEditingController();
  final _descriptionController = TextEditingController();
  final _apiUrlController = TextEditingController();
  final _apiKeyController = TextEditingController();
  final _modelIdController = TextEditingController();
  final _providerController = TextEditingController(text: 'custom');
  final _maxTokensController = TextEditingController();
  final _temperatureController = TextEditingController(text: '0.7');
  final _timeoutController = TextEditingController(text: '300');
  final _maxRetriesController = TextEditingController(text: '3');
  final _maxConcurrentController = TextEditingController(text: '1');
  final _rateLimitController = TextEditingController(text: '60');
  final _costInputController = TextEditingController();
  final _costOutputController = TextEditingController();

  bool _isLoading = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _modelType = widget.initialType;
    _updateDefaultValues();
  }

  void _updateDefaultValues() {
    if (_modelType == AIModelType.transcription) {
      _providerController.text = 'siliconflow';
      _apiUrlController.text = 'https://api.siliconflow.cn/v1/audio/transcriptions';
      _modelIdController.text = 'FunAudioLLM/SenseVoiceSmall';
    } else {
      _providerController.text = 'openai';
      _apiUrlController.text = 'https://api.openai.com/v1';
      _modelIdController.text = 'gpt-4o-mini';
    }
  }

  Future<void> _createModel() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() {
      _isLoading = true;
      _error = null;
    });

    final modelData = {
      'name': _nameController.text.trim(),
      'display_name': _displayNameController.text.trim(),
      'description': _descriptionController.text.trim().isEmpty ? null : _descriptionController.text.trim(),
      'model_type': _modelType.toString().split('.').last,
      'api_url': _apiUrlController.text.trim(),
      'api_key': _apiKeyController.text.trim(),
      'model_id': _modelIdController.text.trim(),
      'provider': _providerController.text.trim(),
      'max_tokens': _maxTokensController.text.isNotEmpty ? int.parse(_maxTokensController.text) : null,
      'temperature': _temperatureController.text,
      'timeout_seconds': int.parse(_timeoutController.text),
      'max_retries': int.parse(_maxRetriesController.text),
      'max_concurrent_requests': int.parse(_maxConcurrentController.text),
      'rate_limit_per_minute': int.parse(_rateLimitController.text),
      'cost_per_input_token': _costInputController.text.isEmpty ? null : _costInputController.text,
      'cost_per_output_token': _costOutputController.text.isEmpty ? null : _costOutputController.text,
      'is_active': true,
      'is_default': false,
    };

    try {
      final result = await ref.read(createModelProvider.notifier).createModel(modelData);

      if (result != null && mounted) {
        widget.onModelCreated(result);
        Navigator.of(context).pop();
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
      title: const Text('创建AI模型配置'),
      content: SizedBox(
        width: double.maxFinite,
        child: Form(
          key: _formKey,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // 模型类型
                _buildModelTypeSelector(),
                const SizedBox(height: 16),

                // 基本信息
                _buildTextFormField(
                  controller: _nameController,
                  label: '模型名称 *',
                  hint: '例如: whisper-v3',
                  validator: (value) => value?.isEmpty ?? true ? '请输入模型名称' : null,
                ),
                const SizedBox(height: 12),

                _buildTextFormField(
                  controller: _displayNameController,
                  label: '显示名称 *',
                  hint: '例如: Whisper Large v3',
                  validator: (value) => value?.isEmpty ?? true ? '请输入显示名称' : null,
                ),
                const SizedBox(height: 12),

                _buildTextFormField(
                  controller: _descriptionController,
                  label: '描述',
                  hint: '模型的简要描述',
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
                  hint: 'https://api.example.com/v1',
                  validator: (value) => value?.isEmpty ?? true ? '请输入API URL' : null,
                ),
                const SizedBox(height: 12),

                _buildTextFormField(
                  controller: _apiKeyController,
                  label: 'API Key *',
                  hint: 'sk-...',
                  isPassword: true,
                  validator: (value) => value?.isEmpty ?? true ? '请输入API Key' : null,
                ),
                const SizedBox(height: 12),

                _buildTextFormField(
                  controller: _modelIdController,
                  label: '模型ID *',
                  hint: '例如: whisper-1',
                  validator: (value) => value?.isEmpty ?? true ? '请输入模型ID' : null,
                ),
                const SizedBox(height: 12),

                _buildTextFormField(
                  controller: _providerController,
                  label: '提供商 *',
                  hint: 'openai, siliconflow, custom',
                  validator: (value) => value?.isEmpty ?? true ? '请输入提供商' : null,
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
                        hint: '300',
                        keyboardType: TextInputType.number,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: _buildTextFormField(
                        controller: _maxRetriesController,
                        label: '最大重试',
                        hint: '3',
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
                        hint: '1',
                        keyboardType: TextInputType.number,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: _buildTextFormField(
                        controller: _rateLimitController,
                        label: '速率限制',
                        hint: '60',
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
          onPressed: _isLoading ? null : _createModel,
          child: _isLoading
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                )
              : const Text('创建'),
        ),
      ],
    );
  }

  Widget _buildModelTypeSelector() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.grey.withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          const Icon(Icons.category, size: 20),
          const SizedBox(width: 8),
          const Text('模型类型:', style: TextStyle(fontWeight: FontWeight.bold)),
          const SizedBox(width: 12),
          SegmentedButton<AIModelType>(
            segments: const [
              ButtonSegment<AIModelType>(
                value: AIModelType.transcription,
                label: Text('转录模型'),
                icon: Icon(Icons.record_voice_over),
              ),
              ButtonSegment<AIModelType>(
                value: AIModelType.textGeneration,
                label: Text('文本生成'),
                icon: Icon(Icons.auto_awesome),
              ),
            ],
            selected: {_modelType},
            onSelectionChanged: (Set<AIModelType> newSelection) {
              setState(() {
                _modelType = newSelection.first;
                _updateDefaultValues();
              });
            },
          ),
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
    _nameController.dispose();
    _displayNameController.dispose();
    _descriptionController.dispose();
    _apiUrlController.dispose();
    _apiKeyController.dispose();
    _modelIdController.dispose();
    _providerController.dispose();
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