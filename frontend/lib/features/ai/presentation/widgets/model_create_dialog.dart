import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
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
  // User "Config Name" -> maps to display_name (and name)
  final _displayNameController = TextEditingController();
  // User "Base url" -> maps to api_url
  final _apiUrlController = TextEditingController();
  // User "Model Name" -> maps to model_id
  final _modelIdController = TextEditingController();
  // User "APIkey" -> maps to api_key
  final _apiKeyController = TextEditingController();

  bool _isLoading = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _modelType = widget.initialType;
    _updateDefaultValues();
  }

  void _updateDefaultValues() {
    // Users should enter their own configuration, no more defaults.
    _apiUrlController.text = '';
    _modelIdController.text = '';
  }

  Future<void> _createModel() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() {
      _isLoading = true;
      _error = null;
    });

    // Auto-generate name from display name (slugify-ish)
    final name = _displayNameController.text.trim();

    final modelData = {
      'name': name,
      'display_name': name,
      'model_type': _modelType == AIModelType.textGeneration ? 'text_generation' : 'transcription',
      'api_url': _apiUrlController.text.trim(),
      'api_key': _apiKeyController.text.trim(),
      'model_id': _modelIdController.text.trim(),
      // Default to generic provider or infer
      'provider': _modelType == AIModelType.transcription ? 'siliconflow' : 'openai',
      // Reasonable defaults for hidden fields
      'max_tokens': null,
      'temperature': '0.7',
      'timeout_seconds': 300,
      'max_retries': 3,
      'max_concurrent_requests': 1,
      'rate_limit_per_minute': 60,
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
    final l10n = AppLocalizations.of(context)!;
    return AlertDialog(
      title: Text(l10n.ai_create_model_config),
      content: SizedBox(
        width: double.maxFinite,
        child: Form(
          key: _formKey,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildModelTypeSelector(),
                const SizedBox(height: 16),

                _buildTextFormField(
                  controller: _displayNameController,
                  label: '${l10n.ai_config_name} *',
                  hint: l10n.ai_config_name_hint,
                  validator: (value) => value?.isEmpty ?? true ? l10n.ai_enter_config_name : null,
                ),
                const SizedBox(height: 12),

                _buildTextFormField(
                  controller: _apiUrlController,
                  label: '${l10n.ai_base_url} *',
                  hint: l10n.ai_base_url_hint,
                  validator: (value) => value?.isEmpty ?? true ? l10n.ai_enter_base_url : null,
                ),
                const SizedBox(height: 12),

                _buildTextFormField(
                  controller: _modelIdController,
                  label: '${l10n.ai_model_name_field} *',
                  hint: l10n.ai_model_id_hint,
                  validator: (value) => value?.isEmpty ?? true ? l10n.ai_enter_model_id : null,
                ),
                const SizedBox(height: 12),

                _buildTextFormField(
                  controller: _apiKeyController,
                  label: '${l10n.ai_api_key} *',
                  hint: 'sk-...',
                  isPassword: true,
                  validator: (value) => value?.isEmpty ?? true ? l10n.ai_enter_api_key : null,
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
          child: Text(l10n.cancel),
        ),
        ElevatedButton(
          onPressed: _isLoading ? null : _createModel,
          child: _isLoading
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                )
              : Text(l10n.create),
        ),
      ],
    );
  }

  Widget _buildModelTypeSelector() {
    final l10n = AppLocalizations.of(context)!;
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
          Text(l10n.ai_model_type_label, style: const TextStyle(fontWeight: FontWeight.bold)),
          const SizedBox(width: 12),
          Expanded(
            child: SegmentedButton<AIModelType>(
              segments: [
                ButtonSegment<AIModelType>(
                  value: AIModelType.transcription,
                  label: Text(l10n.ai_transcription_model),
                  icon: const Icon(Icons.record_voice_over),
                ),
                ButtonSegment<AIModelType>(
                  value: AIModelType.textGeneration,
                  label: Text('Text Gen'),
                  icon: const Icon(Icons.auto_awesome),
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
    _displayNameController.dispose();
    _apiUrlController.dispose();
    _modelIdController.dispose();
    _apiKeyController.dispose();
    super.dispose();
  }
}