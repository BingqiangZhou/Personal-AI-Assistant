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
  late final TextEditingController _apiUrlController;
  late final TextEditingController _modelIdController;
  // API Key is not usually shown for editing for security, unless specifically handled.
  // The backend likely returns a masked key or empty if write-only.
  // Let's assume we allow updating it.
  final _apiKeyController = TextEditingController(); 

  bool _isLoading = false;
  String? _error;
  bool _isApiKeyVisible = false;

  @override
  void initState() {
    super.initState();

    _displayNameController = TextEditingController(text: widget.model.displayName);
    _apiUrlController = TextEditingController(text: widget.model.apiUrl);
    _modelIdController = TextEditingController(text: widget.model.modelId);
    // Fetch decrypted API key from backend
    _loadDecryptedKey();
  }

  Future<void> _loadDecryptedKey() async {
    try {
      // Use repository directly to request decrypted key
      // Assuming aiModelRepositoryProvider is available from imports
      final repo = ref.read(aiModelRepositoryProvider);
      final fullModel = await repo.getModel(widget.model.id, decryptKey: true);
      if (mounted && fullModel.apiKey != null) {
         _apiKeyController.text = fullModel.apiKey!;
      }
    } catch (e) {
      debugPrint('Failed to load decrypted API key: $e');
    }
  }

  Future<void> _updateModel() async {
    if (!_formKey.currentState!.validate()) return;

    setState(() {
      _isLoading = true;
      _error = null;
    });

    final updateData = <String, dynamic>{
      'display_name': _displayNameController.text.trim(),
      'api_url': _apiUrlController.text.trim(),
      'model_id': _modelIdController.text.trim(),
      // Ensure name logic if needed, but display_name is usually enough for UI
    };
    
    // Only add API Key if user entered something (implies they want to change it)
    if (_apiKeyController.text.isNotEmpty) {
        updateData['api_key'] = _apiKeyController.text.trim();
    }

    try {
      final result = await ref.read(modelNotifierProvider(widget.model.id).notifier).updateModel(updateData);

      if (result && mounted) {
        final updatedModel = ref.read(modelNotifierProvider(widget.model.id).notifier).currentModel;
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
      title: const Text('Edit Config'),
      content: SizedBox(
        width: double.maxFinite,
        child: Form(
          key: _formKey,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildInfoCard(),
                const SizedBox(height: 16),

                _buildTextFormField(
                  controller: _displayNameController,
                  label: 'Config Name *',
                  validator: (value) => value?.isEmpty ?? true ? 'Please enter a config name' : null,
                ),
                const SizedBox(height: 12),

                _buildTextFormField(
                  controller: _apiUrlController,
                  label: 'Base URL *',
                  validator: (value) => value?.isEmpty ?? true ? 'Please enter Base URL' : null,
                ),
                const SizedBox(height: 12),

                _buildTextFormField(
                  controller: _modelIdController,
                  label: 'Model Name *',
                  validator: (value) => value?.isEmpty ?? true ? 'Please enter Model Name' : null,
                ),
                const SizedBox(height: 12),
                
                 _buildTextFormField(
                  controller: _apiKeyController,
                  label: 'API Key',
                  hint: 'Leave empty to keep unchanged',
                  isPassword: !_isApiKeyVisible,
                  suffixIcon: IconButton(
                    icon: Icon(_isApiKeyVisible ? Icons.visibility : Icons.visibility_off),
                    onPressed: () => setState(() => _isApiKeyVisible = !_isApiKeyVisible),
                  ),
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
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: _isLoading ? null : _updateModel,
          child: _isLoading
              ? const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                )
              : const Text('Save'),
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
              Expanded(
                child: Text(
                  widget.model.name,
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 16,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          Text(
            'Type: ${widget.model.modelType.toString().split('.').last} | Provider: ${widget.model.provider}',
            style: TextStyle(
              fontSize: 12,
              color: Colors.grey[600],
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
    Widget? suffixIcon,
  }) {
    return TextFormField(
      controller: controller,
      decoration: InputDecoration(
        labelText: label,
        hintText: hint,
        border: const OutlineInputBorder(),
        contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        suffixIcon: suffixIcon,
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