import 'dart:async';
import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/network/server_health_service.dart';
import 'package:personal_ai_assistant/core/providers/core_providers.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../../ai/models/ai_model_config_model.dart';
import '../../../ai/presentation/widgets/model_create_dialog.dart';
import '../../../ai/presentation/widgets/model_edit_dialog.dart';
import '../../../ai/presentation/providers/ai_model_provider.dart' hide aiModelApiServiceProvider;
import '../providers/ai_settings_provider.dart';
import '../widgets/update_dialog.dart';

class SettingsPage extends ConsumerStatefulWidget {
  const SettingsPage({super.key});

  @override
  ConsumerState<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends ConsumerState<SettingsPage> {
  // AI Text Generation Settings
  final _textGenerationUrlController = TextEditingController();
  final _textGenerationApiKeyController = TextEditingController();
  final _textModelController = TextEditingController();

  // Transcription Settings
  final _transcriptionUrlController = TextEditingController();
  final _transcriptionApiKeyController = TextEditingController();
  final _transcriptionModelController = TextEditingController();

  // Add state variables for key visibility
  bool _isTextKeyObscured = true;
  bool _isTranscriptionKeyObscured = true;

  // Model Selection State
  List<AIModelConfigModel> _textGenerationConfigs = [];
  List<AIModelConfigModel> _transcriptionConfigs = [];
  AIModelConfigModel? _selectedTextGenerationConfig;
  AIModelConfigModel? _selectedTranscriptionConfig;
  bool _isLoadingModels = false;

  // Processing Settings
  int _chunkSizeMB = 10;
  int _maxThreads = 4;

  // App Preferences
  bool _darkModeEnabled = true;

  // Server Config (Hidden Feature)
  int _versionTapCount = 0;
  Timer? _versionTapResetTimer;
  final _serverUrlController = TextEditingController();
  ConnectionStatus _connectionStatus = ConnectionStatus.unverified;
  String? _connectionMessage;
  Timer? _debounceTimer;
  final StreamController<HealthCheckResult> _healthCheckController = StreamController.broadcast();
  StreamSubscription? _healthCheckSubscription;

  // Storage key for custom server URL
  static const String _serverBaseUrlKey = 'server_base_url';

  @override
  void initState() {
    super.initState();
    _loadModels();
    _loadServerUrl();
  }

  @override
  void dispose() {
    _versionTapResetTimer?.cancel();
    _debounceTimer?.cancel();
    _healthCheckSubscription?.cancel();
    _healthCheckController.close();
    _serverUrlController.dispose();

    _textGenerationUrlController.dispose();
    _textGenerationApiKeyController.dispose();
    _textModelController.dispose();
    _transcriptionUrlController.dispose();
    _transcriptionApiKeyController.dispose();
    _transcriptionModelController.dispose();
    super.dispose();
  }

  /// Load saved server URL from local storage
  Future<void> _loadServerUrl() async {
    final prefs = await SharedPreferences.getInstance();
    final savedUrl = prefs.getString(_serverBaseUrlKey);
    if (savedUrl != null) {
      _serverUrlController.text = savedUrl;
    }
  }

  Future<void> _fetchFullModelDetails(int id, Function(AIModelConfigModel) onLoaded) async {
    try {
      // Use repository directly to request decrypted key
      final repository = ref.read(aiModelRepositoryProvider);
      final fullModel = await repository.getModel(id, decryptKey: true);
      
      if (mounted) {
        onLoaded(fullModel);
      }
    } catch (e) {
      debugPrint('Failed to load full model details: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final settingsState = ref.watch(aiSettingsControllerProvider);

    // Removed state-variable driven dialog logic, now handled directly in event handlers

    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.settings),
        actions: [
          TextButton.icon(
            onPressed: settingsState.isLoading ? null : _saveSettings,
            icon: settingsState.isLoading
                ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.save),
            label: Text(l10n.save),
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // AI Text Generation Section
            _buildSection(
              title: l10n.settings_ai_text_generation,
              icon: Icons.auto_awesome,
              headerAction: Row(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Expanded(
                    child: _buildDropdown(
                      label: l10n.settings_config,
                      value: _selectedTextGenerationConfig?.id.toString() ?? '',
                      items: ['', ..._textGenerationConfigs.map((model) => model.id.toString())],
                      displayItems: [l10n.settings_add_new, ..._textGenerationConfigs.map((model) => model.displayName)],
                      onChanged: (value) async {
                        if (value == null || value.isEmpty) {
                          showDialog(
                            context: context,
                            builder: (context) => ModelCreateDialog(
                              initialType: AIModelType.textGeneration,
                              onModelCreated: (model) {
                                _loadModels();
                              },
                            ),
                          );
                        } else {
                          final selectedConfig = _textGenerationConfigs.firstWhere((model) => model.id.toString() == value);
                          setState(() {
                            _selectedTextGenerationConfig = selectedConfig;
                            _textGenerationUrlController.text = selectedConfig.apiUrl;
                            _textGenerationApiKeyController.text = selectedConfig.apiKey ?? '';
                            _textModelController.text = selectedConfig.modelId;
                          });

                          // Fetch full details
                          await _fetchFullModelDetails(selectedConfig.id, (fullModel) {
                             _textGenerationApiKeyController.text = fullModel.apiKey ?? '';
                          });
                        }
                      },
                    ),
                  ),
                  if (_selectedTextGenerationConfig != null) ...[
                    IconButton(
                      icon: const Icon(Icons.edit, size: 20),
                      tooltip: l10n.settings_edit_config,
                      onPressed: () {
                        showDialog(
                          context: context,
                          builder: (context) => ModelEditDialog(
                            model: _selectedTextGenerationConfig!,
                            onModelUpdated: (model) {
                              _loadModels();
                            },
                          ),
                        );
                      },
                    ),
                    IconButton(
                      icon: const Icon(Icons.delete, color: Colors.red, size: 20),
                      tooltip: l10n.settings_delete_config,
                      onPressed: () => _showDeleteConfirmDialog(_selectedTextGenerationConfig!),
                    ),
                  ],
                ],
              ),
              titleSuffix: TextButton.icon(
                onPressed: _testConnection,
                icon: const Icon(Icons.network_check, size: 20),
                label: Text(l10n.settings_test_connection),
              ),
              children: [
                _buildTextField(
                  controller: _textGenerationUrlController,
                  label: l10n.settings_api_base_url,
                  hint: 'https://...',
                  prefixIcon: Icons.link,
                ),
                const SizedBox(height: 16),
                _buildTextField(
                  controller: _textGenerationApiKeyController,
                  label: l10n.ai_api_key,
                  hint: 'sk-...',
                  prefixIcon: Icons.key,
                  obscureText: _isTextKeyObscured,
                  onToggleObscure: () {
                    setState(() {
                      _isTextKeyObscured = !_isTextKeyObscured;
                    });
                  },
                ),
                const SizedBox(height: 16),
                _buildTextField(
                  controller: _textModelController,
                  label: l10n.ai_model_name_field,
                  hint: 'e.g. model-id',
                  prefixIcon: Icons.psychology,
                ),
                const SizedBox(height: 8),
                _buildInfoCard(
                  l10n.settings_model_info_ai_tasks,
                ),
              ],
            ),

            const SizedBox(height: 24),

            // Transcription Section
            _buildSection(
              title: l10n.settings_audio_transcription,
              icon: Icons.mic,
              headerAction: Row(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Expanded(
                    child: _buildDropdown(
                      label: l10n.settings_config,
                      value: _selectedTranscriptionConfig?.id.toString() ?? '',
                      items: ['', ..._transcriptionConfigs.map((model) => model.id.toString())],
                      displayItems: [l10n.settings_add_new, ..._transcriptionConfigs.map((model) => model.displayName)],
                      onChanged: (value) async {
                        if (value == null || value.isEmpty) {
                          showDialog(
                            context: context,
                            builder: (context) => ModelCreateDialog(
                              initialType: AIModelType.transcription,
                              onModelCreated: (model) {
                                _loadModels();
                              },
                            ),
                          );
                        } else {
                          final selectedConfig = _transcriptionConfigs.firstWhere((model) => model.id.toString() == value);
                          setState(() {
                            _selectedTranscriptionConfig = selectedConfig;
                            _transcriptionUrlController.text = selectedConfig.apiUrl;
                            _transcriptionApiKeyController.text = selectedConfig.apiKey ?? '';
                            _transcriptionModelController.text = selectedConfig.modelId;
                          });

                          // Fetch full details
                          await _fetchFullModelDetails(selectedConfig.id, (fullModel) {
                             _transcriptionApiKeyController.text = fullModel.apiKey ?? '';
                          });
                        }
                      },
                    ),
                  ),
                  if (_selectedTranscriptionConfig != null) ...[
                    const SizedBox(width: 8),
                    IconButton(
                      icon: const Icon(Icons.edit, size: 20),
                      tooltip: l10n.settings_edit_config,
                      onPressed: () {
                        showDialog(
                          context: context,
                          builder: (context) => ModelEditDialog(
                            model: _selectedTranscriptionConfig!,
                            onModelUpdated: (model) {
                              _loadModels();
                            },
                          ),
                        );
                      },
                    ),
                    IconButton(
                      icon: const Icon(Icons.delete, color: Colors.red, size: 20),
                      tooltip: l10n.settings_delete_config,
                      onPressed: () => _showDeleteConfirmDialog(_selectedTranscriptionConfig!),
                    ),
                  ],
                ],
              ),
              children: [
                _buildTextField(
                  controller: _transcriptionUrlController,
                  label: l10n.settings_api_url,
                  hint: 'https://...',
                  prefixIcon: Icons.link,
                ),
                const SizedBox(height: 16),
                _buildTextField(
                  controller: _transcriptionApiKeyController,
                  label: l10n.ai_api_key,
                  hint: l10n.settings_transcription_api_key_hint,
                  prefixIcon: Icons.key,
                  obscureText: _isTranscriptionKeyObscured,
                  onToggleObscure: () {
                    setState(() {
                      _isTranscriptionKeyObscured = !_isTranscriptionKeyObscured;
                    });
                  },
                ),
                const SizedBox(height: 16),
                _buildTextField(
                  controller: _transcriptionModelController,
                  label: l10n.ai_model_name_field,
                  hint: 'e.g. whisper-1',
                  prefixIcon: Icons.psychology,
                ),
                const SizedBox(height: 8),
                _buildInfoCard(
                  l10n.settings_model_info_transcription,
                ),
              ],
            ),

            const SizedBox(height: 24),

            // Processing Settings
            _buildSection(
              title: l10n.settings_processing,
              icon: Icons.settings_applications,
              children: [
                ListTile(
                  title: Text(l10n.settings_audio_chunk_size),
                  subtitle: Text(l10n.settings_mb_per_chunk(_chunkSizeMB)),
                  trailing: SizedBox(
                    width: 200,
                    child: Slider(
                      value: _chunkSizeMB.toDouble(),
                      min: 5,
                      max: 25,
                      divisions: 20,
                      label: '${_chunkSizeMB}MB',
                      onChanged: (value) {
                        setState(() {
                          _chunkSizeMB = value.toInt();
                        });
                      },
                    ),
                  ),
                ),
                const Divider(),
                ListTile(
                  title: Text(l10n.settings_max_threads),
                  subtitle: Text(l10n.settings_threads(_maxThreads)),
                  trailing: SizedBox(
                    width: 200,
                    child: Slider(
                      value: _maxThreads.toDouble(),
                      min: 1,
                      max: 16,
                      divisions: 15,
                      label: '$_maxThreads threads',
                      onChanged: (value) {
                        setState(() {
                          _maxThreads = value.toInt();
                        });
                      },
                    ),
                  ),
                ),
              ],
            ),

            const SizedBox(height: 24),

            // RSS Subscription Settings
            _buildSection(
              title: l10n.settings_rss_subscription,
              icon: Icons.rss_feed,
              children: [
                ListTile(
                  title: Text(l10n.settings_rss_schedule_config),
                  subtitle: Text(l10n.settings_rss_schedule_subtitle),
                  trailing: const Icon(Icons.arrow_forward_ios),
                  onTap: () {
                    context.push('/profile/settings/rss-schedule');
                  },
                ),
              ],
            ),

            const SizedBox(height: 24),
            // About Section
            _buildSection(
              title: l10n.about,
              icon: Icons.info_outline,
              children: [
                ListTile(
                  title: Text(l10n.version),
                  subtitle: const Text('1.0.0'),
                  onTap: _onVersionTapped,
                ),
                const Divider(),
                ListTile(
                  title: Text(l10n.update_check_updates),
                  subtitle: Text(l10n.update_auto_check),
                  trailing: const Icon(Icons.system_update_alt),
                  onTap: () {
                    ManualUpdateCheckDialog.show(context);
                  },
                ),
                const Divider(),
                ListTile(
                  title: Text(l10n.settings_backend_api_docs),
                  subtitle: Text(l10n.settings_backend_api_docs_subtitle),
                  trailing: const Icon(Icons.open_in_new),
                  onTap: () {
                    _showApiDocsDialog();
                  },
                ),
              ],
            ),

            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }

  Widget _buildSection({
    required String title,
    required IconData icon,
    required List<Widget> children,
    Widget? headerAction,
    Widget? titleSuffix,
  }) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(icon, color: Theme.of(context).colorScheme.primary),
                    const SizedBox(width: 12),
                    Text(
                      title,
                      style: Theme.of(context).textTheme.titleLarge?.copyWith(
                            fontWeight: FontWeight.bold,
                          ),
                    ),
                    if (titleSuffix != null) ...[
                      const SizedBox(width: 12),
                      titleSuffix,
                    ],
                  ],
                ),
                if (headerAction != null) ...[
                  const SizedBox(height: 12),
                  headerAction,
                ],
              ],
            ),
            const SizedBox(height: 16),
            ...children,
          ],
        ),
      ),
    );
  }

  Widget _buildTextField({
    required TextEditingController controller,
    required String label,
    required String hint,
    required IconData prefixIcon,
    bool obscureText = false,
    Function()? onToggleObscure,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: Theme.of(context).textTheme.labelMedium,
        ),
        const SizedBox(height: 4),
        TextField(
          controller: controller,
          obscureText: obscureText,
          decoration: InputDecoration(
            hintText: hint,
            prefixIcon: Icon(prefixIcon),
            suffixIcon: onToggleObscure != null
                ? IconButton(
                    icon: Icon(
                      obscureText ? Icons.visibility : Icons.visibility_off,
                    ),
                    onPressed: onToggleObscure,
                  )
                : null,
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildDropdown({
    required String label,
    required String value,
    required List<String> items,
    List<String>? displayItems,
    required Function(String?)? onChanged,
  }) {
    return DropdownButtonFormField<String>(
      value: value,
      decoration: InputDecoration(
        labelText: label,
        border: const OutlineInputBorder(),
        prefixIcon: const Icon(Icons.model_training),
        contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        isDense: true,
      ),
      items: List.generate(items.length, (index) {
        final item = items[index];
        final displayText = displayItems != null && displayItems.length > index 
            ? displayItems[index] 
            : item;
        return DropdownMenuItem(
          value: item,
          child: Text(displayText),
        );
      }),
      onChanged: onChanged,
    );
  }

  Widget _buildInfoCard(String text) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(
            Icons.info_outline,
            size: 20,
            color: Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              text,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _saveSettings() async {
    // Get the models for each type to check if we need to create new models
    final textModels = ref.read(activeTextModelsProvider).value ?? [];
    final transcriptionModels = ref.read(activeTranscriptionModelsProvider).value ?? [];

    // Helper to get effective API key
    String getEffectiveApiKey(String enteredKey, List<AIModelConfigModel> models, String modelId) {
      if (enteredKey.isNotEmpty) {
        return enteredKey;
      }
      // Fallback to existing model's API key if same model is used
      final matchingModel = models.firstWhere(
        (model) => model.modelId == modelId,
        orElse: () => AIModelConfigModel.create(
          name: '',
          displayName: '',
          modelType: AIModelType.textGeneration,
          apiUrl: '',
          modelId: '',
          provider: '',
        ),
      );
      return matchingModel.apiKey ?? '';
    }

    // Save Text Generation Settings
    final textApiKey = getEffectiveApiKey(
      _textGenerationApiKeyController.text,
      textModels,
      _textModelController.text,
    );

    await ref.read(aiSettingsControllerProvider.notifier).saveSettings(
      type: 'text',
      apiUrl: _textGenerationUrlController.text,
      apiKey: textApiKey,
      modelId: _textModelController.text,
      name: _selectedTextGenerationConfig?.name ?? _textModelController.text,
      provider: 'openai',
      id: _selectedTextGenerationConfig?.id,
    );

    final transcriptionApiKey = getEffectiveApiKey(
      _transcriptionApiKeyController.text,
      transcriptionModels,
      _transcriptionModelController.text,
    );

    // Save Transcription Settings
    await ref.read(aiSettingsControllerProvider.notifier).saveSettings(
      type: 'transcription',
      apiUrl: _transcriptionUrlController.text,
      apiKey: transcriptionApiKey,
      modelId: _transcriptionModelController.text,
      name: _selectedTranscriptionConfig?.name ?? _transcriptionModelController.text,
      provider: _transcriptionModelController.text.toLowerCase().contains('sensevoice') ? 'siliconflow' : 'openai',
      id: _selectedTranscriptionConfig?.id,
    );

    if (mounted) {
       final state = ref.read(aiSettingsControllerProvider);
       final l10n = AppLocalizations.of(context)!;
       if (state.error != null) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('${l10n.error}: ${state.error}'), backgroundColor: Colors.red),
          );
       } else {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(l10n.settings_saved_successfully),
              backgroundColor: Theme.of(context).colorScheme.primary,
            ),
          );
       }
    }
  }

  void _showDeleteConfirmDialog(AIModelConfigModel model) async {
    final l10n = AppLocalizations.of(context)!;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.settings_delete_confirm_title),
        content: Text(l10n.settings_delete_confirm_message(model.displayName)),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: Text(l10n.cancel),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(l10n.delete, style: const TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      final notifier = ref.read(modelNotifierProvider(model.id).notifier);
      final success = await notifier.deleteModel();
      if (mounted) {
        if (success) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(l10n.settings_model_deleted(model.displayName)),
              backgroundColor: Colors.green,
            ),
          );
          _loadModels();
        } else {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(l10n.settings_delete_failed_msg),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    }
  }

  void _toggleModelActive(AIModelConfigModel model) async {
    final l10n = AppLocalizations.of(context)!;
    final notifier = ref.read(modelNotifierProvider(model.id).notifier);
    final success = await notifier.updateModel({
      'is_active': !model.isActive,
    });

    if (mounted) {
      if (success) {
        final status = model.isActive ? l10n.ai_model_disabled : l10n.ai_model_enabled;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.settings_model_enabled_disabled(status)),
            backgroundColor: Colors.green,
          ),
        );
        _refreshModels();
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.settings_operation_failed_msg),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  void _setAsDefault(AIModelConfigModel model) async {
    final l10n = AppLocalizations.of(context)!;
    final success = await ref
        .read(modelNotifierProvider(model.id).notifier)
        .setAsDefault(model.modelType.toString().split('.').last);

    if (mounted) {
      if (success) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.settings_set_default_success(model.displayName)),
            backgroundColor: Colors.green,
          ),
        );
        _refreshModels();
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.settings_set_default_failed_msg),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  Future<void> _loadModels() async {
    setState(() {
      _isLoadingModels = true;
    });

    try {
      // Load all models
      final models = await ref.read(aiModelRepositoryProvider).getModels();
      
      setState(() {
        _textGenerationConfigs = models.models.where((model) => model.modelType == AIModelType.textGeneration).toList();
        _transcriptionConfigs = models.models.where((model) => model.modelType == AIModelType.transcription).toList();

        // --- Validate Text Generation Selection ---
        if (_selectedTextGenerationConfig != null) {
          // Check if current selection still exists in the new list
          try {
            final match = _textGenerationConfigs.firstWhere((m) => m.id == _selectedTextGenerationConfig!.id);
            _selectedTextGenerationConfig = match; // Update reference to fresh object
          } catch (e) {
            // Previously selected model was deleted or is gone
            _selectedTextGenerationConfig = null;
          }
        }
        
        // If nothing selected (or just reset), try to pick a default
        if (_selectedTextGenerationConfig == null && _textGenerationConfigs.isNotEmpty) {
           _selectedTextGenerationConfig = _textGenerationConfigs.firstWhere(
              (m) => m.isDefault,
              orElse: () => _textGenerationConfigs.first,
           );
        }

        // Update Text Controllers based on final selection
        if (_selectedTextGenerationConfig != null) {
          _textGenerationUrlController.text = _selectedTextGenerationConfig!.apiUrl;
          _textModelController.text = _selectedTextGenerationConfig!.modelId;
          _textGenerationApiKeyController.text = _selectedTextGenerationConfig!.apiKey ?? '';
        } else {
          // List is empty
          _textGenerationUrlController.clear();
          _textModelController.clear();
          _textGenerationApiKeyController.clear();
        }


        // --- Validate Transcription Selection ---
        if (_selectedTranscriptionConfig != null) {
          try {
            final match = _transcriptionConfigs.firstWhere((m) => m.id == _selectedTranscriptionConfig!.id);
            _selectedTranscriptionConfig = match;
          } catch (e) {
            _selectedTranscriptionConfig = null;
          }
        }

        if (_selectedTranscriptionConfig == null && _transcriptionConfigs.isNotEmpty) {
           _selectedTranscriptionConfig = _transcriptionConfigs.firstWhere(
              (m) => m.isDefault,
              orElse: () => _transcriptionConfigs.first,
           );
        }

        // Update Transcription Controllers based on final selection
        if (_selectedTranscriptionConfig != null) {
          _transcriptionUrlController.text = _selectedTranscriptionConfig!.apiUrl;
          _transcriptionModelController.text = _selectedTranscriptionConfig!.modelId;
          _transcriptionApiKeyController.text = _selectedTranscriptionConfig!.apiKey ?? '';
        } else {
          _transcriptionUrlController.clear();
          _transcriptionModelController.clear();
          _transcriptionApiKeyController.clear();
        }

        _isLoadingModels = false;
      });

      // Fetch decrypted keys for selected models to update controllers
      if (_selectedTextGenerationConfig != null && mounted) {
        _fetchFullModelDetails(_selectedTextGenerationConfig!.id, (model) {
           if (mounted) _textGenerationApiKeyController.text = model.apiKey ?? '';
        });
      }
      if (_selectedTranscriptionConfig != null && mounted) {
        _fetchFullModelDetails(_selectedTranscriptionConfig!.id, (model) {
           if (mounted) _transcriptionApiKeyController.text = model.apiKey ?? '';
        });
      }

    } catch (e) {
      if (mounted) {
        final l10n = AppLocalizations.of(context)!;
        setState(() {
          _isLoadingModels = false;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.settings_load_models_failed(e.toString())),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  void _refreshModels() {
    _loadModels();
  }

  void _showApiDocsDialog() {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.settings_api_documentation),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              _buildApiEndpoint(l10n.settings_text_generation, '/api/v1/ai/chat'),
              const Divider(),
              _buildApiEndpoint(l10n.settings_transcription_endpoint, '/api/v1/podcast/transcribe'),
              const Divider(),
              _buildApiEndpoint(l10n.settings_user_settings_endpoint, '/api/v1/user/settings'),
              const SizedBox(height: 16),
              Text(
                l10n.settings_config_env_vars,
                style: const TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              _buildEnvVar('OPENAI_API_KEY', l10n.settings_openai_api_key),
              _buildEnvVar('OPENAI_API_BASE_URL', l10n.settings_openai_api_base_url),
              _buildEnvVar('TRANSCRIPTION_API_URL', l10n.settings_transcription_api_url),
              _buildEnvVar('TRANSCRIPTION_API_KEY', l10n.settings_transcription_api_key_env),
              _buildEnvVar('TRANSCRIPTION_MODEL', l10n.settings_transcription_model_name),
              _buildEnvVar('SUMMARY_MODEL', l10n.settings_summary_model),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(l10n.close),
          ),
        ],
      ),
    );
  }

  Widget _buildApiEndpoint(String name, String endpoint) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          name,
          style: const TextStyle(fontWeight: FontWeight.bold),
        ),
        Text(endpoint),
      ],
    );
  }

  Widget _buildEnvVar(String name, String description) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            name,
            style: const TextStyle(fontWeight: FontWeight.bold),
          ),
          Text(description),
        ],
      ),
    );
  }

  Future<void> _testConnection() async {
    final l10n = AppLocalizations.of(context)!;
    final url = _textGenerationUrlController.text.trim();
    final key = _textGenerationApiKeyController.text.trim();
    final modelId = _textModelController.text.trim();

    if (url.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.settings_enter_api_url)),
      );
      return;
    }
    if (key.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.settings_enter_api_key)),
      );
      return;
    }

    if (modelId.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.settings_enter_model_name_validation)),
      );
      return;
    }

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(l10n.settings_testing_connection),
        duration: const Duration(seconds: 1),
      ),
    );

    try {
      final result = await ref.read(aiModelRepositoryProvider).validateAPIKey(
        url,
        key,
        modelId,
        AIModelType.textGeneration,
      );

      if (mounted) {
        ScaffoldMessenger.of(context).hideCurrentSnackBar();
        showDialog(
          context: context,
          builder: (context) => AlertDialog(
            title: Row(children: [
              Icon(
                result.valid ? Icons.check_circle : Icons.error,
                color: result.valid ? Colors.green : Colors.red,
              ),
              const SizedBox(width: 8),
              Text(result.valid ? l10n.settings_connection_successful : l10n.settings_connection_failed)
            ]),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                   Text(l10n.settings_response_time(result.responseTimeMs.toInt())),
                   const SizedBox(height: 8),
                   if (result.valid) ...[
                     Text(l10n.settings_test_response, style: const TextStyle(fontWeight: FontWeight.bold)),
                     Container(
                       padding: const EdgeInsets.all(8),
                       color: Colors.grey.shade800,
                       child: Text(result.testResult ?? l10n.no_data)
                     )
                   ] else ...[
                     Text(l10n.settings_error_message, style: const TextStyle(fontWeight: FontWeight.bold)),
                     Container(
                       padding: const EdgeInsets.all(8),
                       color: Colors.red.shade900,
                       child: Text(result.errorMessage ?? l10n.settings_unknown_error)
                     )
                   ]
                ],
              ),
            ),
            actions: [
              TextButton(onPressed: () => Navigator.pop(context), child: Text(l10n.ok))
            ]
          )
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).hideCurrentSnackBar();
        showDialog(
          context: context,
          builder: (context) => AlertDialog(
            title: Row(children: [
              const Icon(Icons.error, color: Colors.red),
              const SizedBox(width: 8),
              Text(l10n.settings_connection_error)
            ]),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                   Text(l10n.settings_unexpected_error, style: const TextStyle(fontWeight: FontWeight.bold)),
                   Container(
                     padding: const EdgeInsets.all(8),
                     color: Colors.red.shade50,
                     child: Text(e.toString())
                   )
                ],
              ),
            ),
            actions: [
              TextButton(onPressed: () => Navigator.pop(context), child: Text(l10n.ok))
            ]
          )
        );
      }
    }
  }

  // ==================== Server Config (Hidden Feature) ====================

  /// Handle version tap - trigger dialog after 5 consecutive taps
  void _onVersionTapped() {
    setState(() {
      _versionTapCount++;
    });

    // Reset tap count after 1.2 seconds of inactivity
    _versionTapResetTimer?.cancel();
    _versionTapResetTimer = Timer(const Duration(milliseconds: 1200), () {
      setState(() {
        _versionTapCount = 0;
      });
    });

    // Trigger dialog after 5 taps
    if (_versionTapCount == 5) {
      setState(() {
        _versionTapCount = 0;
      });
      _versionTapResetTimer?.cancel();
      _showServerConfigDialog();
    }
  }

  /// Show server configuration dialog
  void _showServerConfigDialog() {
    setState(() {
      _connectionStatus = ConnectionStatus.unverified;
      _connectionMessage = null;
    });

    // Set default to local URL if empty
    if (_serverUrlController.text.isEmpty) {
      _serverUrlController.text = 'http://localhost:8000';
    }

    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) {
          final l10n = AppLocalizations.of(context)!;
          return AlertDialog(
            title: Text(l10n.backend_api_server_config),
            content: SizedBox(
              width: 500,
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Left: Connection status panel
                  Expanded(
                    flex: 1,
                    child: _buildConnectionStatusPanel(),
                  ),
                  const SizedBox(width: 16),
                  // Right: Input field
                  Expanded(
                    flex: 2,
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        // Quick select: Local server button
                        OutlinedButton.icon(
                          onPressed: () {
                            _serverUrlController.text = 'http://localhost:8000';
                            _onServerUrlChanged('http://localhost:8000', setDialogState);
                          },
                          icon: const Icon(Icons.computer, size: 16),
                          label: Text(l10n.use_local_url),
                          style: OutlinedButton.styleFrom(
                            minimumSize: const Size.fromHeight(32),
                          ),
                        ),
                        const SizedBox(height: 12),
                        TextField(
                          controller: _serverUrlController,
                          decoration: InputDecoration(
                            labelText: l10n.backend_api_url_label,
                            hintText: l10n.backend_api_url_hint,
                            border: const OutlineInputBorder(),
                            errorText: _connectionStatus == ConnectionStatus.failed
                                ? _connectionMessage ?? l10n.connection_error_hint
                                : null,
                          ),
                          onChanged: (value) => _onServerUrlChanged(value, setDialogState),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          l10n.backend_api_description,
                          style: TextStyle(
                            fontSize: 11,
                            color: Theme.of(context).colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.of(context).pop(),
                child: Text(l10n.cancel),
              ),
              TextButton(
                onPressed: _connectionStatus == ConnectionStatus.success
                    ? () => _saveServerConfig(context)
                    : null,
                child: Text(l10n.save),
              ),
            ],
          );
        },
      ),
    ).then((_) {
      // Clean up when dialog closes
      _debounceTimer?.cancel();
      _healthCheckSubscription?.cancel();
    });
  }

  /// Build connection status panel
  Widget _buildConnectionStatusPanel() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: _getStatusColor().withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: _getStatusColor()),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            _getStatusIcon(),
            color: _getStatusColor(),
            size: 32,
          ),
          const SizedBox(height: 8),
          Text(
            _getStatusText(),
            style: TextStyle(
              color: _getStatusColor(),
              fontWeight: FontWeight.bold,
            ),
            textAlign: TextAlign.center,
          ),
          if (_connectionMessage != null && _connectionStatus != ConnectionStatus.failed) ...[
            const SizedBox(height: 4),
            Text(
              _connectionMessage!,
              style: TextStyle(
                fontSize: 12,
                color: _getStatusColor().withOpacity(0.8),
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ],
      ),
    );
  }

  /// Get status icon based on connection status
  IconData _getStatusIcon() {
    switch (_connectionStatus) {
      case ConnectionStatus.unverified:
        return Icons.help_outline;
      case ConnectionStatus.verifying:
        return Icons.sync;
      case ConnectionStatus.success:
        return Icons.check_circle;
      case ConnectionStatus.failed:
        return Icons.error;
    }
  }

  /// Get status color based on connection status
  Color _getStatusColor() {
    switch (_connectionStatus) {
      case ConnectionStatus.unverified:
        return Colors.grey;
      case ConnectionStatus.verifying:
        return Colors.blue;
      case ConnectionStatus.success:
        return Colors.green;
      case ConnectionStatus.failed:
        return Colors.red;
    }
  }

  /// Get status text based on connection status
  String _getStatusText() {
    switch (_connectionStatus) {
      case ConnectionStatus.unverified:
        return '未验证\nUnverified';
      case ConnectionStatus.verifying:
        return '验证中\nVerifying';
      case ConnectionStatus.success:
        return '成功\nSuccess';
      case ConnectionStatus.failed:
        return '失败\nFailed';
    }
  }

  /// Handle server URL input change with debounce
  void _onServerUrlChanged(String value, StateSetter setDialogState) {
    // Cancel previous debounce timer
    _debounceTimer?.cancel();

    // Cancel ongoing health check
    _healthCheckSubscription?.cancel();

    // Reset to unverified if empty
    if (value.trim().isEmpty) {
      setDialogState(() {
        _connectionStatus = ConnectionStatus.unverified;
        _connectionMessage = null;
      });
      return;
    }

    // Set to verifying state
    setDialogState(() {
      _connectionStatus = ConnectionStatus.verifying;
      _connectionMessage = null;
    });

    // Debounce verification (500ms)
    _debounceTimer = Timer(const Duration(milliseconds: 500), () {
      _verifyServerConnection(value, setDialogState);
    });
  }

  /// Verify server connection using health check
  void _verifyServerConnection(String baseUrl, StateSetter setDialogState) {
    final healthService = ServerHealthService(Dio());

    _healthCheckSubscription = healthService.verifyConnection(baseUrl).listen(
      (result) {
        if (mounted) {
          setDialogState(() {
            _connectionStatus = result.status;
            _connectionMessage = result.message;
            if (result.responseTimeMs != null) {
              _connectionMessage = '${result.message} (${result.responseTimeMs}ms)';
            }
          });
        }
      },
      onError: (e) {
        if (mounted) {
          setDialogState(() {
            _connectionStatus = ConnectionStatus.failed;
            _connectionMessage = '连接错误: $e';
          });
        }
      },
    );
  }

  /// Save server configuration and apply immediately
  Future<void> _saveServerConfig(BuildContext dialogContext) async {
    final l10n = AppLocalizations.of(context)!;
    final baseUrl = _serverUrlController.text.trim();
    if (baseUrl.isEmpty) return;

    try {
      // Normalize URL (remove trailing slashes, /api/v1 suffix)
      var normalizedUrl = baseUrl.trim();
      while (normalizedUrl.endsWith('/')) {
        normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length - 1);
      }
      // Remove /api/v1 suffix if present
      if (normalizedUrl.endsWith('/api/v1')) {
        normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length - 8);
      } else if (normalizedUrl.contains('/api/v1/')) {
        normalizedUrl = normalizedUrl.replaceFirst('/api/v1/', '/');
      }

      // Save clean baseUrl to local storage (without /api/v1)
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_serverBaseUrlKey, normalizedUrl);
      debugPrint('💾 Saved backend API baseUrl: $normalizedUrl');

      // Update DioClient baseUrl immediately (runtime effect)
      final dioClient = ref.read(dioClientProvider);
      dioClient.updateBaseUrl('$normalizedUrl/api/v1');

      // Close dialog
      Navigator.of(dialogContext).pop();

      // Show success toast at top
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.connected_successfully),
            backgroundColor: Colors.green,
            behavior: SnackBarBehavior.floating,
            margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 80),
            duration: const Duration(milliseconds: 1500),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.save_failed(e.toString())),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }
}