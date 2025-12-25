import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../ai/models/ai_model_config_model.dart';
import '../../../ai/presentation/widgets/model_create_dialog.dart';
import '../../../ai/presentation/widgets/model_edit_dialog.dart';
import '../../../ai/presentation/providers/ai_model_provider.dart' hide aiModelApiServiceProvider;
import '../providers/ai_settings_provider.dart';

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

  @override
  void initState() {
    super.initState();
    _loadModels();
  }

  @override
  void dispose() {
    _textGenerationUrlController.dispose();
    _textGenerationApiKeyController.dispose();
    _textModelController.dispose();
    _transcriptionUrlController.dispose();
    _transcriptionApiKeyController.dispose();
    _transcriptionModelController.dispose();
    super.dispose();
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
    final settingsState = ref.watch(aiSettingsControllerProvider);

    // Removed state-variable driven dialog logic, now handled directly in event handlers

    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
        actions: [
          TextButton.icon(
            onPressed: settingsState.isLoading ? null : _saveSettings,
            icon: settingsState.isLoading 
                ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2)) 
                : const Icon(Icons.save),
            label: const Text('Save'),
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
              title: 'AI Text Generation Model',
              icon: Icons.auto_awesome,
              headerAction: Row(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Expanded(
                    child: _buildDropdown(
                      label: 'Config',
                      value: _selectedTextGenerationConfig?.id.toString() ?? '',
                      items: ['', ..._textGenerationConfigs.map((model) => model.id.toString())],
                      displayItems: ['Add New...', ..._textGenerationConfigs.map((model) => model.displayName)],
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
                      tooltip: 'Edit Config',
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
                      tooltip: 'Delete Config',
                      onPressed: () => _showDeleteConfirmDialog(_selectedTextGenerationConfig!),
                    ),
                  ],
                ],
              ),
              titleSuffix: TextButton.icon(
                onPressed: _testConnection,
                icon: const Icon(Icons.network_check, size: 20),
                label: const Text('Test Connection'),
              ),
              children: [
                _buildTextField(
                  controller: _textGenerationUrlController,
                  label: 'API Base URL',
                  hint: 'https://...',
                  prefixIcon: Icons.link,
                ),
                const SizedBox(height: 16),
                _buildTextField(
                  controller: _textGenerationApiKeyController,
                  label: 'API Key',
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
                  label: 'Model Name',
                  hint: 'e.g. model-id',
                  prefixIcon: Icons.psychology,
                ),
                const SizedBox(height: 8),
                _buildInfoCard(
                  'This model will be used for AI tasks. Select or create a configuration above.',
                ),
              ],
            ),

            const SizedBox(height: 24),

            // Transcription Section
            _buildSection(
              title: 'Audio Transcription Model',
              icon: Icons.mic,
              headerAction: Row(
                crossAxisAlignment: CrossAxisAlignment.center,
                children: [
                  Expanded(
                    child: _buildDropdown(
                      label: 'Config',
                      value: _selectedTranscriptionConfig?.id.toString() ?? '',
                      items: ['', ..._transcriptionConfigs.map((model) => model.id.toString())],
                      displayItems: ['Add New...', ..._transcriptionConfigs.map((model) => model.displayName)],
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
                      tooltip: 'Edit Config',
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
                      tooltip: 'Delete Config',
                      onPressed: () => _showDeleteConfirmDialog(_selectedTranscriptionConfig!),
                    ),
                  ],
                ],
              ),
              children: [
                _buildTextField(
                  controller: _transcriptionUrlController,
                  label: 'API URL',
                  hint: 'https://...',
                  prefixIcon: Icons.link,
                ),
                const SizedBox(height: 16),
                _buildTextField(
                  controller: _transcriptionApiKeyController,
                  label: 'API Key',
                  hint: 'Enter your transcription API key',
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
                  label: 'Model Name',
                  hint: 'e.g. whisper-1',
                  prefixIcon: Icons.psychology,
                ),
                const SizedBox(height: 8),
                _buildInfoCard(
                  'This model will be used for transcribing podcast audio to text.',
                ),
              ],
            ),

            const SizedBox(height: 24),

            // Processing Settings
            _buildSection(
              title: 'Processing Settings',
              icon: Icons.settings_applications,
              children: [
                ListTile(
                  title: const Text('Audio Chunk Size'),
                  subtitle: Text('${_chunkSizeMB}MB per chunk'),
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
                  title: const Text('Max Concurrent Threads'),
                  subtitle: Text('$_maxThreads threads'),
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

            // App Preferences
            _buildSection(
              title: 'App Preferences',
              icon: Icons.palette,
              children: [
                SwitchListTile(
                  title: const Text('Dark Mode'),
                  subtitle: const Text('Enable dark theme'),
                  value: _darkModeEnabled,
                  onChanged: (value) {
                    setState(() {
                      _darkModeEnabled = value;
                    });
                  },
                ),
              ],
            ),

            const SizedBox(height: 24),

            // RSS Subscription Settings
            _buildSection(
              title: 'RSS Subscription Settings',
              icon: Icons.rss_feed,
              children: [
                ListTile(
                  title: const Text('RSS Schedule Configuration'),
                  subtitle: const Text('Manage update frequency and schedule for all RSS subscriptions'),
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
              title: 'About',
              icon: Icons.info_outline,
              children: [
                ListTile(
                  title: const Text('App Version'),
                  subtitle: const Text('1.0.0'),
                ),
                const Divider(),
                ListTile(
                  title: const Text('Backend API Documentation'),
                  subtitle: const Text('View API docs and endpoints'),
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
       if (state.error != null) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Error: ${state.error}'), backgroundColor: Colors.red),
          );
       } else {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: const Text('Settings saved successfully!'),
              backgroundColor: Theme.of(context).colorScheme.primary,
            ),
          );
       }
    }
  }

  void _showDeleteConfirmDialog(AIModelConfigModel model) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('确认删除'),
        content: Text('确定要删除模型 "${model.displayName}" 吗？这将影响所有使用该模型的功能。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('取消'),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('删除', style: TextStyle(color: Colors.red)),
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
              content: Text('模型 "${model.displayName}" 已删除'),
              backgroundColor: Colors.green,
            ),
          );
          _loadModels();
        } else {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('删除失败'),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    }
  }

  void _toggleModelActive(AIModelConfigModel model) async {
    final notifier = ref.read(modelNotifierProvider(model.id).notifier);
    final success = await notifier.updateModel({
      'is_active': !model.isActive,
    });

    if (mounted) {
      if (success) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('模型已${model.isActive ? "禁用" : "启用"}'),
            backgroundColor: Colors.green,
          ),
        );
        _refreshModels();
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('操作失败'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  void _setAsDefault(AIModelConfigModel model) async {
    final success = await ref
        .read(modelNotifierProvider(model.id).notifier)
        .setAsDefault(model.modelType.toString().split('.').last);

    if (mounted) {
      if (success) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('已将 "${model.displayName}" 设为默认模型'),
            backgroundColor: Colors.green,
          ),
        );
        _refreshModels();
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('设置默认模型失败'),
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
        setState(() {
          _isLoadingModels = false;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('加载模型失败: $e'),
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
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('API Documentation'),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              _buildApiEndpoint('Text Generation', '/api/v1/ai/chat'),
              const Divider(),
              _buildApiEndpoint('Transcription', '/api/v1/podcast/transcribe'),
              const Divider(),
              _buildApiEndpoint('Settings', '/api/v1/user/settings'),
              const SizedBox(height: 16),
              const Text(
                'Configuration Environment Variables:',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              _buildEnvVar('OPENAI_API_KEY', 'OpenAI API key'),
              _buildEnvVar('OPENAI_API_BASE_URL', 'API base URL'),
              _buildEnvVar('TRANSCRIPTION_API_URL', 'Transcription API URL'),
              _buildEnvVar('TRANSCRIPTION_API_KEY', 'Transcription API key'),
              _buildEnvVar('TRANSCRIPTION_MODEL', 'Transcription model name'),
              _buildEnvVar('SUMMARY_MODEL', 'AI summary model name'),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Close'),
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
    final url = _textGenerationUrlController.text.trim();
    final key = _textGenerationApiKeyController.text.trim();
    final modelId = _textModelController.text.trim();

    if (url.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please enter API URL')),
      );
      return;
    }
    if (key.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please enter API Key')),
      );
      return;
    }

    if (modelId.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please enter Model Name')),
      );
      return;
    }

    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Testing connection...'),
        duration: Duration(seconds: 1), 
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
              Text(result.valid ? "Connection Successful" : "Connection Failed")
            ]),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                   Text("Response Time: ${result.responseTimeMs.toInt()}ms"),
                   const SizedBox(height: 8),
                   if (result.valid) ...[
                     const Text("Test Response:", style: TextStyle(fontWeight: FontWeight.bold)),
                     Container(
                       padding: const EdgeInsets.all(8),
                       color: Colors.grey.shade800,
                       child: Text(result.testResult ?? "No content")
                     )
                   ] else ...[
                     const Text("Error Message:", style: TextStyle(fontWeight: FontWeight.bold)),
                     Container(
                       padding: const EdgeInsets.all(8),
                       color: Colors.red.shade900,
                       child: Text(result.errorMessage ?? "Unknown error occurred")
                     )
                   ]
                ],
              ),
            ),
            actions: [
              TextButton(onPressed: () => Navigator.pop(context), child: const Text("OK"))
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
            title: const Row(children: [
              Icon(Icons.error, color: Colors.red),
              SizedBox(width: 8),
              Text("Connection Error")
            ]),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                   const Text("An unexpected error occurred:", style: TextStyle(fontWeight: FontWeight.bold)),
                   Container(
                     padding: const EdgeInsets.all(8),
                     color: Colors.red.shade50,
                     child: Text(e.toString())
                   )
                ],
              ),
            ),
            actions: [
              TextButton(onPressed: () => Navigator.pop(context), child: const Text("OK"))
            ]
          )
        );
      }
    }
  }
}