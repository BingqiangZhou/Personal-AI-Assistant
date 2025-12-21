import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

class SettingsPage extends ConsumerStatefulWidget {
  const SettingsPage({super.key});

  @override
  ConsumerState<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends ConsumerState<SettingsPage> {
  // AI Text Generation Settings
  final _textGenerationUrlController = TextEditingController(text: 'https://api.openai.com/v1');
  final _textGenerationApiKeyController = TextEditingController();
  String _selectedTextModel = 'gpt-4o-mini';
  final List<String> _textModels = ['gpt-4o-mini', 'gpt-4o', 'gpt-3.5-turbo'];

  // Transcription Settings
  final _transcriptionUrlController = TextEditingController(text: 'https://api.siliconflow.cn/v1/audio/transcriptions');
  final _transcriptionApiKeyController = TextEditingController();
  String _selectedTranscriptionModel = 'FunAudioLLM/SenseVoiceSmall';
  final List<String> _transcriptionModels = ['FunAudioLLM/SenseVoiceSmall', 'whisper-1', 'whisper-large-v3'];

  // App Settings
  bool _darkModeEnabled = false;
  int _chunkSizeMB = 10;
  int _maxThreads = 4;

  @override
  void dispose() {
    _textGenerationUrlController.dispose();
    _textGenerationApiKeyController.dispose();
    _transcriptionUrlController.dispose();
    _transcriptionApiKeyController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
        actions: [
          TextButton.icon(
            onPressed: _saveSettings,
            icon: const Icon(Icons.save),
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
              children: [
                _buildTextField(
                  controller: _textGenerationUrlController,
                  label: 'API Base URL',
                  hint: 'https://api.openai.com/v1',
                  prefixIcon: Icons.link,
                ),
                const SizedBox(height: 16),
                _buildTextField(
                  controller: _textGenerationApiKeyController,
                  label: 'API Key',
                  hint: 'sk-...',
                  prefixIcon: Icons.key,
                  obscureText: true,
                ),
                const SizedBox(height: 16),
                _buildDropdown(
                  label: 'Model',
                  value: _selectedTextModel,
                  items: _textModels,
                  onChanged: (value) {
                    setState(() {
                      _selectedTextModel = value!;
                    });
                  },
                ),
                const SizedBox(height: 8),
                _buildInfoCard(
                  'This model will be used for generating AI summaries, chat responses, and other text generation tasks.',
                ),
              ],
            ),

            const SizedBox(height: 24),

            // Transcription Section
            _buildSection(
              title: 'Audio Transcription Model',
              icon: Icons.mic,
              children: [
                _buildTextField(
                  controller: _transcriptionUrlController,
                  label: 'API URL',
                  hint: 'https://api.siliconflow.cn/v1/audio/transcriptions',
                  prefixIcon: Icons.link,
                ),
                const SizedBox(height: 16),
                _buildTextField(
                  controller: _transcriptionApiKeyController,
                  label: 'API Key',
                  hint: 'Enter your transcription API key',
                  prefixIcon: Icons.key,
                  obscureText: true,
                ),
                const SizedBox(height: 16),
                _buildDropdown(
                  label: 'Model',
                  value: _selectedTranscriptionModel,
                  items: _transcriptionModels,
                  onChanged: (value) {
                    setState(() {
                      _selectedTranscriptionModel = value!;
                    });
                  },
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
                      max: 8,
                      divisions: 7,
                      label: '$_maxThreads',
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
  }) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
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
  }) {
    return TextField(
      controller: controller,
      obscureText: obscureText,
      decoration: InputDecoration(
        labelText: label,
        hintText: hint,
        prefixIcon: Icon(prefixIcon),
        border: const OutlineInputBorder(),
        suffixIcon: obscureText
            ? IconButton(
                icon: const Icon(Icons.visibility),
                onPressed: () {
                  // Toggle visibility
                },
              )
            : null,
      ),
    );
  }

  Widget _buildDropdown({
    required String label,
    required String value,
    required List<String> items,
    required ValueChanged<String?> onChanged,
  }) {
    return DropdownButtonFormField<String>(
      value: value,
      decoration: InputDecoration(
        labelText: label,
        border: const OutlineInputBorder(),
        prefixIcon: const Icon(Icons.model_training),
      ),
      items: items.map((item) {
        return DropdownMenuItem(
          value: item,
          child: Text(item),
        );
      }).toList(),
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

  void _saveSettings() {
    // TODO: Implement API call to save settings
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Text('Settings saved successfully!'),
        backgroundColor: Theme.of(context).colorScheme.primary,
        action: SnackBarAction(
          label: 'OK',
          textColor: Colors.white,
          onPressed: () {},
        ),
      ),
    );
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
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            name,
            style: const TextStyle(fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 4),
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: Colors.grey[200],
              borderRadius: BorderRadius.circular(4),
            ),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    endpoint,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEnvVar(String name, String description) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            '• ',
            style: TextStyle(color: Theme.of(context).colorScheme.primary),
          ),
          Expanded(
            child: RichText(
              text: TextSpan(
                style: TextStyle(color: Theme.of(context).colorScheme.onSurface),
                children: [
                  TextSpan(
                    text: name,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const TextSpan(text: ': '),
                  TextSpan(text: description),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}