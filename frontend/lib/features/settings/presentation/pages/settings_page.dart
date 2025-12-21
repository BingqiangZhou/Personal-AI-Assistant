import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

class SettingsPage extends ConsumerWidget {
  const SettingsPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // General Settings
          _buildSection(
            title: 'General',
            children: [
              SwitchListTile(
                title: const Text('Dark Mode'),
                subtitle: const Text('Enable dark theme'),
                value: false,
                onChanged: (value) {
                  // TODO: Implement theme switching
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Theme switching coming soon!')),
                  );
                },
              ),
              ListTile(
                title: const Text('Language'),
                subtitle: const Text('English'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Language selection coming soon!')),
                  );
                },
              ),
            ],
          ),

          const SizedBox(height: 16),

          // Assistant Settings
          _buildSection(
            title: 'AI Assistant',
            children: [
              ListTile(
                title: const Text('AI Model Management'),
                subtitle: const Text('Configure AI models and providers'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  context.go('/profile/settings/ai-models');
                },
              ),
              SwitchListTile(
                title: const Text('Voice Input'),
                subtitle: const Text('Enable voice commands'),
                value: false,
                onChanged: (value) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Voice input coming soon!')),
                  );
                },
              ),
            ],
          ),

          const SizedBox(height: 16),

          // Knowledge Base Settings
          _buildSection(
            title: 'Knowledge Base',
            children: [
              ListTile(
                title: const Text('Import/Export'),
                subtitle: const Text('Manage your knowledge data'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Import/Export coming soon!')),
                  );
                },
              ),
              ListTile(
                title: const Text('Storage'),
                subtitle: const Text('Manage storage usage'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Storage management coming soon!')),
                  );
                },
              ),
            ],
          ),

          const SizedBox(height: 16),

          // Podcast Settings
          _buildSection(
            title: 'Podcasts',
            children: [
              SwitchListTile(
                title: const Text('Auto-download'),
                subtitle: const Text('Download new episodes automatically'),
                value: false,
                onChanged: (value) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Auto-download coming soon!')),
                  );
                },
              ),
              ListTile(
                title: const Text('Playback Quality'),
                subtitle: const Text('High'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Quality settings coming soon!')),
                  );
                },
              ),
            ],
          ),

          const SizedBox(height: 16),

          // About
          _buildSection(
            title: 'About',
            children: [
              ListTile(
                title: const Text('Version'),
                subtitle: const Text('1.0.0'),
              ),
              ListTile(
                title: const Text('About'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  showAboutDialog(
                    context: context,
                    applicationName: 'Personal AI Assistant',
                    applicationVersion: '1.0.0',
                    applicationIcon: const Icon(Icons.smart_toy, size: 48),
                    children: [
                      const Text('A comprehensive personal AI assistant with knowledge base management and podcast features.'),
                    ],
                  );
                },
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildSection({
    required String title,
    required List<Widget> children,
  }) {
    return Card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.all(16),
            child: Text(
              title,
              style: const TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
          ...children,
        ],
      ),
    );
  }
}