import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/network/server_health_service.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:personal_ai_assistant/shared/widgets/server_config_dialog.dart';

class SettingsPage extends ConsumerStatefulWidget {
  const SettingsPage({super.key});

  @override
  ConsumerState<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends ConsumerState<SettingsPage> {
  // Server Config
  final _serverUrlController = TextEditingController();
  final ConnectionStatus _connectionStatus = ConnectionStatus.unverified;

  @override
  void initState() {
    super.initState();
    _loadServerUrl();
  }

  @override
  void dispose() {
    _serverUrlController.dispose();
    super.dispose();
  }

  /// Load saved server URL from local storage
  Future<void> _loadServerUrl() async {
    final prefs = await SharedPreferences.getInstance();
    final savedUrl = prefs.getString('server_base_url');
    if (savedUrl != null) {
      _serverUrlController.text = savedUrl;
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;

    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.settings),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Server Configuration Section
            _buildServerConfigCard(),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }

  // ==================== Server Configuration ====================

  /// Build the server configuration card displayed at the top of settings
  Widget _buildServerConfigCard() {
    final l10n = AppLocalizations.of(context)!;
    return Card(
      elevation: 2,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 标题行，与其他section保持一致的风格
            Row(
              children: [
                Icon(
                  Icons.dns_rounded,
                  color: Theme.of(context).colorScheme.primary,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    l10n.server_config_title,
                    style: Theme.of(context).textTheme.titleLarge?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            // 可点击的内容区域
            ListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(
                '${l10n.backend_api_url_label}: ${_serverUrlController.text.isEmpty ? l10n.default_server_address : _serverUrlController.text}',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
              trailing: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  // Connection status indicator
                  _buildStatusIndicator(),
                  const SizedBox(width: 8),
                  const Icon(Icons.chevron_right),
                ],
              ),
              onTap: _showServerConfigDialog,
            ),
          ],
        ),
      ),
    );
  }

  /// Build a small connection status indicator
  Widget _buildStatusIndicator() {
    IconData icon;
    Color color;

    switch (_connectionStatus) {
      case ConnectionStatus.unverified:
        icon = Icons.help_outline;
        color = Colors.grey;
        break;
      case ConnectionStatus.verifying:
        icon = Icons.sync;
        color = Colors.blue;
        break;
      case ConnectionStatus.success:
        icon = Icons.check_circle;
        color = Colors.green;
        break;
      case ConnectionStatus.failed:
        icon = Icons.error;
        color = Colors.red;
        break;
    }

    return Icon(icon, color: color, size: 20);
  }

  /// Show server configuration dialog (using shared dialog)
  void _showServerConfigDialog() {
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => ServerConfigDialog(
        initialUrl: _serverUrlController.text.isNotEmpty
            ? _serverUrlController.text
            : null,
        onSave: () {
          // Refresh the server URL display after saving
          setState(() {
            _loadServerUrl();
          });
        },
      ),
    );
  }
}
