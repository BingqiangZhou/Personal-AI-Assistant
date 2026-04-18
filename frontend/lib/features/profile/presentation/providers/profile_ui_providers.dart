import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:personal_ai_assistant/core/storage/local_storage_service.dart';
import 'package:personal_ai_assistant/core/utils/app_logger.dart' as logger;

/// Manages the notification toggle preference stored in local storage.
class NotificationPreferenceNotifier extends Notifier<bool> {
  static const String _storageKey = 'profile_notifications_enabled';

  @override
  bool build() {
    _loadFromStorage();
    return true;
  }

  Future<void> _loadFromStorage() async {
    try {
      final storage = ref.read(localStorageServiceProvider);
      final saved = await storage.getBool(_storageKey);
      if (saved != null) {
        state = saved;
      }
    } catch (e) {
      logger.AppLogger.debug('Error loading notification preference: $e');
    }
  }

  Future<void> setEnabled(bool value) async {
    state = value;
    try {
      final storage = ref.read(localStorageServiceProvider);
      await storage.saveBool(_storageKey, value);
    } catch (e) {
      logger.AppLogger.debug('Error saving notification preference: $e');
    }
  }
}

/// Provider for notification preference state.
final notificationPreferenceProvider =
    NotifierProvider<NotificationPreferenceNotifier, bool>(
  NotificationPreferenceNotifier.new,
);

/// Manages the app version string loaded from PackageInfo.
class AppVersionNotifier extends Notifier<String> {
  @override
  String build() {
    // Load version asynchronously on first access
    _loadVersion();
    return 'Loading...';
  }

  Future<void> _loadVersion() async {
    try {
      final packageInfo = await PackageInfo.fromPlatform();
      state = 'v${packageInfo.version} (${packageInfo.buildNumber})';
    } catch (e) {
      logger.AppLogger.debug('Error loading version: $e');
      state = 'Unknown';
    }
  }
}

/// Provider for app version display string.
final appVersionProvider = NotifierProvider<AppVersionNotifier, String>(
  AppVersionNotifier.new,
);
