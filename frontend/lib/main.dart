import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:audio_service/audio_service.dart';
import 'package:permission_handler/permission_handler.dart';
import 'dart:io' show Platform;

import 'core/app/app.dart';
import 'core/app/config/app_config.dart';
import 'core/services/service_locator.dart';
import 'core/storage/local_storage_service.dart';
import 'features/podcast/presentation/providers/audio_handler.dart';

// Global AudioHandler instance (initialized once in main)
late final AudioHandler audioHandler;

void main() async {
  // Ensure Flutter binding is initialized
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize AudioService (MUST be done in main, only once)
  audioHandler = await AudioService.init(
    builder: () => PodcastAudioHandler(),
    config: AudioServiceConfig(
      androidNotificationChannelId: 'com.personal_ai_assistant.audio',
      androidNotificationChannelName: 'Podcast Playback',
      androidNotificationChannelDescription: 'Podcast audio playback controls',
      androidNotificationIcon: 'mipmap/ic_launcher',
      androidShowNotificationBadge: true,
      // CRITICAL FIX: Keep foreground service running when paused for state sync
      androidStopForegroundOnPause: false,
      // Ongoing notification is automatic when foreground service is running
      androidNotificationOngoing: false, // Must be false when stopForegroundOnPause is false
      // Ensure compact action buttons are visible
      androidResumeOnClick: true,
    ),
  );

  debugPrint('🎵 AudioService initialized in main()');

  // Request notification permission on startup (Android 13+)
  // CRITICAL: This is required for system media controls to work properly
  if (Platform.isAndroid) {
    debugPrint('📱 Android detected: Requesting notification permission on startup...');
    final notificationStatus = await Permission.notification.status;
    debugPrint('📱 Current notification permission status: $notificationStatus');

    if (!notificationStatus.isGranted) {
      debugPrint('🔔 Requesting notification permission...');
      final result = await Permission.notification.request();
      debugPrint('🔔 Permission request result: $result');

      if (!result.isGranted) {
        debugPrint('⚠️ Notification permission DENIED - System media controls may NOT work!');
        debugPrint('⚠️ Please grant notification permission in system settings');
      } else {
        debugPrint('✅ Notification permission GRANTED - System media controls will work!');
      }
    } else {
      debugPrint('✅ Notification permission already granted');
    }
  } else {
    debugPrint('📱 Non-Android platform: Skipping notification permission check');
  }

  // Set system UI overlay style BEFORE any widget initialization
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.dark,
      systemNavigationBarColor: Colors.transparent,
      systemNavigationBarIconBrightness: Brightness.dark,
      systemNavigationBarDividerColor: Colors.transparent,
    ),
  );

  // Set preferred orientations early
  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
  ]);

  // Set system UI mode to edgeToEdge to prevent system background
  await SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);

  // Initialize services
  await ServiceLocator.init();

  // Initialize SharedPreferences for LocalStorageService
  final prefs = await SharedPreferences.getInstance();
  final storageService = LocalStorageServiceImpl(prefs);

  // Load Server Base URL (backend server address without /api/v1 suffix)
  final customServerUrl = await storageService.getServerBaseUrl();
  if (customServerUrl != null && customServerUrl.isNotEmpty) {
    AppConfig.setServerBaseUrl(customServerUrl);
    debugPrint('📥 [AppInit] Loaded server URL: $customServerUrl');
  }

  // For backward compatibility, also check old api_base_url
  final oldApiBaseUrl = await storageService.getApiBaseUrl();
  if (oldApiBaseUrl != null && oldApiBaseUrl.isNotEmpty) {
    // Migrate old api_base_url to new server_base_url
    await storageService.saveServerBaseUrl(oldApiBaseUrl);
    AppConfig.setServerBaseUrl(oldApiBaseUrl);
    debugPrint('🔄 [AppInit] Migrated old API URL to server URL: $oldApiBaseUrl');
  }

  // Run app with custom splash screen wrapper and providers
  runApp(
    ProviderScope(
      overrides: [
        localStorageServiceProvider.overrideWithValue(storageService),
      ],
      child: const _AppWithSplashScreen(),
    ),
  );
}

class _AppWithSplashScreen extends StatelessWidget {
  const _AppWithSplashScreen();

  @override
  Widget build(BuildContext context) {
    return const PersonalAIAssistantApp();
  }
}