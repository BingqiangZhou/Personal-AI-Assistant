import 'dart:async';
import 'dart:io' show Platform;
import 'dart:ui';

import 'package:audio_service/audio_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter/services.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'core/app/app.dart';
import 'core/app/config/app_config.dart';
import 'core/constants/app_constants.dart' as core_constants;
import 'core/storage/local_storage_service.dart';
import 'core/theme/theme_provider.dart';
import 'features/podcast/presentation/providers/audio_handler.dart';

// Global AudioHandler instance (initialized once in main)
// On mobile: AudioHandler from AudioService
// On desktop: Direct PodcastAudioHandler instance
late final PodcastAudioHandler audioHandler;

void main() {
  // CRITICAL: Everything must run inside the same zone.
  // ensureInitialized(), AudioService.init(), and runApp() must share a zone,
  // otherwise Flutter throws a zone mismatch assertion and stream callbacks
  // across zone boundaries break audio playback state updates.
  runZonedGuarded(() async {
    WidgetsFlutterBinding.ensureInitialized();

    FlutterError.onError = (details) {
      FlutterError.presentError(details);
      debugPrint('❌ [FlutterError] ${details.exceptionAsString()}');
    };

    PlatformDispatcher.instance.onError = (error, stack) {
      debugPrint('❌ [PlatformError] $error');
      return true;
    };

    // CRITICAL: Initialize audio handler BEFORE runApp.
    // AudioService.init() must complete before any widget can subscribe to
    // the handler's streams, otherwise a race condition causes dead subscriptions.
    final isMobile = Platform.isAndroid || Platform.isIOS;

    if (isMobile) {
      audioHandler = await AudioService.init(
        builder: () => PodcastAudioHandler(),
        config: const AudioServiceConfig(
          androidNotificationChannelId: 'com.personal_ai_assistant.audio',
          androidNotificationChannelName: 'Podcast Playback',
          androidNotificationChannelDescription:
              'Podcast audio playback controls',
          androidNotificationIcon: 'mipmap/ic_launcher',
          androidShowNotificationBadge: true,
          androidStopForegroundOnPause: false,
          androidResumeOnClick: true,
        ),
      );
      debugPrint('🎵 AudioService initialized (mobile platform)');
    } else {
      audioHandler = PodcastAudioHandler();
      debugPrint('🎵 PodcastAudioHandler initialized (desktop platform)');
    }

    // Request notification permission on Android 13+ (required for foreground service)
    if (Platform.isAndroid) {
      final notificationStatus = await Permission.notification.status;
      if (!notificationStatus.isGranted) {
        await Permission.notification.request();
      }
    }

    SystemChrome.setSystemUIOverlayStyle(
      const SystemUiOverlayStyle(
        statusBarColor: Colors.transparent,
        statusBarIconBrightness: Brightness.dark,
        systemNavigationBarColor: Colors.transparent,
        systemNavigationBarIconBrightness: Brightness.dark,
        systemNavigationBarDividerColor: Colors.transparent,
      ),
    );

    SystemChrome.setPreferredOrientations([
      DeviceOrientation.portraitUp,
      DeviceOrientation.portraitDown,
    ]);

    SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);

    final prefs = await SharedPreferences.getInstance();
    final storageService = LocalStorageServiceImpl(prefs);

    final initialThemeModeCode =
        await storageService.getString(core_constants.AppConstants.themeKey) ??
        kThemeModeSystem;

    final customServerUrl = await storageService.getServerBaseUrl();
    if (customServerUrl != null && customServerUrl.isNotEmpty) {
      AppConfig.setServerBaseUrl(customServerUrl);
      debugPrint('📥 [AppInit] Loaded server URL: $customServerUrl');
    }

    final oldApiBaseUrl = await storageService.getApiBaseUrl();
    if (oldApiBaseUrl != null && oldApiBaseUrl.isNotEmpty) {
      await storageService.saveServerBaseUrl(oldApiBaseUrl);
      AppConfig.setServerBaseUrl(oldApiBaseUrl);
      debugPrint(
        '🔄 [AppInit] Migrated old API URL to server URL: $oldApiBaseUrl',
      );
    }

    runApp(
      ProviderScope(
        overrides: [
          localStorageServiceProvider.overrideWithValue(storageService),
          initialThemeModeCodeProvider.overrideWithValue(initialThemeModeCode),
        ],
        child: const _AppWithSplashScreen(),
      ),
    );
  }, (error, stackTrace) {
    debugPrint('❌ [ZoneError] $error');
  });
}

class _AppWithSplashScreen extends StatelessWidget {
  const _AppWithSplashScreen();

  @override
  Widget build(BuildContext context) {
    return const PersonalAIAssistantApp();
  }
}
