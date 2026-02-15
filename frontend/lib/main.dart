import 'dart:async';
import 'dart:ui';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter/services.dart';
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
late PodcastAudioHandler audioHandler;

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  FlutterError.onError = (details) {
    FlutterError.presentError(details);
    debugPrint('❌ [FlutterError] ${details.exceptionAsString()}');
  };

  PlatformDispatcher.instance.onError = (error, stack) {
    debugPrint('❌ [PlatformError] $error');
    return true;
  };

  runZonedGuarded(() async {
    audioHandler = PodcastAudioHandler();

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
