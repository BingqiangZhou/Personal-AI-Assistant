import 'dart:async';
import 'dart:io' show Platform;

import 'package:audio_service/audio_service.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'core/app/app.dart';
import 'core/app/config/app_config.dart';
import 'core/constants/app_constants.dart' as core_constants;
import 'core/storage/local_storage_service.dart';
import 'core/theme/theme_provider.dart';
import 'core/utils/app_logger.dart' as logger;
import 'features/podcast/presentation/providers/audio_handler.dart';

late final PodcastAudioHandler audioHandler;

void main() {
  runZonedGuarded(
    () async {
      WidgetsFlutterBinding.ensureInitialized();
      if (kDebugMode) {
        logger.AppLogger.configure(const logger.AppLoggerConfig.debug());
      }

      FlutterError.onError = (details) {
        FlutterError.presentError(details);
        logger.AppLogger.error(
          '[FlutterError] ${details.exceptionAsString()}',
          stackTrace: details.stack,
        );
      };

      PlatformDispatcher.instance.onError = (error, stack) {
        logger.AppLogger.error(
          '[PlatformError] $error',
          error: error,
          stackTrace: stack,
        );
        return true;
      };

      final isMobile = Platform.isAndroid || Platform.isIOS;

      if (isMobile) {
        audioHandler = await AudioService.init(
          builder: PodcastAudioHandler.new,
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
        logger.AppLogger.info('AudioService initialized (mobile platform)');
      } else {
        audioHandler = PodcastAudioHandler();
        logger.AppLogger.info(
          'PodcastAudioHandler initialized (desktop platform)',
        );
      }

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
          await storageService.getString(
            core_constants.AppConstants.themeKey,
          ) ??
          kThemeModeSystem;

      final customServerUrl = await storageService.getServerBaseUrl();
      if (customServerUrl != null && customServerUrl.isNotEmpty) {
        AppConfig.setServerBaseUrl(customServerUrl);
        logger.AppLogger.info('[AppInit] Loaded server URL: $customServerUrl');
      }

      final oldApiBaseUrl = await storageService.getApiBaseUrl();
      if (oldApiBaseUrl != null && oldApiBaseUrl.isNotEmpty) {
        await storageService.saveServerBaseUrl(oldApiBaseUrl);
        AppConfig.setServerBaseUrl(oldApiBaseUrl);
        logger.AppLogger.info(
          '[AppInit] Migrated old API URL to server URL: $oldApiBaseUrl',
        );
      }

      runApp(
        ProviderScope(
          overrides: [
            localStorageServiceProvider.overrideWithValue(storageService),
            initialThemeModeCodeProvider.overrideWithValue(
              initialThemeModeCode,
            ),
          ],
          child: const _AppWithSplashScreen(),
        ),
      );
    },
    (error, stackTrace) {
      logger.AppLogger.error(
        '[ZoneError] $error',
        error: error,
        stackTrace: stackTrace,
      );
    },
  );
}

class _AppWithSplashScreen extends StatelessWidget {
  const _AppWithSplashScreen();

  @override
  Widget build(BuildContext context) {
    return const PersonalAIAssistantApp();
  }
}
