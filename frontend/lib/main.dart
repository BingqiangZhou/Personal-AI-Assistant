import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'core/app/app.dart';
import 'core/localization/locale_provider.dart';
import 'core/services/service_locator.dart';
import 'core/storage/local_storage_service.dart';

void main() async {
  // Ensure Flutter binding is initialized
  WidgetsFlutterBinding.ensureInitialized();

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