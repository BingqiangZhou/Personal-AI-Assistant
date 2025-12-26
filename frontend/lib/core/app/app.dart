import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';

import '../localization/locale_provider.dart';
import '../router/app_router.dart';
import '../theme/app_theme.dart';
import '../widgets/loading_page.dart';

class PersonalAIAssistantApp extends ConsumerStatefulWidget {
  const PersonalAIAssistantApp({super.key});

  @override
  ConsumerState<PersonalAIAssistantApp> createState() => _PersonalAIAssistantAppState();
}

class _PersonalAIAssistantAppState extends ConsumerState<PersonalAIAssistantApp> {
  bool _isInitialized = false;

  @override
  void initState() {
    super.initState();
    _initializeApp();
  }

  Future<void> _initializeApp() async {
    // Load saved locale from storage
    await ref.read(localeProvider.notifier).loadSavedLocale();

    // Simulate app initialization time - longer to prevent any flash
    await Future.delayed(const Duration(milliseconds: 1200));

    if (mounted) {
      setState(() {
        _isInitialized = true;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    // Show loading page while initializing
    if (!_isInitialized) {
      return MaterialApp(
        title: 'Personal AI Assistant',
        debugShowCheckedModeBanner: false,
        theme: AppTheme.lightTheme,
        darkTheme: AppTheme.darkTheme,
        themeMode: ThemeMode.system,
        home: const LoadingPage(),
      );
    }

    // Show main app after initialization
    return MaterialApp.router(
      title: 'Personal AI Assistant',
      debugShowCheckedModeBanner: false,

      // Theme configuration
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: ThemeMode.system,

      // Router configuration
      routerConfig: ref.watch(appRouterProvider),

      // Localization
      locale: ref.watch(localeProvider),
      localizationsDelegates: const [
        AppLocalizations.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      supportedLocales: const [
        Locale('en'),
        Locale('zh'),
      ],

      // Simple builder without flash prevention
      builder: (context, child) {
        return MediaQuery.withClampedTextScaling(
          minScaleFactor: 0.8,
          maxScaleFactor: 1.2,
          child: child!,
        );
      },
    );
  }
}