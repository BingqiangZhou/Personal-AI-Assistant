import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:go_router/go_router.dart';

import '../localization/locale_provider.dart';
import '../providers/route_provider.dart';
import '../router/app_router.dart';
import '../theme/app_theme.dart';
import '../theme/app_colors.dart';
import '../../features/auth/presentation/providers/auth_provider.dart';

/// Splash screen widget that matches the Mindriver brand style
class _SplashScreenWidget extends StatelessWidget {
  const _SplashScreenWidget();

  @override
  Widget build(BuildContext context) {
    final brightness = MediaQuery.platformBrightnessOf(context);
    final isDark = brightness == Brightness.dark;

    return Scaffold(
      body: Container(
        decoration: BoxDecoration(
          gradient: isDark
              ? AppColors.darkSubtleGradient
              : AppColors.softBackgroundGradient,
        ),
        child: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // App logo with shadow
              Container(
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(24),
                  boxShadow: [
                    BoxShadow(
                      color: isDark
                          ? AppColors.riverAccent.withValues(alpha: 0.3)
                          : AppColors.primary.withValues(alpha: 0.2),
                      blurRadius: 30,
                      offset: const Offset(0, 10),
                    ),
                  ],
                ),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(24),
                  child: Image.asset(
                    'assets/icons/appLogo.png',
                    width: 120,
                    height: 120,
                    fit: BoxFit.cover,
                  ),
                ),
              ),
              const SizedBox(height: 32),
              // App name
              Text(
                'Personal AI Assistant',
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.w600,
                  color: isDark
                      ? AppColors.darkTextPrimary
                      : AppColors.lightTextPrimary,
                  letterSpacing: -0.5,
                ),
              ),
              const SizedBox(height: 8),
              // Tagline
              Text(
                'Your intelligent companion',
                style: TextStyle(
                  fontSize: 14,
                  color: isDark
                      ? AppColors.darkTextSecondary
                      : AppColors.lightTextSecondary,
                ),
              ),
              const SizedBox(height: 48),
              // Loading indicator
              SizedBox(
                width: 32,
                height: 32,
                child: CircularProgressIndicator(
                  strokeWidth: 3,
                  valueColor: AlwaysStoppedAnimation<Color>(
                    isDark ? AppColors.riverAccent : AppColors.primary,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

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
    _setupRouteListener();
  }

  Future<void> _initializeApp() async {
    // Load saved locale from storage
    await ref.read(localeProvider.notifier).loadSavedLocale();

    // Check authentication status
    await ref.read(authProvider.notifier).checkAuthStatus();

    // Small delay to ensure the splash screen is visible
    await Future.delayed(const Duration(milliseconds: 600));

    if (mounted) {
      setState(() {
        _isInitialized = true;
      });
    }
  }

  void _setupRouteListener() {
    // Set initial route
    WidgetsBinding.instance.addPostFrameCallback((_) {
      // Update route after first frame is rendered
      if (mounted) {
        // Try to get current route from GoRouter
        try {
          final router = ref.read(appRouterProvider);
          final RouteMatchList matchList = router.routerDelegate.currentConfiguration;
          final uri = matchList.uri;
          ref.read(currentRouteProvider.notifier).setRoute(uri.toString());
        } catch (_) {
          // If getting route fails, just set to home
          ref.read(currentRouteProvider.notifier).setRoute('/');
        }
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    // Show splash screen while initializing
    if (!_isInitialized) {
      return MaterialApp(
        title: 'Personal AI Assistant',
        debugShowCheckedModeBanner: false,
        theme: AppTheme.lightTheme,
        darkTheme: AppTheme.darkTheme,
        themeMode: ThemeMode.system,
        home: const _SplashScreenWidget(),
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