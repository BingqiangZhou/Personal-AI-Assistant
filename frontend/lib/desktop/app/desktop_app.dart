import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/constants/app_constants.dart';
import '../../shared/themes/app_theme.dart';
import 'routes/app_router.dart';
import '../widgets/layouts/desktop_layout.dart';
import '../widgets/components/desktop_menu_bar.dart';
import '../widgets/components/desktop_side_navigation.dart';

class DesktopApp extends ConsumerWidget {
  const DesktopApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final router = ref.watch(appRouterProvider);
    final screenWidth = MediaQuery.of(context).size.width;

    return MaterialApp.router(
      title: '${AppConstants.appName} Desktop',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.desktopLightTheme,
      darkTheme: AppTheme.desktopDarkTheme,
      themeMode: ThemeMode.system,
      routerConfig: router,
      builder: (context, child) {
        return DesktopLayout(
          child: child!,
          screenWidth: screenWidth,
        );
      },
    );
  }
}

class DesktopScaffold extends ConsumerWidget {
  const DesktopScaffold({
    super.key,
    required this.body,
    this.title,
    this.actions,
    this.floatingActionButton,
    this.showSideNavigation = true,
  });

  final Widget body;
  final String? title;
  final List<Widget>? actions;
  final Widget? floatingActionButton;
  final bool showSideNavigation;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final screenWidth = MediaQuery.of(context).size.width;

    return Scaffold(
      appBar: screenWidth > 800 ? DesktopMenuBar(
        title: title,
        actions: actions,
      ) : null,
      body: Row(
        children: [
          // Side Navigation for wider screens
          if (showSideNavigation && screenWidth > 1200)
            const DesktopSideNavigation(width: 280),

          // Main content area
          Expanded(
            child: body,
          ),
        ],
      ),
      floatingActionButton: floatingActionButton,
    );
  }
}