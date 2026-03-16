import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';

/// Creates a test-friendly MaterialApp with required localizations.
///
/// Use this for widget tests that need localization support.
/// For tests that need routing, use [testAppWithRouter] instead.
Widget testApp({
  required Widget child,
  Locale locale = const Locale('en'),
}) {
  return ProviderScope(
    child: MaterialApp(
      home: child,
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      locale: locale,
    ),
  );
}

/// Creates a test-friendly MaterialApp.router with required localizations.
///
/// Use this for widget tests that need routing support.
Widget testAppWithRouter({
  required GoRouter router,
  Locale locale = const Locale('en'),
}) {
  return ProviderScope(
    child: MaterialApp.router(
      routerConfig: router,
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      locale: locale,
    ),
  );
}

/// Creates a simple GoRouter with the given routes.
///
/// This is a convenience method for tests that need navigation.
GoRouter createTestRouter(List<RouteBase> routes, {String initialLocation = '/'}) {
  return GoRouter(
    initialLocation: initialLocation,
    routes: routes,
  );
}

/// Helper to tap a widget and wait for it to settle.
Future<void> tapAndSettle(WidgetTester tester, Finder finder) async {
  await tester.pumpAndSettle();
  await tester.tap(finder, warnIfMissed: false);
  await tester.pump();
}

/// Helper to enter text and wait for it to settle.
Future<void> enterTextAndSettle(
  WidgetTester tester,
  Finder finder,
  String text,
) async {
  await tester.pumpAndSettle();
  await tester.enterText(finder, text);
  await tester.pump();
}

/// Helper to drain top floating notices (they auto-dismiss after 3 seconds).
Future<void> drainTopNotices(WidgetTester tester) async {
  await tester.pump(const Duration(seconds: 4));
}
