import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:personal_ai_assistant/features/auth/presentation/providers/auth_provider.dart';
import 'package:personal_ai_assistant/features/splash/presentation/pages/splash_page.dart';

class _TestAuthNotifier extends AuthNotifier {
  _TestAuthNotifier(this._isAuthenticated);

  final bool _isAuthenticated;

  @override
  AuthState build() {
    return AuthState(isAuthenticated: _isAuthenticated);
  }
}

GoRouter _router() {
  return GoRouter(
    initialLocation: '/splash',
    routes: [
      GoRoute(path: '/splash', builder: (context, state) => const SplashPage()),
      GoRoute(
        path: '/home',
        builder: (context, state) => const Scaffold(body: Text('home')),
      ),
      GoRoute(
        path: '/login',
        builder: (context, state) => const Scaffold(body: Text('login')),
      ),
    ],
  );
}

Widget _app({required bool authenticated}) {
  return ProviderScope(
    overrides: [
      authProvider.overrideWith(() => _TestAuthNotifier(authenticated)),
    ],
    child: MaterialApp.router(routerConfig: _router()),
  );
}

void main() {
  testWidgets('SplashPage shows loader and redirects to login', (tester) async {
    await tester.pumpWidget(_app(authenticated: false));
    await tester.pump();

    expect(find.byType(CircularProgressIndicator), findsOneWidget);

    await tester.pumpAndSettle();
    expect(find.text('login'), findsOneWidget);
  });

  testWidgets('SplashPage shows loader and redirects to home', (tester) async {
    await tester.pumpWidget(_app(authenticated: true));
    await tester.pump();

    expect(find.byType(CircularProgressIndicator), findsOneWidget);

    await tester.pumpAndSettle();
    expect(find.text('home'), findsOneWidget);
  });
}
