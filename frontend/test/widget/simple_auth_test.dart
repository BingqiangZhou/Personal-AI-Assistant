import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/auth/presentation/pages/login_page.dart';
import 'package:personal_ai_assistant/features/auth/presentation/pages/register_page.dart';

GoRouter _router(String initialLocation) {
  return GoRouter(
    initialLocation: initialLocation,
    routes: [
      GoRoute(path: '/login', builder: (context, state) => const LoginPage()),
      GoRoute(
        path: '/register',
        builder: (context, state) => const RegisterPage(),
      ),
    ],
  );
}

Widget _app(GoRouter router) {
  return ProviderScope(
    child: MaterialApp.router(
      routerConfig: router,
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      locale: const Locale('en'),
    ),
  );
}

Future<void> _tap(WidgetTester tester, Finder finder) async {
  await tester.ensureVisible(finder);
  await tester.pumpAndSettle();
  await tester.tap(finder, warnIfMissed: false);
  await tester.pump();
}

Future<void> _drainTopNotices(WidgetTester tester) async {
  await tester.pump(const Duration(seconds: 4));
}

void main() {
  group('Auth Simple Tests', () {
    testWidgets('Register and Login pages should render', (tester) async {
      await tester.pumpWidget(_app(_router('/register')));
      await tester.pumpAndSettle();

      expect(find.text('Create Account'), findsWidgets);
      expect(find.text('Full Name'), findsOneWidget);
      expect(find.text('Email'), findsOneWidget);
      expect(find.text('Password'), findsWidgets);
      expect(find.text('Confirm Password'), findsOneWidget);
      expect(find.text('Already have an account?'), findsOneWidget);
      expect(find.text('Sign In'), findsOneWidget);

      await tester.pumpWidget(_app(_router('/login')));
      await tester.pumpAndSettle();

      expect(find.text("Dawn's near. Let's begin."), findsOneWidget);
      expect(find.text('Sign in to continue'), findsOneWidget);
      expect(find.text('Email'), findsOneWidget);
      expect(find.text('Password'), findsOneWidget);
      expect(find.text('Remember me'), findsOneWidget);
      expect(find.text('Forgot Password?'), findsOneWidget);
      expect(find.text('Sign In'), findsWidgets);
      expect(find.text("Don't have an account?"), findsOneWidget);
      expect(find.text('Sign Up'), findsOneWidget);
    });

    testWidgets('Should navigate between login and register', (tester) async {
      await tester.pumpWidget(_app(_router('/login')));
      await tester.pumpAndSettle();

      expect(find.text("Dawn's near. Let's begin."), findsOneWidget);

      await _tap(tester, find.text('Sign Up'));
      await tester.pumpAndSettle();

      expect(find.text('Create Account'), findsWidgets);

      await _tap(tester, find.text('Sign In'));
      await tester.pumpAndSettle();

      expect(find.text("Dawn's near. Let's begin."), findsOneWidget);
    });

    testWidgets('Should toggle password visibility icons', (tester) async {
      await tester.pumpWidget(_app(_router('/login')));
      await tester.pumpAndSettle();

      expect(find.byIcon(Icons.visibility_off), findsOneWidget);
      expect(find.byIcon(Icons.visibility), findsNothing);

      await tester.tap(find.byIcon(Icons.visibility_off));
      await tester.pump();

      expect(find.byIcon(Icons.visibility), findsOneWidget);
      expect(find.byIcon(Icons.visibility_off), findsNothing);
    });

    testWidgets('Should handle remember me checkbox', (tester) async {
      await tester.pumpWidget(_app(_router('/login')));
      await tester.pumpAndSettle();

      final checkbox = find.byType(Checkbox);
      expect(tester.widget<Checkbox>(checkbox).value, isFalse);

      await _tap(tester, checkbox);

      expect(tester.widget<Checkbox>(checkbox).value, isTrue);
    });

    testWidgets('Should show validation errors on register form', (tester) async {
      await tester.pumpWidget(_app(_router('/register')));
      await tester.pumpAndSettle();

      await _tap(tester, find.byType(Checkbox).at(1));
      await _tap(tester, find.byKey(const Key('register_button')));

      expect(find.text('Please enter your name'), findsOneWidget);
      expect(find.text('Please enter your email'), findsOneWidget);
      expect(find.text('Please enter your password'), findsNWidgets(2));
    });

    testWidgets('Should show validation errors on login form', (tester) async {
      await tester.pumpWidget(_app(_router('/login')));
      await tester.pumpAndSettle();

      await _tap(tester, find.byKey(const Key('login_button')));

      expect(find.text('Please enter your email'), findsOneWidget);
      expect(find.text('Please enter your password'), findsOneWidget);
    });

    testWidgets('Should validate email format', (tester) async {
      await tester.pumpWidget(_app(_router('/register')));
      await tester.pumpAndSettle();

      final fields = find.byType(TextFormField);

      await tester.enterText(fields.at(0), 'Test User');
      await tester.enterText(fields.at(1), 'invalid-email');
      await _tap(tester, find.byType(Checkbox).at(1));
      await _tap(tester, find.byKey(const Key('register_button')));

      expect(find.text('Please enter a valid email'), findsOneWidget);
    });

    testWidgets('Should validate password requirements', (tester) async {
      await tester.pumpWidget(_app(_router('/register')));
      await tester.pumpAndSettle();

      final fields = find.byType(TextFormField);

      await tester.enterText(fields.at(0), 'Test User');
      await tester.enterText(fields.at(1), 'test@example.com');
      await _tap(tester, find.byType(Checkbox).at(1));

      await tester.enterText(fields.at(2), 'weak');
      await tester.enterText(fields.at(3), 'weak');
      await _tap(tester, find.byKey(const Key('register_button')));

      await tester.enterText(fields.at(2), 'password123');
      await tester.enterText(fields.at(3), 'password123');
      await _tap(tester, find.byKey(const Key('register_button')));
      expect(find.text('Contain at least one uppercase letter'), findsOneWidget);

      await tester.enterText(fields.at(2), 'PASSWORD123');
      await tester.enterText(fields.at(3), 'PASSWORD123');
      await _tap(tester, find.byKey(const Key('register_button')));
      expect(find.text('Contain at least one lowercase letter'), findsOneWidget);

      await tester.enterText(fields.at(2), 'Password');
      await tester.enterText(fields.at(3), 'Password');
      await _tap(tester, find.byKey(const Key('register_button')));
      expect(find.text('Contain at least one number'), findsOneWidget);
    });

    testWidgets('Should validate password confirmation', (tester) async {
      await tester.pumpWidget(_app(_router('/register')));
      await tester.pumpAndSettle();

      final fields = find.byType(TextFormField);

      await tester.enterText(fields.at(0), 'Test User');
      await tester.enterText(fields.at(1), 'test@example.com');
      await tester.enterText(fields.at(2), 'Password123');
      await tester.enterText(fields.at(3), 'DifferentPassword');

      await _tap(tester, find.byKey(const Key('register_button')));

      expect(find.text('Passwords do not match'), findsOneWidget);

      await tester.enterText(fields.at(3), 'Password123');
      await _tap(tester, find.byKey(const Key('register_button')));

      expect(find.text('Passwords do not match'), findsNothing);
      await _drainTopNotices(tester);
    });

    testWidgets('Should show terms agreement error', (tester) async {
      await tester.pumpWidget(_app(_router('/register')));
      await tester.pumpAndSettle();

      final fields = find.byType(TextFormField);

      await tester.enterText(fields.at(0), 'Test User');
      await tester.enterText(fields.at(1), 'test@example.com');
      await tester.enterText(fields.at(2), 'Password123');
      await tester.enterText(fields.at(3), 'Password123');

      await _tap(tester, find.byKey(const Key('register_button')));

      expect(find.text('I agree to the Terms and Conditions'), findsOneWidget);
      await _drainTopNotices(tester);
    });
  });
}
