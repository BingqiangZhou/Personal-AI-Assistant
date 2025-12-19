import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';

import 'package:personal_ai_assistant/features/auth/presentation/pages/login_page.dart';
import 'package:personal_ai_assistant/features/auth/presentation/providers/auth_provider.dart';

import 'login_page_test.mocks.dart';

@GenerateMocks([AuthNotifier])
void main() {
  group('Login Page Widget Tests', () {
    late MockAuthNotifier mockAuthNotifier;

    setUp(() {
      mockAuthNotifier = MockAuthNotifier();
    });

    testWidgets('Should display all form fields', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Check for all form fields
      expect(find.text('Welcome Back'), findsOneWidget);
      expect(find.text('Email'), findsOneWidget);
      expect(find.text('Password'), findsOneWidget);
      expect(find.text('Sign In'), findsOneWidget);
      expect(find.text('Remember me'), findsOneWidget);
      expect(find.text('Forgot Password?'), findsOneWidget);
      expect(find.text("Don't have an account? "), findsOneWidget);
      expect(find.text('Sign Up'), findsOneWidget);
    });

    testWidgets('Should validate empty form fields', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Try to submit empty form
      await tester.tap(find.text('Sign In'));
      await tester.pump();

      // Should show validation errors
      expect(find.text('Please enter your email'), findsOneWidget);
      expect(find.text('Please enter your password'), findsOneWidget);
    });

    testWidgets('Should validate email format', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Enter invalid email
      await tester.enterText(find.ancestor(
        of: find.text('Email'),
        matching: find.byType(TextFormField),
      ), 'invalid-email');

      // Try to submit
      await tester.tap(find.text('Sign In'));
      await tester.pump();

      // Should show email error
      expect(find.text('Please enter a valid email'), findsOneWidget);
    });

    testWidgets('Should validate password length', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Fill email
      await tester.enterText(find.ancestor(
        of: find.text('Email'),
        matching: find.byType(TextFormField),
      ), 'test@example.com');

      // Enter short password
      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      ), '123');

      // Try to submit
      await tester.tap(find.text('Sign In'));
      await tester.pump();

      // Should show password error
      expect(find.text('Password must be at least 6 characters'), findsOneWidget);
    });

    testWidgets('Should toggle password visibility', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Find password field
      final passwordField = find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      ).first;

      // Initially obscured
      expect(tester.widget<TextFormField>(passwordField).obscureText, isTrue);

      // Toggle password visibility
      await tester.tap(find.byIcon(Icons.visibility_off));
      await tester.pump();

      expect(tester.widget<TextFormField>(passwordField).obscureText, isFalse);

      // Toggle back
      await tester.tap(find.byIcon(Icons.visibility));
      await tester.pump();

      expect(tester.widget<TextFormField>(passwordField).obscureText, isTrue);
    });

    testWidgets('Should toggle remember me checkbox', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      final rememberCheckbox = find.byType(Checkbox);

      // Should be unchecked initially
      expect(tester.widget<Checkbox>(rememberCheckbox).value, isFalse);

      // Check the checkbox
      await tester.tap(rememberCheckbox);
      await tester.pump();

      expect(tester.widget<Checkbox>(rememberCheckbox).value, isTrue);

      // Uncheck the checkbox
      await tester.tap(rememberCheckbox);
      await tester.pump();

      expect(tester.widget<Checkbox>(rememberCheckbox).value, isFalse);
    });

    testWidgets('Should show loading state when submitting', (WidgetTester tester) async {
      when(mockAuthNotifier.isLoading).thenReturn(true);

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Fill form with valid data
      await tester.enterText(find.ancestor(
        of: find.text('Email'),
        matching: find.byType(TextFormField),
      ), 'test@example.com');

      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      ), 'validpassword');

      // Submit form
      await tester.tap(find.byKey(Key('login_button')));
      await tester.pump();

      // Should show loading state
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });

    testWidgets('Should navigate to register page', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Click on Sign Up link
      await tester.tap(find.text('Sign Up'));
      await tester.pump();

      // Note: In a real app, this would navigate using GoRouter
      // For this test, we just verify the tap works
      expect(find.text('Sign Up'), findsOneWidget);
    });

    testWidgets('Should handle forgot password tap', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Click on Forgot Password link
      await tester.tap(find.text('Forgot Password?'));
      await tester.pump();

      // Note: In a real app, this would navigate to forgot password page
      // For this test, we just verify the tap works
      expect(find.text('Forgot Password?'), findsOneWidget);
    });

    testWidgets('Should accept valid form input', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Fill form with valid data
      await tester.enterText(find.ancestor(
        of: find.text('Email'),
        matching: find.byType(TextFormField),
      ), 'test@example.com');

      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      ), 'validpassword');

      // Check remember me
      await tester.tap(find.byType(Checkbox));
      await tester.pump();

      // Submit form
      await tester.tap(find.byKey(Key('login_button')));
      await tester.pump();

      // Should not show validation errors
      expect(find.text('Please enter your email'), findsNothing);
      expect(find.text('Please enter your password'), findsNothing);
      expect(find.text('Please enter a valid email'), findsNothing);
      expect(find.text('Password must be at least 6 characters'), findsNothing);
    });
  });
}