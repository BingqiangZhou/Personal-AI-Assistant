import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mockito/annotations.dart';

import 'package:personal_ai_assistant/features/auth/presentation/pages/register_page.dart';
import 'package:personal_ai_assistant/features/auth/presentation/providers/auth_provider.dart';

import 'register_page_test.mocks.dart';

@GenerateMocks([AuthNotifier])
void main() {
  group('Register Page Widget Tests', () {
    late MockAuthNotifier mockAuthNotifier;

    setUp(() {
      mockAuthNotifier = MockAuthNotifier();
    });

    testWidgets('Should display all form fields', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith(() => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Check for all form fields
      expect(find.text('用户名 (可选)'), findsOneWidget);
      expect(find.text('Email'), findsOneWidget);
      expect(find.text('Password'), findsOneWidget);
      expect(find.text('Confirm Password'), findsOneWidget);
      expect(find.text('Create Account'), findsOneWidget);
      expect(find.text('Already have an account?'), findsOneWidget);
      expect(find.text('Sign In'), findsOneWidget);
      expect(find.text('Password Requirements:'), findsOneWidget);
    });

    testWidgets('Should validate empty form fields', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith(() => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Try to submit empty form
      await tester.tap(find.text('Create Account'));
      await tester.pump();

      // Should show validation errors
      expect(find.text('Please enter your email'), findsOneWidget);
      expect(find.text('Please enter your password'), findsOneWidget);
      expect(find.text('Please confirm your password'), findsOneWidget);
    });

    testWidgets('Should validate email format', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith(() => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Fill username field (optional)
      await tester.enterText(find.ancestor(
        of: find.text('用户名 (可选)'),
        matching: find.byType(TextFormField),
      ), 'johndoe');

      // Enter invalid email
      await tester.enterText(find.ancestor(
        of: find.text('Email'),
        matching: find.byType(TextFormField),
      ), 'invalid-email');

      // Try to submit
      await tester.tap(find.text('Create Account'));
      await tester.pump();

      // Should show email error
      expect(find.text('Please enter a valid email'), findsOneWidget);
    });

    testWidgets('Should validate password requirements', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith(() => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Fill username and email
      await tester.enterText(find.ancestor(
        of: find.text('用户名 (可选)'),
        matching: find.byType(TextFormField),
      ), 'johndoe');

      await tester.enterText(find.ancestor(
        of: find.text('Email'),
        matching: find.byType(TextFormField),
      ), 'john@example.com');

      // Test weak password
      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      ), 'weak');

      await tester.tap(find.text('Create Account'));
      await tester.pump();

      expect(find.text('Password must be at least 8 characters'), findsOneWidget);

      // Test password without uppercase
      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      ), 'password123');

      await tester.tap(find.text('Create Account'));
      await tester.pump();

      expect(find.text('Password must contain at least one uppercase letter (A-Z)'), findsOneWidget);

      // Test password without lowercase
      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      ), 'PASSWORD123');

      await tester.tap(find.text('Create Account'));
      await tester.pump();

      expect(find.text('Password must contain at least one lowercase letter (a-z)'), findsOneWidget);

      // Test password without number
      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      ), 'Password');

      await tester.tap(find.text('Create Account'));
      await tester.pump();

      expect(find.text('Password must contain at least one number (0-9)'), findsOneWidget);
    });

    testWidgets('Should validate password confirmation', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith(() => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Fill all fields with valid data except mismatched password
      await tester.enterText(find.ancestor(
        of: find.text('用户名 (可选)'),
        matching: find.byType(TextFormField),
      ), 'johndoe');

      await tester.enterText(find.ancestor(
        of: find.text('Email'),
        matching: find.byType(TextFormField),
      ), 'john@example.com');

      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      ), 'Password123');

      await tester.enterText(find.ancestor(
        of: find.text('Confirm Password'),
        matching: find.byType(TextFormField),
      ), 'DifferentPassword');

      await tester.tap(find.text('Create Account'));
      await tester.pump();

      expect(find.text('Passwords do not match'), findsOneWidget);
    });

    testWidgets('Should show terms agreement error', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith(() => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Fill all valid fields
      await tester.enterText(find.ancestor(
        of: find.text('用户名 (可选)'),
        matching: find.byType(TextFormField),
      ), 'johndoe');

      await tester.enterText(find.ancestor(
        of: find.text('Email'),
        matching: find.byType(TextFormField),
      ), 'john@example.com');

      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      ), 'Password123');

      await tester.enterText(find.ancestor(
        of: find.text('Confirm Password'),
        matching: find.byType(TextFormField),
      ), 'Password123');

      // Don't check terms checkbox and try to submit
      await tester.tap(find.text('Create Account'));
      await tester.pump();

      // Should show snackbar
      expect(find.text('Please agree to the terms and conditions'), findsOneWidget);
    });

    testWidgets('Should toggle password visibility', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith(() => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Find password visibility toggle button - it should show icons for toggle
      // Initial state should show visibility_off icons (password is obscured)
      expect(find.byIcon(Icons.visibility_off), findsWidgets);

      // Toggle password visibility
      final firstToggle = find.byIcon(Icons.visibility_off).first;
      await tester.tap(firstToggle);
      await tester.pump();

      // After toggle, should see visibility icon
      expect(find.byIcon(Icons.visibility), findsWidgets);
    });

    testWidgets('Should display password requirements', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith(() => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Check password requirements are displayed
      expect(find.text('Password Requirements:'), findsOneWidget);
      expect(find.text('At least 8 characters'), findsOneWidget);
      expect(find.text('One uppercase letter (A-Z)'), findsOneWidget);
      expect(find.text('One lowercase letter (a-z)'), findsOneWidget);
      expect(find.text('One number (0-9)'), findsOneWidget);
    });
  });
}