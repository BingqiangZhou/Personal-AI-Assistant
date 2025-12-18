import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mockito/mockito.dart';
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
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Check for all form fields
      expect(find.text('First Name'), findsOneWidget);
      expect(find.text('Last Name'), findsOneWidget);
      expect(find.text('Email'), findsOneWidget);
      expect(find.text('Password'), findsOneWidget);
      expect(find.text('Confirm Password'), findsOneWidget);
      expect(find.text('Create Account'), findsOneWidget);
      expect(find.text('Already have an account?'), findsOneWidget);
      expect(find.text('Sign In'), findsOneWidget);
    });

    testWidgets('Should validate empty form fields', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
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
      expect(find.text('Required'), findsWidgets);
      expect(find.text('Please enter your email'), findsOneWidget);
      expect(find.text('Please enter your password'), findsOneWidget);
      expect(find.text('Please confirm your password'), findsOneWidget);
    });

    testWidgets('Should validate email format', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Fill name fields
      await tester.enterText(find.ancestor(
        of: find.text('First Name'),
        matching: find.byType(TextFormField),
      ), 'John');

      await tester.enterText(find.ancestor(
        of: find.text('Last Name'),
        matching: find.byType(TextFormField),
      ), 'Doe');

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
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Fill name and email
      await tester.enterText(find.ancestor(
        of: find.text('First Name'),
        matching: find.byType(TextFormField),
      ), 'John');

      await tester.enterText(find.ancestor(
        of: find.text('Last Name'),
        matching: find.byType(TextFormField),
      ), 'Doe');

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

      expect(find.text('Password must contain uppercase letter'), findsOneWidget);

      // Test password without number
      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      ), 'Password');

      await tester.tap(find.text('Create Account'));
      await tester.pump();

      expect(find.text('Password must contain number'), findsOneWidget);
    });

    testWidgets('Should validate password confirmation', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Fill all fields with valid data except mismatched password
      await tester.enterText(find.ancestor(
        of: find.text('First Name'),
        matching: find.byType(TextFormField),
      ), 'John');

      await tester.enterText(find.ancestor(
        of: find.text('Last Name'),
        matching: find.byType(TextFormField),
      ), 'Doe');

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
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Fill all valid fields
      await tester.enterText(find.ancestor(
        of: find.text('First Name'),
        matching: find.byType(TextFormField),
      ), 'John');

      await tester.enterText(find.ancestor(
        of: find.text('Last Name'),
        matching: find.byType(TextFormField),
      ), 'Doe');

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

      expect(find.text('Please agree to the terms and conditions'), findsOneWidget);
    });

    testWidgets('Should toggle password visibility', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith((ref) => mockAuthNotifier),
          ],
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Find password fields
      final passwordField = find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      ).first;

      final confirmPasswordField = find.ancestor(
        of: find.text('Confirm Password'),
        matching: find.byType(TextFormField),
      ).first;

      // Initially obscured
      expect(tester.widget<TextFormField>(passwordField).obscureText, isTrue);
      expect(tester.widget<TextFormField>(confirmPasswordField).obscureText, isTrue);

      // Toggle password visibility
      await tester.tap(find.byIcon(Icons.visibility_off).first);
      await tester.pump();

      expect(tester.widget<TextFormField>(passwordField).obscureText, isFalse);

      // Toggle back
      await tester.tap(find.byIcon(Icons.visibility).first);
      await tester.pump();

      expect(tester.widget<TextFormField>(passwordField).obscureText, isTrue);
    });
  });
}