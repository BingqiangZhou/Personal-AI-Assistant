import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import 'package:personal_ai_assistant/core/app/app.dart';
import 'package:personal_ai_assistant/features/auth/presentation/pages/login_page.dart';
import 'package:personal_ai_assistant/features/auth/presentation/pages/register_page.dart';
import 'package:personal_ai_assistant/features/splash/presentation/pages/splash_page.dart';

void main() {
  group('Authentication Flow Tests', () {
    late ProviderContainer container;

    setUp(() {
      container = ProviderContainer();
    });

    tearDown(() {
      container.dispose();
    });

    testWidgets('App should start with splash page', (WidgetTester tester) async {
      // Build our app and trigger a frame
      await tester.pumpWidget(
        ProviderScope(
          child: const PersonalAIAssistantApp(),
        ),
      );

      // Verify that we start with splash page
      expect(find.byType(SplashPage), findsOneWidget);

      // Wait for splash animation
      await tester.pumpAndSettle(Duration(seconds: 2));

      // Should redirect to login (not authenticated)
      expect(find.byType(LoginPage), findsOneWidget);
    });

    testWidgets('Registration form validation', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Find all form fields
      final usernameField = find.ancestor(
        of: find.text('用户名 (可选)'),
        matching: find.byType(TextFormField),
      );
      final emailField = find.ancestor(
        of: find.text('Email'),
        matching: find.byType(TextFormField),
      );
      final passwordField = find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      );
      final confirmPasswordField = find.ancestor(
        of: find.text('Confirm Password'),
        matching: find.byType(TextFormField),
      );
      final registerButton = find.text('Create Account');

      // Test empty fields
      await tester.tap(registerButton);
      await tester.pump();

      // Should show validation errors
      expect(find.text('Please enter your email'), findsOneWidget);
      expect(find.text('Please enter your password'), findsOneWidget);
      expect(find.text('Please confirm your password'), findsOneWidget);

      // Test invalid email
      await tester.enterText(emailField, 'invalid-email');
      await tester.tap(registerButton);
      await tester.pump();
      expect(find.text('Please enter a valid email'), findsOneWidget);

      // Test weak password
      await tester.enterText(emailField, 'test@example.com');
      await tester.enterText(usernameField, 'testuser');
      await tester.enterText(passwordField, 'weak');
      await tester.tap(registerButton);
      await tester.pump();
      expect(find.text('Password must be at least 8 characters'), findsOneWidget);

      // Test password without uppercase
      await tester.enterText(passwordField, 'password123');
      await tester.tap(registerButton);
      await tester.pump();
      expect(find.text('Password must contain at least one uppercase letter (A-Z)'), findsOneWidget);

      // Test password without lowercase
      await tester.enterText(passwordField, 'PASSWORD123');
      await tester.tap(registerButton);
      await tester.pump();
      expect(find.text('Password must contain at least one lowercase letter (a-z)'), findsOneWidget);

      // Test password without number
      await tester.enterText(passwordField, 'Password');
      await tester.tap(registerButton);
      await tester.pump();
      expect(find.text('Password must contain at least one number (0-9)'), findsOneWidget);

      // Test password mismatch
      await tester.enterText(passwordField, 'Password123');
      await tester.enterText(confirmPasswordField, 'DifferentPassword');
      await tester.tap(registerButton);
      await tester.pump();
      expect(find.text('Passwords do not match'), findsOneWidget);

      // Test valid form (but don't submit)
      await tester.enterText(confirmPasswordField, 'Password123');
      await tester.pump();
      // Check that validation errors are cleared
      expect(find.text('Passwords do not match'), findsNothing);
    });

    testWidgets('Login form validation', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Find form fields
      final emailField = find.ancestor(
        of: find.text('Email'),
        matching: find.byType(TextFormField),
      );
      final passwordField = find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      );
      final loginButton = find.text('Sign In');

      // Test empty fields
      await tester.tap(loginButton);
      await tester.pump();

      expect(find.text('Please enter your email'), findsOneWidget);
      expect(find.text('Please enter your password'), findsOneWidget);

      // Test invalid email
      await tester.enterText(emailField, 'invalid-email');
      await tester.tap(loginButton);
      await tester.pump();
      expect(find.text('Please enter a valid email'), findsOneWidget);

      // Test short password
      await tester.enterText(emailField, 'test@example.com');
      await tester.enterText(passwordField, '123');
      await tester.tap(loginButton);
      await tester.pump();
      expect(find.text('Password must be at least 6 characters'), findsOneWidget);

      // Test valid form
      await tester.enterText(passwordField, 'validpassword');
      await tester.pump();
      expect(find.text('Password must be at least 6 characters'), findsNothing);
    });

    testWidgets('Navigation between login and register', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Click on Sign Up link
      await tester.tap(find.text('Sign Up'));
      await tester.pumpAndSettle();

      // Should be on register page
      expect(find.byType(RegisterPage), findsOneWidget);
      expect(find.text('Create Account'), findsOneWidget);

      // Click on Sign In link
      await tester.tap(find.text('Sign In'));
      await tester.pumpAndSettle();

      // Should be back on login page
      expect(find.byType(LoginPage), findsOneWidget);
      expect(find.text('Welcome Back'), findsOneWidget);
    });

    testWidgets('Password visibility toggle', (WidgetTester tester) async {
      // Test on login page
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      final toggleButton = find.byIcon(Icons.visibility_off);

      // Password should be obscured initially - visibility_off icon is shown
      expect(find.byIcon(Icons.visibility_off), findsOneWidget);

      // Toggle visibility
      await tester.tap(toggleButton);
      await tester.pump();

      // Password should be visible - visibility icon is shown
      expect(find.byIcon(Icons.visibility), findsOneWidget);
      expect(find.byIcon(Icons.visibility_off), findsNothing);

      // Toggle back
      await tester.tap(find.byIcon(Icons.visibility));
      await tester.pump();
      expect(find.byIcon(Icons.visibility_off), findsOneWidget);
      expect(find.byIcon(Icons.visibility), findsNothing);
    });

    testWidgets('Remember me checkbox functionality', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
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

    testWidgets('Terms and conditions checkbox on register page', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      final registerButton = find.text('Create Account');

      // Try to register without agreeing to terms
      await tester.enterText(find.ancestor(
        of: find.text('Email'),
        matching: find.byType(TextFormField),
      ), 'test@example.com');
      await tester.enterText(find.ancestor(
        of: find.text('用户名 (可选)'),
        matching: find.byType(TextFormField),
      ), 'testuser');
      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(TextFormField),
      ), 'Password123');
      await tester.enterText(find.ancestor(
        of: find.text('Confirm Password'),
        matching: find.byType(TextFormField),
      ), 'Password123');

      await tester.tap(registerButton);
      await tester.pump();

      // Should show terms agreement snackbar
      expect(find.text('Please agree to the terms and conditions'), findsOneWidget);
    });
  });
}