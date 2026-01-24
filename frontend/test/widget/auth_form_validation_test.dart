import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:personal_ai_assistant/features/auth/presentation/pages/register_page.dart';
import 'package:personal_ai_assistant/features/auth/presentation/pages/login_page.dart';
import 'package:personal_ai_assistant/shared/widgets/custom_text_field.dart';

void main() {
  group('Auth Form Validation Tests', () {
    testWidgets('Register form should validate email correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Find email field using label text
      final emailField = find.byWidgetPredicate(
        (widget) => widget is CustomTextField && widget.label == 'Email',
      );

      // Enter invalid email
      await tester.enterText(emailField, 'invalid-email');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Please enter a valid email'), findsOneWidget);

      // Enter valid email
      await tester.enterText(emailField, 'test@example.com');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Please enter a valid email'), findsNothing);
    });

    testWidgets('Register form should validate password correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Find password field using label text
      final passwordField = find.byWidgetPredicate(
        (widget) => widget is CustomTextField && widget.label == 'Password',
      );

      // Test short password
      await tester.enterText(passwordField, 'short');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Password must be at least 8 characters'), findsOneWidget);

      // Test password without uppercase
      await tester.enterText(passwordField, 'password123');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Password must contain at least one uppercase letter (A-Z)'), findsOneWidget);

      // Test password without number
      await tester.enterText(passwordField, 'Password');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Password must contain at least one number (0-9)'), findsOneWidget);

      // Test valid password
      await tester.enterText(passwordField, 'Password123');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Password must be at least 8 characters'), findsNothing);
      expect(find.text('Password must contain at least one uppercase letter (A-Z)'), findsNothing);
      expect(find.text('Password must contain at least one number (0-9)'), findsNothing);
    });

    testWidgets('Register form should validate password confirmation', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Find password fields using label text
      final passwordField = find.byWidgetPredicate(
        (widget) => widget is CustomTextField && widget.label == 'Password',
      );
      final confirmPasswordField = find.byWidgetPredicate(
        (widget) => widget is CustomTextField && widget.label == 'Confirm Password',
      );

      // Enter mismatching passwords
      await tester.enterText(passwordField, 'Password123');
      await tester.enterText(confirmPasswordField, 'DifferentPassword');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Passwords do not match'), findsOneWidget);

      // Enter matching passwords
      await tester.enterText(confirmPasswordField, 'Password123');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Passwords do not match'), findsNothing);
    });

    testWidgets('Login form should validate fields', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Find email and password fields using label text
      final emailField = find.byWidgetPredicate(
        (widget) => widget is CustomTextField && widget.label == 'Email',
      );
      final passwordField = find.byWidgetPredicate(
        (widget) => widget is CustomTextField && widget.label == 'Password',
      );

      // Test empty fields
      await tester.tap(find.byKey(const Key('login_button')));
      await tester.pump();

      expect(find.text('Please enter your email'), findsOneWidget);
      expect(find.text('Please enter your password'), findsOneWidget);

      // Test invalid email
      await tester.enterText(emailField, 'invalid-email');
      await tester.tap(find.byKey(const Key('login_button')));
      await tester.pump();

      expect(find.text('Please enter a valid email'), findsOneWidget);

      // Test short password
      await tester.enterText(emailField, 'test@example.com');
      await tester.enterText(passwordField, '123');
      await tester.tap(find.byKey(const Key('login_button')));
      await tester.pump();

      expect(find.text('Password must be at least 6 characters'), findsOneWidget);

      // Test valid form
      await tester.enterText(passwordField, 'validpassword');
      await tester.tap(find.byKey(const Key('login_button')));
      await tester.pump();

      expect(find.text('Please enter your email'), findsNothing);
      expect(find.text('Please enter your password'), findsNothing);
      expect(find.text('Please enter a valid email'), findsNothing);
      expect(find.text('Password must be at least 6 characters'), findsNothing);
    });

    testWidgets('Should navigate between login and register', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Should be on login page
      expect(find.text('Welcome Back'), findsOneWidget);
      expect(find.text('Sign In'), findsWidgets);

      // Click Sign Up
      await tester.tap(find.text('Sign Up'));
      await tester.pumpAndSettle();

      // Should be on register page
      expect(find.text('Create Account'), findsOneWidget);
      expect(find.text('Already have an account?'), findsOneWidget);

      // Click Sign In
      await tester.tap(find.text('Sign In'));
      await tester.pumpAndSettle();

      // Should be back on login page
      expect(find.text('Welcome Back'), findsOneWidget);
    });

    testWidgets('Should toggle password visibility', (WidgetTester tester) async {
      // Test on login page
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Find password visibility toggle button
      final toggleButton = find.byIcon(Icons.visibility_off);

      // Should be obscured initially
      expect(toggleButton, findsOneWidget);

      // Toggle visibility
      await tester.tap(toggleButton);
      await tester.pump();

      // Should show visibility icon
      expect(find.byIcon(Icons.visibility), findsOneWidget);
      expect(toggleButton, findsNothing);

      // Toggle back
      await tester.tap(find.byIcon(Icons.visibility));
      await tester.pump();

      // Should show visibility_off icon again
      expect(find.byIcon(Icons.visibility_off), findsOneWidget);
      expect(find.byIcon(Icons.visibility), findsNothing);
    });

    testWidgets('Should handle remember me checkbox', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      final checkbox = find.byType(Checkbox);

      // Should be unchecked initially
      expect(tester.widget<Checkbox>(checkbox).value, isFalse);

      // Check the checkbox
      await tester.tap(checkbox);
      await tester.pump();

      expect(tester.widget<Checkbox>(checkbox).value, isTrue);

      // Uncheck the checkbox
      await tester.tap(checkbox);
      await tester.pump();

      expect(tester.widget<Checkbox>(checkbox).value, isFalse);
    });

    testWidgets('Should show terms agreement error', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Fill all valid fields but don't check terms
      await tester.enterText(
        find.byWidgetPredicate(
          (widget) => widget is CustomTextField && widget.label == '用户名 (可选)',
        ),
        'Test',
      );

      await tester.enterText(
        find.byWidgetPredicate(
          (widget) => widget is CustomTextField && widget.label == 'Email',
        ),
        'test@example.com',
      );

      await tester.enterText(
        find.byWidgetPredicate(
          (widget) => widget is CustomTextField && widget.label == 'Password',
        ),
        'Password123',
      );

      await tester.enterText(
        find.byWidgetPredicate(
          (widget) => widget is CustomTextField && widget.label == 'Confirm Password',
        ),
        'Password123',
      );

      // Try to submit without checking terms
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Please agree to the terms and conditions'), findsOneWidget);
    });
  });
}