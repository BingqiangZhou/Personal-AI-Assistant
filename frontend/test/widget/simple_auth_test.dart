import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:personal_ai_assistant/features/auth/presentation/pages/register_page.dart';
import 'package:personal_ai_assistant/features/auth/presentation/pages/login_page.dart';

void main() {
  group('Auth Simple Tests', () {
    testWidgets('Register and Login pages should render', (WidgetTester tester) async {
      // Test register page
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      expect(find.text('Create Account'), findsOneWidget);
      expect(find.text('First Name'), findsOneWidget);
      expect(find.text('Last Name'), findsOneWidget);
      expect(find.text('Email'), findsOneWidget);
      expect(find.text('Password'), findsOneWidget);
      expect(find.text('Confirm Password'), findsOneWidget);
      expect(find.text('Already have an account?'), findsOneWidget);
      expect(find.text('Sign In'), findsOneWidget);

      // Test login page
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      expect(find.text('Welcome Back'), findsOneWidget);
      expect(find.text('Sign in to continue to your AI assistant'), findsOneWidget);
      expect(find.text('Email'), findsOneWidget);
      expect(find.text('Password'), findsOneWidget);
      expect(find.text('Remember me'), findsOneWidget);
      expect(find.text('Forgot Password?'), findsOneWidget);
      expect(find.text('Sign In'), findsOneWidget);
      expect(find.text("Don't have an account?"), findsOneWidget);
      expect(find.text('Sign Up'), findsOneWidget);
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

      // Click Sign Up
      await tester.tap(find.text('Sign Up'));
      await tester.pumpAndSettle();

      // Should be on register page
      expect(find.text('Create Account'), findsOneWidget);

      // Click Sign In
      await tester.tap(find.text('Sign In'));
      await tester.pumpAndSettle();

      // Should be back on login page
      expect(find.text('Welcome Back'), findsOneWidget);
    });

    testWidgets('Should toggle password visibility icons', (WidgetTester tester) async {
      // Test on login page
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Should have visibility_off icon initially
      expect(find.byIcon(Icons.visibility_off), findsOneWidget);
      expect(find.byIcon(Icons.visibility), findsNothing);

      // Toggle visibility
      await tester.tap(find.byIcon(Icons.visibility_off));
      await tester.pump();

      // Should show visibility icon
      expect(find.byIcon(Icons.visibility), findsOneWidget);
      expect(find.byIcon(Icons.visibility_off), findsNothing);

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

    testWidgets('Should show validation errors on register form', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Try to submit empty form
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      // Should show validation errors
      expect(find.text('Required'), findsWidgets); // First name and Last name
      expect(find.text('Please enter your email'), findsOneWidget);
      expect(find.text('Please enter your password'), findsOneWidget);
      expect(find.text('Please confirm your password'), findsOneWidget);
    });

    testWidgets('Should show validation errors on login form', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Try to submit empty form
      await tester.tap(find.byKey(const Key('login_button')));
      await tester.pump();

      // Should show validation errors
      expect(find.text('Please enter your email'), findsOneWidget);
      expect(find.text('Please enter your password'), findsOneWidget);
    });

    testWidgets('Should validate email format', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      // Find email field (first text field after name fields)
      final emailFields = find.byType(TextField);
      expect(emailFields, findsAtLeastNWidgets(3));

      // Enter invalid email in the third field (after first name and last name)
      await tester.enterText(emailFields.at(2), 'invalid-email');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Please enter a valid email'), findsOneWidget);

      // Enter valid email
      await tester.enterText(emailFields.at(2), 'test@example.com');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Please enter a valid email'), findsNothing);
    });

    testWidgets('Should validate password requirements', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      final textFields = find.byType(TextField);

      // Fill first three fields (first name, last name, email)
      await tester.enterText(textFields.at(0), 'Test');
      await tester.enterText(textFields.at(1), 'User');
      await tester.enterText(textFields.at(2), 'test@example.com');

      // Enter weak password in fourth field
      await tester.enterText(textFields.at(3), 'weak');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Password must be at least 8 characters'), findsOneWidget);

      // Test password without uppercase
      await tester.enterText(textFields.at(3), 'password123');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Password must contain uppercase letter'), findsOneWidget);

      // Test password without number
      await tester.enterText(textFields.at(3), 'Password');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Password must contain number'), findsOneWidget);

      // Test valid password
      await tester.enterText(textFields.at(3), 'Password123');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Password must be at least 8 characters'), findsNothing);
      expect(find.text('Password must contain uppercase letter'), findsNothing);
      expect(find.text('Password must contain lowercase letter'), findsNothing);
      expect(find.text('Password must contain number'), findsNothing);

      // Test password without lowercase
      await tester.enterText(textFields.at(3), 'PASSWORD123');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Password must contain lowercase letter'), findsOneWidget);
    });

    testWidgets('Should validate password confirmation', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      final textFields = find.byType(TextField);

      // Fill all fields except matching password confirmation
      await tester.enterText(textFields.at(0), 'Test');
      await tester.enterText(textFields.at(1), 'User');
      await tester.enterText(textFields.at(2), 'test@example.com');
      await tester.enterText(textFields.at(3), 'Password123');
      await tester.enterText(textFields.at(4), 'DifferentPassword');

      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Passwords do not match'), findsOneWidget);

      // Fix password confirmation
      await tester.enterText(textFields.at(4), 'Password123');
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Passwords do not match'), findsNothing);
    });

    testWidgets('Should show terms agreement error', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );

      final textFields = find.byType(TextField);

      // Fill all valid fields
      await tester.enterText(textFields.at(0), 'Test');
      await tester.enterText(textFields.at(1), 'User');
      await tester.enterText(textFields.at(2), 'test@example.com');
      await tester.enterText(textFields.at(3), 'Password123');
      await tester.enterText(textFields.at(4), 'Password123');

      // Don't check terms checkbox and try to submit
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text('Please agree to the terms and conditions'), findsOneWidget);
    });
  });
}