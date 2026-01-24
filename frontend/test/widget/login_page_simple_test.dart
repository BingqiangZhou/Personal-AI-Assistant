import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:personal_ai_assistant/features/auth/presentation/pages/login_page.dart';

void main() {
  group('Login Page Widget Tests (Simple)', () {
    testWidgets('Should display all form fields', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
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
          child: MaterialApp(
            home: LoginPage(),
          ),
        ),
      );

      // Initially should show visibility off icon
      expect(find.byIcon(Icons.visibility_off), findsOneWidget);

      // Toggle password visibility
      await tester.tap(find.byIcon(Icons.visibility_off));
      await tester.pump();

      // Should show visibility icon
      expect(find.byIcon(Icons.visibility), findsOneWidget);

      // Toggle back
      await tester.tap(find.byIcon(Icons.visibility));
      await tester.pump();

      // Should show visibility off icon again
      expect(find.byIcon(Icons.visibility_off), findsOneWidget);
    });

    testWidgets('Should toggle remember me checkbox', (WidgetTester tester) async {
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

    testWidgets('Should accept valid form input', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
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