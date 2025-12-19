import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:personal_ai_assistant/features/auth/presentation/pages/forgot_password_page.dart';

void main() {
  group('Forgot Password Page Widget Tests', () {
    testWidgets('Should display all form elements initially', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: ForgotPasswordPage(),
          ),
        ),
      );

      // Check for all required UI elements
      expect(find.text('Forgot Password'), findsOneWidget);
      expect(find.text('Forgot Password?'), findsOneWidget);
      expect(find.byIcon(Icons.lock_reset), findsOneWidget);
      expect(find.text('Email'), findsOneWidget);
      expect(find.text('Send Reset Link'), findsOneWidget);
      expect(find.text('Enter your email address and we\'ll send you a link to reset your password'), findsOneWidget);
    });

    testWidgets('Should validate empty email field', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: ForgotPasswordPage(),
          ),
        ),
      );

      // Try to submit empty form
      await tester.tap(find.byKey(Key('forgot_password_submit_button')));
      await tester.pump();

      // Should show validation error
      expect(find.text('Please enter your email'), findsOneWidget);
    });

    testWidgets('Should find back button icon', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: ForgotPasswordPage(),
          ),
        ),
      );

      // Check for back button icon
      expect(find.byIcon(Icons.arrow_back), findsOneWidget);
    });

    testWidgets('Should display email text field', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: ForgotPasswordPage(),
          ),
        ),
      );

      // Should find the email text field
      expect(find.byType(TextField), findsWidgets);
    });

    testWidgets('Should have submit button', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: ForgotPasswordPage(),
          ),
        ),
      );

      // Should find the submit button
      expect(find.byKey(Key('forgot_password_submit_button')), findsOneWidget);
    });
  });
}