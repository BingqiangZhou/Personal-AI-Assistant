import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:personal_ai_assistant/features/auth/presentation/pages/reset_password_page.dart';

void main() {
  group('Reset Password Page Widget Tests', () {
    const testToken = 'test-reset-token-123';

    testWidgets('Should display all form elements initially', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: ResetPasswordPage(token: testToken),
          ),
        ),
      );

      // Check for all required UI elements
      expect(find.text('Set New Password'), findsOneWidget);
      expect(find.byIcon(Icons.lock_open), findsOneWidget);
      expect(find.text('New Password'), findsOneWidget);
      expect(find.text('Confirm New Password'), findsOneWidget);
      expect(find.byKey(Key('reset_password_button')), findsOneWidget);
      expect(find.text('Password must:'), findsOneWidget);
    });

    testWidgets('Should validate empty password fields', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: ResetPasswordPage(token: testToken),
          ),
        ),
      );

      // Try to submit empty form (scroll to make button visible)
      await tester.dragUntilVisible(
        find.byKey(Key('reset_password_button')),
        find.byType(SingleChildScrollView),
        const Offset(0, 300),
      );
      await tester.tap(find.byKey(Key('reset_password_button')));
      await tester.pump();

      // Should show validation errors
      expect(find.text('Please enter your new password'), findsOneWidget);
      expect(find.text('Please confirm your new password'), findsOneWidget);
    });

    testWidgets('Should find back button icon', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: ResetPasswordPage(token: testToken),
          ),
        ),
      );

      // Check for back button icon
      expect(find.byIcon(Icons.arrow_back), findsOneWidget);
    });

    testWidgets('Should display password fields', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: ResetPasswordPage(token: testToken),
          ),
        ),
      );

      // Should find the password text fields
      expect(find.byType(TextField), findsWidgets);
    });

    testWidgets('Should display password requirements', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: ResetPasswordPage(token: testToken),
          ),
        ),
      );

      // Should find password requirements
      expect(find.text('Be at least 8 characters'), findsOneWidget);
      expect(find.text('Contain at least one uppercase letter'), findsOneWidget);
      expect(find.text('Contain at least one lowercase letter'), findsOneWidget);
      expect(find.text('Contain at least one number'), findsOneWidget);
    });

    testWidgets('Should have reset password button', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: ResetPasswordPage(token: testToken),
          ),
        ),
      );

      // Should find the reset password button
      expect(find.byKey(Key('reset_password_button')), findsOneWidget);
    });

    testWidgets('Should show error for invalid token', (WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: ResetPasswordPage(token: null),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Should show error dialog
      expect(find.text('Error'), findsOneWidget);
      expect(find.text('Invalid reset link. Please request a new password reset.'), findsOneWidget);
    });
  });
}