import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:mockito/mockito.dart';
import 'package:http/http.dart' as http;

import 'package:personal_ai_assistant/main.dart';
import 'package:personal_ai_assistant/core/router/app_router.dart';
import 'package:personal_ai_assistant/features/auth/presentation/providers/auth_provider.dart';
import 'package:personal_ai_assistant/features/auth/data/datasources/auth_remote_datasource.dart';
import 'package:personal_ai_assistant/features/auth/data/repositories/auth_repository_impl.dart';
import 'package:personal_ai_assistant/shared/widgets/custom_text_field.dart';
import 'package:personal_ai_assistant/shared/widgets/custom_button.dart';

// Mock classes
class MockAuthRemoteDataSource extends Mock implements AuthRemoteDataSource {}
class MockHttpClient extends Mock implements http.Client {}

void main() {
  group('Forgot Password Flow Integration Tests', () {
    late ProviderContainer container;
    late MockAuthRemoteDataSource mockDataSource;
    late MockHttpClient mockHttpClient;

    setUp(() {
      mockDataSource = MockAuthRemoteDataSource();
      mockHttpClient = MockHttpClient();

      container = ProviderContainer(
        overrides: [
          authRemoteDataSourceProvider.overrideWithValue(mockDataSource),
        ],
      );
    });

    tearDown(() {
      container.dispose();
    });

    Widget createTestApp() {
      return UncontrolledProviderScope(
        container: container,
        child: MaterialApp.router(
          routerConfig: AppRouter(),
        ),
      );
    }

    testWidgets('complete forgot password flow: login -> forgot password -> reset password -> login', (WidgetTester tester) async {
      // Arrange - Mock API responses
      when(mockDataSource.forgotPassword(any))
          .thenAnswer((_) async => PasswordResetResponse(
                message: "If an account with this email exists, a password reset link has been sent.",
                token: "test-reset-token-123",
                expiresAt: DateTime.now().add(const Duration(hours: 1)),
              ));

      when(mockDataSource.resetPassword(any, any))
          .thenAnswer((_) async => PasswordResetResponse(
                message: "Password has been successfully reset. Please login with your new password.",
              ));

      // 1. Start at login page
      await tester.pumpWidget(createTestApp());
      await tester.pumpAndSettle();

      // Verify we're on login page
      expect(find.text('Login'), findsOneWidget);
      expect(find.text('Forgot Password?'), findsOneWidget);

      // 2. Click Forgot Password link
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Verify we're on forgot password page
      expect(find.text('Forgot Password'), findsOneWidget);
      expect(find.text('Enter your email address and we\'ll send you a link to reset your password'), findsOneWidget);

      // 3. Enter email and submit
      const testEmail = 'test@example.com';
      await tester.enterText(find.byType(CustomTextField), testEmail);
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
      await tester.pumpAndSettle();

      // Verify API was called
      verify(mockDataSource.forgotPassword(testEmail)).called(1);

      // 4. Verify success message is displayed
      expect(find.text('Email Sent!'), findsOneWidget);
      expect(find.text('We\'ve sent a password reset link to'), findsOneWidget);
      expect(find.text(testEmail), findsOneWidget);

      // 5. Now simulate navigating to reset password page with token
      // In a real app, this would be via email link
      container.read(appRouterProvider).go('/reset-password?token=test-reset-token-123');
      await tester.pumpAndSettle();

      // Verify we're on reset password page
      expect(find.text('Reset Password'), findsOneWidget);
      expect(find.text('Set New Password'), findsOneWidget);

      // 6. Enter new password
      const newPassword = 'NewSecurePassword123';
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
        newPassword
      );

      // 7. Confirm new password
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'Confirm New Password'),
        newPassword
      );
      await tester.pump();

      // Verify password requirements are met
      expect(find.text('Be at least 8 characters'), findsOneWidget);
      expect(find.text('Contain at least one uppercase letter'), findsOneWidget);
      expect(find.text('Contain at least one lowercase letter'), findsOneWidget);
      expect(find.text('Contain at least one number'), findsOneWidget);

      // 8. Submit new password
      await tester.tap(find.byKey(const Key('reset_password_button')));
      await tester.pumpAndSettle();

      // Verify API was called
      verify(mockDataSource.resetPassword('test-reset-token-123', newPassword)).called(1);

      // 9. Verify success message
      expect(find.text('Password Reset Successful!'), findsOneWidget);
      expect(find.text('Your password has been successfully reset. You can now login with your new password.'), findsOneWidget);

      // 10. Click Go to Login
      await tester.tap(find.byKey(const Key('go_to_login_button')));
      await tester.pumpAndSettle();

      // Verify we're back on login page
      expect(find.text('Login'), findsOneWidget);
    });

    testWidgets('forgot password flow with error handling', (WidgetTester tester) async {
      // Arrange - Mock error response
      when(mockDataSource.forgotPassword(any))
          .thenThrow(Exception('Network error'));

      await tester.pumpWidget(createTestApp());
      await tester.pumpAndSettle();

      // Navigate to forgot password
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Enter email and submit
      await tester.enterText(find.byType(CustomTextField), 'test@example.com');
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
      await tester.pumpAndSettle();

      // Verify error is displayed
      expect(find.byType(SnackBar), findsOneWidget);

      // Verify form is still displayed (not in success state)
      expect(find.text('Enter your email address and we\'ll send you a link to reset your password'), findsOneWidget);
      expect(find.byKey(const Key('forgot_password_submit_button')), findsOneWidget);
    });

    testWidgets('reset password flow with invalid token', (WidgetTester tester) async {
      // Arrange - Mock error for invalid token
      when(mockDataSource.resetPassword(any, any))
          .thenThrow(Exception('Invalid or expired reset token'));

      // Navigate directly to reset page with invalid token
      container.read(appRouterProvider).go('/reset-password?token=invalid-token');
      await tester.pumpAndSettle();

      // Enter password
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
        'NewPassword123'
      );
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'Confirm New Password'),
        'NewPassword123'
      );

      // Submit
      await tester.tap(find.byKey(const Key('reset_password_button')));
      await tester.pumpAndSettle();

      // Verify error is displayed
      expect(find.byType(SnackBar), findsOneWidget);

      // Verify form is still displayed
      expect(find.text('Set New Password'), findsOneWidget);
      expect(find.byKey(const Key('reset_password_button')), findsOneWidget);
    });

    testWidgets('resend email functionality', (WidgetTester tester) async {
      // Arrange - Mock successful forgot password calls
      when(mockDataSource.forgotPassword(any))
          .thenAnswer((_) async => PasswordResetResponse(
                message: "If an account with this email exists, a password reset link has been sent.",
                token: "new-token-456",
                expiresAt: DateTime.now().add(const Duration(hours: 1)),
              ));

      await tester.pumpWidget(createTestApp());
      await tester.pumpAndSettle();

      // Navigate to forgot password
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Enter email and submit first time
      await tester.enterText(find.byType(CustomTextField), 'test@example.com');
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
      await tester.pumpAndSettle();

      // Verify success state
      expect(find.text('Email Sent!'), findsOneWidget);

      // Click resend email
      await tester.tap(find.byKey(const Key('resend_email_button')));
      await tester.pump();

      // Verify we're back to the form
      expect(find.text('Enter your email address and we\'ll send you a link to reset your password'), findsOneWidget);

      // Email should still be filled
      expect(find.text('test@example.com'), findsOneWidget);

      // Submit again
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
      await tester.pumpAndSettle();

      // Verify API was called twice
      verify(mockDataSource.forgotPassword('test@example.com')).called(2);

      // Should show success again
      expect(find.text('Email Sent!'), findsOneWidget);
    });

    testWidgets('password strength validation during reset', (WidgetTester tester) async {
      // Navigate directly to reset page
      container.read(appRouterProvider).go('/reset-password?token=test-token');
      await tester.pumpAndSettle();

      // Test various password strengths
      final testCases = [
        ('weak', false, false, false, false),  // Too short
        ('weakpass', false, false, false, false),  // No uppercase or number
        ('Weakpass', false, false, true, false),  // Has uppercase but no number
        ('Weak123', false, true, true, true),  // Has uppercase and number but too short
        ('StrongPass123', true, true, true, true),  // Meets all requirements
      ];

      for (final (password, hasMinLength, hasNumber, hasUppercase, hasLowercase) in testCases) {
        // Clear fields
        await tester.enterText(
          find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
          ''
        );
        await tester.enterText(
          find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'Confirm New Password'),
          ''
        );
        await tester.pump();

        // Enter test password
        await tester.enterText(
          find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
          password
        );
        await tester.pump();

        // Check if requirements are visually met (this is approximate since we can't directly check the visual state)
        if (hasMinLength && password.length >= 8) {
          // The requirement item should be present and possibly styled differently
          expect(find.text('Be at least 8 characters'), findsOneWidget);
        }

        // Test submit behavior
        if (password.length >= 8) {
          await tester.enterText(
            find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'Confirm New Password'),
            password
          );
          await tester.tap(find.byKey(const Key('reset_password_button')));
          await tester.pump();

          // Should not show length error
          expect(find.text('Password must be at least 8 characters'), findsNothing);
        }
      }
    });

    testWidgets('navigation persistence through flow', (WidgetTester tester) async {
      await tester.pumpWidget(createTestApp());
      await tester.pumpAndSettle();

      // Navigate through the flow
      expect(find.text('Login'), findsOneWidget);

      // To forgot password
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();
      expect(find.text('Forgot Password'), findsOneWidget);

      // Back to login
      await tester.tap(find.byIcon(Icons.arrow_back));
      await tester.pumpAndSettle();
      expect(find.text('Login'), findsOneWidget);

      // Test deep link to reset password
      container.read(appRouterProvider).go('/reset-password?token=test-token');
      await tester.pumpAndSettle();
      expect(find.text('Reset Password'), findsOneWidget);

      // Back to login
      await tester.tap(find.byIcon(Icons.arrow_back));
      await tester.pumpAndSettle();
      expect(find.text('Login'), findsOneWidget);
    });

    testWidgets('email validation edge cases in forgot password', (WidgetTester tester) async {
      await tester.pumpWidget(createTestApp());
      await tester.pumpAndSettle();

      // Navigate to forgot password
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      final edgeCases = [
        ('', 'Please enter your email'),
        ('invalid', 'Please enter a valid email'),
        ('@domain.com', 'Please enter a valid email'),
        ('user@', 'Please enter a valid email'),
        ('valid@example.com', null), // Should pass
        ('user.name+tag@example.co.uk', null), // Should pass
      ];

      for (final (email, expectedError) in edgeCases) {
        // Clear field
        await tester.enterText(find.byType(CustomTextField), '');
        await tester.pump();

        // Enter test email
        await tester.enterText(find.byType(CustomTextField), email);
        await tester.pump();

        // Try to submit
        await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
        await tester.pump();

        if (expectedError != null) {
          expect(find.text(expectedError), findsOneWidget);
        } else {
          expect(find.text('Please enter your email'), findsNothing);
          expect(find.text('Please enter a valid email'), findsNothing);
        }
      }
    });

    testWidgets('form state management during async operations', (WidgetTester tester) async {
      // Create a delayed response to test loading state
      when(mockDataSource.forgotPassword(any)).thenAnswer((_) async {
        await Future.delayed(const Duration(milliseconds: 500));
        return PasswordResetResponse(
          message: "If an account with this email exists, a password reset link has been sent.",
          token: "delayed-token",
          expiresAt: DateTime.now().add(const Duration(hours: 1)),
        );
      });

      await tester.pumpWidget(createTestApp());
      await tester.pumpAndSettle();

      // Navigate to forgot password
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Enter email and submit
      await tester.enterText(find.byType(CustomTextField), 'test@example.com');
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));

      // Should show loading immediately
      await tester.pump();
      expect(find.byType(CircularProgressIndicator), findsOneWidget);

      // Wait for completion
      await tester.pump(const Duration(milliseconds: 500));
      await tester.pumpAndSettle();

      // Should show success
      expect(find.text('Email Sent!'), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsNothing);
    });
  });
}