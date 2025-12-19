import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:mockito/mockito.dart';

import 'package:personal_ai_assistant/features/auth/presentation/pages/forgot_password_page.dart';
import 'package:personal_ai_assistant/features/auth/presentation/providers/auth_provider.dart';
import 'package:personal_ai_assistant/core/router/app_router.dart';
import 'package:personal_ai_assistant/shared/widgets/custom_text_field.dart';
import 'package:personal_ai_assistant/shared/widgets/custom_button.dart';

// Mock classes
class MockAuthNotifier extends Mock implements AuthNotifier {}
class MockGoRouter extends Mock implements GoRouter {}

void main() {
  group('ForgotPasswordPage Widget Tests', () {
    late ProviderContainer container;
    late MockAuthNotifier mockAuthNotifier;
    late MockGoRouter mockGoRouter;

    setUp(() {
      mockAuthNotifier = MockAuthNotifier();
      mockGoRouter = MockGoRouter();

      container = ProviderContainer(
        overrides: [
          authProvider.overrideWith((ref) => mockAuthNotifier),
        ],
      );
    });

    tearDown(() {
      container.dispose();
    });

    Widget createWidgetUnderTest() {
      return UncontrolledProviderScope(
        container: container,
        child: MaterialApp.router(
          routerConfig: AppRouter(),
        ),
      );
    }

    testWidgets('renders all required UI components initially', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Assert - Check for key UI elements
      expect(find.text('Forgot Password'), findsOneWidget);
      expect(find.text('Forgot Password?'), findsOneWidget);
      expect(find.text('Enter your email address and we\'ll send you a link to reset your password'), findsOneWidget);
      expect(find.byType(CustomTextField), findsOneWidget);
      expect(find.byType(CustomButton), findsOneWidget);
      expect(find.text('Send Reset Link'), findsOneWidget);
      expect(find.byIcon(Icons.lock_reset), findsOneWidget);
      expect(find.byIcon(Icons.email_outlined), findsOneWidget);
    });

    testWidgets('displays email input field with proper validation', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Assert - Email field should be present
      final emailField = find.byType(CustomTextField);
      expect(emailField, findsOneWidget);

      // Check for email-specific properties
      final textField = tester.widget<CustomTextField>(emailField);
      expect(textField.label, 'Email');
      expect(textField.keyboardType, TextInputType.emailAddress);
    });

    testWidgets('validates empty email field', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Act - Submit without entering email
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
      await tester.pump();

      // Assert - Validation error should appear
      expect(find.text('Please enter your email'), findsOneWidget);
    });

    testWidgets('validates invalid email format', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Act - Enter invalid email
      await tester.enterText(find.byType(CustomTextField), 'invalid-email');
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
      await tester.pump();

      // Assert - Validation error should appear
      expect(find.text('Please enter a valid email'), findsOneWidget);
    });

    testWidgets('submits successfully with valid email', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.forgotPassword(any)).thenAnswer((_) async {});
      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Act - Enter valid email and submit
      await tester.enterText(find.byType(CustomTextField), 'test@example.com');
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
      await tester.pump();

      // Assert - forgotPassword should be called
      verify(mockAuthNotifier.forgotPassword('test@example.com')).called(1);
    });

    testWidgets('displays loading state during submission', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.forgotPassword(any)).thenAnswer((_) async {});

      // Set loading state
      when(mockAuthNotifier.isLoading).thenReturn(true);
      when(mockAuthNotifier.state).thenReturn(const AuthState(
        isLoading: true,
        currentOperation: AuthOperation.forgotPassword,
      ));

      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Act - Enter email and submit
      await tester.enterText(find.byType(CustomTextField), 'test@example.com');
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
      await tester.pump();

      // Assert - Loading overlay should be visible
      expect(find.byType(LoadingOverlay), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });

    testWidgets('displays success message after email sent', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.forgotPassword(any)).thenAnswer((_) async {});

      // Set success state after submission
      when(mockAuthNotifier.isLoading).thenReturn(false);
      when(mockAuthNotifier.state).thenReturn(AuthState(
        isLoading: false,
        currentOperation: AuthOperation.forgotPassword,
        error: null,
      ));

      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Act - Enter valid email and submit
      await tester.enterText(find.byType(CustomTextField), 'test@example.com');
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
      await tester.pump();

      // Simulate successful response
      when(mockAuthNotifier.state).thenReturn(AuthState(
        isLoading: false,
        currentOperation: AuthOperation.forgotPassword,
        error: null,
      ));
      await tester.pump();

      // Assert - Success message should be displayed
      expect(find.text('Email Sent!'), findsOneWidget);
      expect(find.text('We\'ve sent a password reset link to'), findsOneWidget);
      expect(find.text('test@example.com'), findsOneWidget);
      expect(find.text('Please check your email and click the link to reset your password'), findsOneWidget);
      expect(find.byKey(const Key('back_to_login_button')), findsOneWidget);
      expect(find.byKey(const Key('resend_email_button')), findsOneWidget);
      expect(find.byIcon(Icons.check_circle_outline), findsOneWidget);
    });

    testWidgets('displays error message when submission fails', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.forgotPassword(any)).thenThrow(Exception('Failed to send email'));

      // Set error state
      when(mockAuthNotifier.state).thenReturn(AuthState(
        isLoading: false,
        currentOperation: AuthOperation.forgotPassword,
        error: 'Failed to send email',
      ));

      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Act - Enter email and submit
      await tester.enterText(find.byType(CustomTextField), 'test@example.com');
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
      await tester.pump();

      // Assert - Error message should be displayed
      expect(find.text('Failed to send email'), findsOneWidget);

      // Check for snackbar
      expect(find.byType(SnackBar), findsOneWidget);
    });

    testWidgets('back button navigates to login page', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Act - Tap back button
      await tester.tap(find.byIcon(Icons.arrow_back));
      await tester.pumpAndSettle();

      // Assert - Should be back on login page
      expect(find.text('Login'), findsOneWidget);
      expect(find.text('Forgot Password?'), findsOneWidget);
    });

    testWidgets('Back to Login button navigates correctly after success', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.forgotPassword(any)).thenAnswer((_) async {});

      // Set success state
      when(mockAuthNotifier.state).thenReturn(AuthState(
        isLoading: false,
        currentOperation: AuthOperation.forgotPassword,
        error: null,
      ));

      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Act - Enter email and submit
      await tester.enterText(find.byType(CustomTextField), 'test@example.com');
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
      await tester.pump();

      // Wait for success state
      await tester.pumpAndSettle();

      // Tap Back to Login button
      await tester.tap(find.byKey(const Key('back_to_login_button')));
      await tester.pumpAndSettle();

      // Assert - Should be back on login page
      expect(find.text('Login'), findsOneWidget);
    });

    testWidgets('resend email button resets form state', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.forgotPassword(any)).thenAnswer((_) async {});

      // Set success state
      when(mockAuthNotifier.state).thenReturn(AuthState(
        isLoading: false,
        currentOperation: AuthOperation.forgotPassword,
        error: null,
      ));

      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Act - Submit email to show success state
      await tester.enterText(find.byType(CustomTextField), 'test@example.com');
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
      await tester.pumpAndSettle();

      // Now tap resend email
      await tester.tap(find.byKey(const Key('resend_email_button')));
      await tester.pump();

      // Assert - Should return to initial form state
      expect(find.text('Forgot Password?'), findsOneWidget);
      expect(find.text('Enter your email address and we\'ll send you a link to reset your password'), findsOneWidget);
      expect(find.byKey(const Key('forgot_password_submit_button')), findsOneWidget);
      expect(find.text('Send Reset Link'), findsOneWidget);

      // Verify clearError was called
      verify(mockAuthNotifier.clearError()).called(1);
    });

    testWidgets('handles multiple email entry attempts', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.forgotPassword(any)).thenAnswer((_) async {});
      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Act - Enter different emails
      await tester.enterText(find.byType(CustomTextField), 'first@example.com');
      await tester.pump();
      expect(find.text('first@example.com'), findsOneWidget);

      // Clear and enter new email
      await tester.enterText(find.byType(CustomTextField), '');
      await tester.enterText(find.byType(CustomTextField), 'second@example.com');
      await tester.pump();
      expect(find.text('second@example.com'), findsOneWidget);
      expect(find.text('first@example.com'), findsNothing);
    });

    testWidgets('supports accessibility features', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Assert - Check semantic labels
      expect(
        tester.semantics.findByLabel('Email'),
        findsOneWidget,
      );

      expect(
        tester.semantics.findByLabel('Send Reset Link'),
        findsOneWidget,
      );
    });

    testWidgets('supports keyboard navigation', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Act - Test tab navigation
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.pump();

      // Verify focus moves through fields
      expect(tester.binding.focusManager.primaryFocus?.debugLabel, contains('Email'));
    });

    testWidgets('handles edge case email formats', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.forgotPassword(any)).thenAnswer((_) async {});
      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Act & Assert - Test various email formats
      final testCases = [
        ('test+tag@example.com', true),
        ('user.name@example.co.uk', true),
        ('test@localhost', false),  // Our validator requires @
        ('test@example', true),     // Basic check passes
      ];

      for (final (email, shouldPass) in testCases) {
        await tester.enterText(find.byType(CustomTextField), email);
        await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
        await tester.pump();

        if (shouldPass) {
          // Should not show invalid email error
          expect(find.text('Please enter a valid email'), findsNothing);
        }

        // Clear for next test
        await tester.enterText(find.byType(CustomTextField), '');
        await tester.pump();
      }
    });

    testWidgets('persists email text during loading', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.forgotPassword(any)).thenAnswer((_) async {});

      // Simulate loading
      when(mockAuthNotifier.isLoading).thenReturn(true);
      when(mockAuthNotifier.state).thenReturn(const AuthState(
        isLoading: true,
        currentOperation: AuthOperation.forgotPassword,
      ));

      await tester.pumpWidget(createWidgetUnderTest());
      await tester.pumpAndSettle();

      // Navigate to forgot password page
      await tester.tap(find.text('Forgot Password?'));
      await tester.pumpAndSettle();

      // Act - Enter email and submit
      await tester.enterText(find.byType(CustomTextField), 'test@example.com');
      await tester.tap(find.byKey(const Key('forgot_password_submit_button')));
      await tester.pump();

      // Assert - Email text should persist during loading
      expect(find.text('test@example.com'), findsOneWidget);
    });
  });
}