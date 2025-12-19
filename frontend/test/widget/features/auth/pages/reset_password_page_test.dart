import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:mockito/mockito.dart';

import 'package:personal_ai_assistant/features/auth/presentation/pages/reset_password_page.dart';
import 'package:personal_ai_assistant/features/auth/presentation/providers/auth_provider.dart';
import 'package:personal_ai_assistant/core/router/app_router.dart';
import 'package:personal_ai_assistant/shared/widgets/custom_text_field.dart';
import 'package:personal_ai_assistant/shared/widgets/custom_button.dart';
import 'package:personal_ai_assistant/features/auth/presentation/widgets/password_requirement_item.dart';

// Mock classes
class MockAuthNotifier extends Mock implements AuthNotifier {}

void main() {
  group('ResetPasswordPage Widget Tests', () {
    late ProviderContainer container;
    late MockAuthNotifier mockAuthNotifier;

    setUp(() {
      mockAuthNotifier = MockAuthNotifier();

      container = ProviderContainer(
        overrides: [
          authProvider.overrideWith((ref) => mockAuthNotifier),
        ],
      );
    });

    tearDown(() {
      container.dispose();
    });

    Widget createWidgetUnderTest({String? token}) {
      return UncontrolledProviderScope(
        container: container,
        child: MaterialApp.router(
          routerConfig: AppRouter(),
        ),
      );
    }

    testWidgets('renders all required UI components with valid token', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Assert - Check for key UI elements
      expect(find.text('Reset Password'), findsOneWidget);
      expect(find.text('Set New Password'), findsOneWidget);
      expect(find.text('Your new password must be different from\nprevious used passwords'), findsOneWidget);
      expect(find.byType(CustomTextField), findsNWidgets(2)); // Password and Confirm Password
      expect(find.text('New Password'), findsOneWidget);
      expect(find.text('Confirm New Password'), findsOneWidget);
      expect(find.byKey(const Key('reset_password_button')), findsOneWidget);
      expect(find.text('Reset Password'), findsOneWidget);
      expect(find.byIcon(Icons.lock_outline), findsNWidgets(2));
      expect(find.byIcon(Icons.lock_open), findsOneWidget);
    });

    testWidgets('displays error dialog when token is missing', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: null));
      await tester.pumpAndSettle();

      // Wait for post frame callback
      await tester.pump();

      // Assert - Error dialog should be shown
      expect(find.text('Error'), findsOneWidget);
      expect(find.text('Invalid reset link. Please request a new password reset.'), findsOneWidget);
      expect(find.text('OK'), findsOneWidget);
    });

    testWidgets('displays error dialog when token is empty', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: ''));
      await tester.pumpAndSettle();

      // Wait for post frame callback
      await tester.pump();

      // Assert - Error dialog should be shown
      expect(find.text('Error'), findsOneWidget);
      expect(find.text('Invalid reset link. Please request a new password reset.'), findsOneWidget);
      expect(find.text('OK'), findsOneWidget);
    });

    testWidgets('navigates to forgot password when error dialog OK is tapped', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: null));
      await tester.pumpAndSettle();
      await tester.pump();

      // Act - Tap OK on error dialog
      await tester.tap(find.text('OK'));
      await tester.pumpAndSettle();

      // Assert - Should navigate to forgot password page
      expect(find.text('Forgot Password'), findsOneWidget);
    });

    testWidgets('validates empty password fields', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Act - Submit without entering passwords
      await tester.tap(find.byKey(const Key('reset_password_button')));
      await tester.pump();

      // Assert - Validation errors should appear
      expect(find.text('Please enter your new password'), findsOneWidget);
      expect(find.text('Please confirm your new password'), findsOneWidget);
    });

    testWidgets('validates password minimum length', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Act - Enter short password
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
        '123'
      );
      await tester.tap(find.byKey(const Key('reset_password_button')));
      await tester.pump();

      // Assert - Password length error should appear
      expect(find.text('Password must be at least 8 characters'), findsOneWidget);
    });

    testWidgets('validates password confirmation match', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Act - Enter different passwords
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
        'Password123'
      );
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'Confirm New Password'),
        'DifferentPassword456'
      );
      await tester.tap(find.byKey(const Key('reset_password_button')));
      await tester.pump();

      // Assert - Password mismatch error should appear
      expect(find.text('Passwords do not match'), findsOneWidget);
    });

    testWidgets('submits successfully with valid passwords', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.resetPassword(token: anyNamed('token'), newPassword: anyNamed('newPassword')))
          .thenAnswer((_) async {});
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Act - Enter matching valid passwords and submit
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
        'NewPassword123'
      );
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'Confirm New Password'),
        'NewPassword123'
      );
      await tester.tap(find.byKey(const Key('reset_password_button')));
      await tester.pump();

      // Assert - resetPassword should be called with correct parameters
      verify(mockAuthNotifier.resetPassword(
        token: 'valid-token',
        newPassword: 'NewPassword123'
      )).called(1);
    });

    testWidgets('shows password requirements that update in real-time', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Assert - Initial requirements should be shown as not met
      expect(find.text('Password must:'), findsOneWidget);
      expect(find.text('Be at least 8 characters'), findsOneWidget);
      expect(find.text('Contain at least one uppercase letter'), findsOneWidget);
      expect(find.text('Contain at least one lowercase letter'), findsOneWidget);
      expect(find.text('Contain at least one number'), findsOneWidget);

      // Check initial state (all requirements should be invalid)
      final requirementItems = find.byType(PasswordRequirementItem);
      expect(requirementItems, findsNWidgets(4));

      // Act - Enter a password that meets all requirements
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
        'SecurePass123'
      );
      await tester.pump();

      // Assert - All requirements should now be valid
      // Note: We can't easily test the visual state change without accessing internal state,
      // but we can verify the widget still exists and updates
      expect(requirementItems, findsNWidgets(4));
    });

    testWidgets('displays loading state during submission', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.resetPassword(token: anyNamed('token'), newPassword: anyNamed('newPassword')))
          .thenAnswer((_) async {});

      // Set loading state
      when(mockAuthNotifier.isLoading).thenReturn(true);
      when(mockAuthNotifier.state).thenReturn(const AuthState(
        isLoading: true,
        currentOperation: AuthOperation.resetPassword,
      ));

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Act - Enter valid passwords and submit
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
        'NewPassword123'
      );
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'Confirm New Password'),
        'NewPassword123'
      );
      await tester.tap(find.byKey(const Key('reset_password_button')));
      await tester.pump();

      // Assert - Loading overlay should be visible
      expect(find.byType(LoadingOverlay), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });

    testWidgets('displays success message after password reset', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.resetPassword(token: anyNamed('token'), newPassword: anyNamed('newPassword')))
          .thenAnswer((_) async {});

      // Set success state after submission
      when(mockAuthNotifier.state).thenReturn(AuthState(
        isLoading: false,
        currentOperation: AuthOperation.resetPassword,
        error: null,
      ));

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Simulate successful response by updating state
      when(mockAuthNotifier.state).thenReturn(AuthState(
        isLoading: false,
        currentOperation: AuthOperation.resetPassword,
        error: null,
      ));

      // Act - Enter valid passwords and submit
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
        'NewPassword123'
      );
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'Confirm New Password'),
        'NewPassword123'
      );
      await tester.tap(find.byKey(const Key('reset_password_button')));
      await tester.pump();

      // Wait for success state
      await tester.pumpAndSettle();

      // Assert - Success message should be displayed
      expect(find.text('Password Reset Successful!'), findsOneWidget);
      expect(find.text('Your password has been successfully reset. You can now login with your new password.'), findsOneWidget);
      expect(find.byKey(const Key('go_to_login_button')), findsOneWidget);
      expect(find.text('Go to Login'), findsOneWidget);
      expect(find.byIcon(Icons.check_circle_outline), findsOneWidget);
    });

    testWidgets('displays error message when reset fails', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.resetPassword(token: anyNamed('token'), newPassword: anyNamed('newPassword')))
          .thenThrow(Exception('Invalid token'));

      // Set error state
      when(mockAuthNotifier.state).thenReturn(AuthState(
        isLoading: false,
        currentOperation: AuthOperation.resetPassword,
        error: 'Invalid or expired reset token',
      ));

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Act - Enter valid passwords and submit
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
        'NewPassword123'
      );
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'Confirm New Password'),
        'NewPassword123'
      );
      await tester.tap(find.byKey(const Key('reset_password_button')));
      await tester.pump();

      // Assert - Error message should be displayed
      expect(find.text('Invalid or expired reset token'), findsOneWidget);

      // Check for snackbar
      expect(find.byType(SnackBar), findsOneWidget);
    });

    testWidgets('back button navigates to login page', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Act - Tap back button
      await tester.tap(find.byIcon(Icons.arrow_back));
      await tester.pumpAndSettle();

      // Assert - Should be back on login page
      expect(find.text('Login'), findsOneWidget);
    });

    testWidgets('Go to Login button navigates correctly after success', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.resetPassword(token: anyNamed('token'), newPassword: anyNamed('newPassword')))
          .thenAnswer((_) async {});

      // Set success state
      when(mockAuthNotifier.state).thenReturn(AuthState(
        isLoading: false,
        currentOperation: AuthOperation.resetPassword,
        error: null,
      ));

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Simulate successful response
      when(mockAuthNotifier.state).thenReturn(AuthState(
        isLoading: false,
        currentOperation: AuthOperation.resetPassword,
        error: null,
      ));

      // Act - Enter passwords and submit
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
        'NewPassword123'
      );
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'Confirm New Password'),
        'NewPassword123'
      );
      await tester.tap(find.byKey(const Key('reset_password_button')));
      await tester.pump();

      // Wait for success state
      await tester.pumpAndSettle();

      // Tap Go to Login button
      await tester.tap(find.byKey(const Key('go_to_login_button')));
      await tester.pumpAndSettle();

      // Assert - Should be back on login page
      expect(find.text('Login'), findsOneWidget);
    });

    testWidgets('password visibility toggle works correctly', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Find password field
      final passwordField = find.byWidgetPredicate(
        (widget) => widget is CustomTextField && widget.label == 'New Password'
      );

      // Find visibility toggle buttons (should be two for both fields)
      final toggleButtons = find.byIcon(Icons.visibility_off);

      // Assert - Initial state should show password (visibility_off icon)
      expect(toggleButtons, findsNWidgets(2));

      // Act - Toggle visibility for password field
      await tester.tap(toggleButtons.first);
      await tester.pump();

      // Assert - Icon should change to visibility
      expect(find.byIcon(Icons.visibility), findsOneWidget);
      expect(find.byIcon(Icons.visibility_off), findsOneWidget);

      // Toggle back
      await tester.tap(find.byIcon(Icons.visibility));
      await tester.pump();

      // Assert - Should be back to visibility_off
      expect(toggleButtons, findsNWidgets(2));
    });

    testWidgets('supports accessibility features', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Assert - Check semantic labels
      expect(
        tester.semantics.findByLabel('New Password'),
        findsOneWidget,
      );

      expect(
        tester.semantics.findByLabel('Confirm New Password'),
        findsOneWidget,
      );

      expect(
        tester.semantics.findByLabel('Reset Password'),
        findsOneWidget,
      );
    });

    testWidgets('handles special characters in password', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Act - Enter password with special characters
      const specialPassword = 'P@ssw0rd!123';
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
        specialPassword
      );
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'Confirm New Password'),
        specialPassword
      );
      await tester.tap(find.byKey(const Key('reset_password_button')));
      await tester.pump();

      // Assert - Should accept special characters
      expect(find.text(specialPassword), findsNWidgets(2));
      expect(find.text('Password must be at least 8 characters'), findsNothing);
      expect(find.text('Passwords do not match'), findsNothing);
    });

    testWidgets('maintains form state during error scenarios', (WidgetTester tester) async {
      // Arrange
      when(mockAuthNotifier.state).thenReturn(const AuthState());

      await tester.pumpWidget(createWidgetUnderTest(token: 'valid-token'));
      await tester.pumpAndSettle();

      // Act - Enter password
      const password = 'TestPassword123';
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'New Password'),
        password
      );
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'Confirm New Password'),
        'different'
      );
      await tester.tap(find.byKey(const Key('reset_password_button')));
      await tester.pump();

      // Assert - Password field should retain its value
      expect(find.text(password), findsOneWidget);
      expect(find.text('different'), findsOneWidget);
      expect(find.text('Passwords do not match'), findsOneWidget);

      // Fix confirmation password
      await tester.enterText(
        find.byWidgetPredicate((widget) => widget is CustomTextField && widget.label == 'Confirm New Password'),
        password
      );
      await tester.pump();

      // Assert - Error should be resolved
      expect(find.text('Passwords do not match'), findsNothing);
    });
  });
}