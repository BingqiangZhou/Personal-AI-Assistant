import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/auth/presentation/pages/register_page.dart';
import 'package:personal_ai_assistant/features/auth/presentation/providers/auth_provider.dart';
import 'package:personal_ai_assistant/features/auth/presentation/widgets/password_requirement_item.dart';

class _TestAuthNotifier extends AuthNotifier {
  @override
  AuthState build() {
    return const AuthState();
  }

  @override
  Future<void> register({
    required String email,
    required String password,
    String? username,
    bool rememberMe = false,
  }) async {}
}

void main() {
  group('Register Page Widget Tests', () {
    Future<void> pumpRegisterPage(WidgetTester tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            authProvider.overrideWith(_TestAuthNotifier.new),
          ],
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            locale: const Locale('en'),
            home: const RegisterPage(),
          ),
        ),
      );
      await tester.pumpAndSettle();
    }

    AppLocalizations l10nOf(WidgetTester tester) {
      return AppLocalizations.of(tester.element(find.byType(RegisterPage)))!;
    }

    testWidgets('Should display all form fields', (WidgetTester tester) async {
      await pumpRegisterPage(tester);
      final l10n = l10nOf(tester);

      // Check for all form fields
      expect(find.text(l10n.auth_full_name), findsOneWidget);
      expect(find.text(l10n.auth_email), findsOneWidget);
      expect(find.text(l10n.auth_password), findsOneWidget);
      expect(find.text(l10n.auth_confirm_password), findsOneWidget);
      expect(find.text(l10n.auth_create_account), findsWidgets);
      expect(find.text(l10n.auth_already_have_account), findsOneWidget);
      expect(find.text(l10n.auth_sign_in_link), findsOneWidget);
      expect(find.text('${l10n.auth_password}:'), findsOneWidget);
      expect(find.byType(PasswordRequirementItem), findsNWidgets(4));
    });

    testWidgets('Should validate empty form fields', (WidgetTester tester) async {
      await pumpRegisterPage(tester);
      final l10n = l10nOf(tester);

      // Try to submit empty form
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      // Should show validation errors
      expect(find.text(l10n.auth_enter_email), findsOneWidget);
      expect(find.text(l10n.auth_enter_password), findsWidgets);
    });

    testWidgets('Should validate email format', (WidgetTester tester) async {
      await pumpRegisterPage(tester);
      final l10n = l10nOf(tester);

      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_full_name),
        matching: find.byType(TextFormField),
      ), 'johndoe');

      // Enter invalid email
      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_email),
        matching: find.byType(TextFormField),
      ), 'invalid-email');

      // Try to submit
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      // Should show email error
      expect(find.text(l10n.auth_enter_valid_email), findsOneWidget);
    });

    testWidgets('Should validate password requirements', (WidgetTester tester) async {
      await pumpRegisterPage(tester);
      final l10n = l10nOf(tester);

      // Fill username and email
      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_full_name),
        matching: find.byType(TextFormField),
      ), 'johndoe');

      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_email),
        matching: find.byType(TextFormField),
      ), 'john@example.com');

      // Test weak password
      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_password),
        matching: find.byType(TextFormField),
      ), 'weak');

      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text(l10n.auth_password_too_short), findsOneWidget);

      // Test password without uppercase
      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_password),
        matching: find.byType(TextFormField),
      ), 'password123');

      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text(l10n.auth_password_requirement_uppercase), findsOneWidget);

      // Test password without lowercase
      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_password),
        matching: find.byType(TextFormField),
      ), 'PASSWORD123');

      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text(l10n.auth_password_requirement_lowercase), findsOneWidget);

      // Test password without number
      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_password),
        matching: find.byType(TextFormField),
      ), 'Password');

      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text(l10n.auth_password_requirement_number), findsOneWidget);
    });

    testWidgets('Should validate password confirmation', (WidgetTester tester) async {
      await pumpRegisterPage(tester);
      final l10n = l10nOf(tester);

      // Fill all fields with valid data except mismatched password
      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_full_name),
        matching: find.byType(TextFormField),
      ), 'johndoe');

      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_email),
        matching: find.byType(TextFormField),
      ), 'john@example.com');

      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_password),
        matching: find.byType(TextFormField),
      ), 'Password123');

      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_confirm_password),
        matching: find.byType(TextFormField),
      ), 'DifferentPassword');

      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text(l10n.auth_passwords_not_match), findsOneWidget);
    });

    testWidgets('Should show terms agreement error', (WidgetTester tester) async {
      await pumpRegisterPage(tester);
      final l10n = l10nOf(tester);

      // Fill all valid fields
      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_full_name),
        matching: find.byType(TextFormField),
      ), 'johndoe');

      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_email),
        matching: find.byType(TextFormField),
      ), 'john@example.com');

      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_password),
        matching: find.byType(TextFormField),
      ), 'Password123');

      await tester.enterText(find.ancestor(
        of: find.text(l10n.auth_confirm_password),
        matching: find.byType(TextFormField),
      ), 'Password123');

      // Don't check terms checkbox and try to submit
      await tester.tap(find.byKey(const Key('register_button')));
      await tester.pump();

      expect(find.text(l10n.auth_agree_terms), findsOneWidget);
    });

    testWidgets('Should toggle password visibility', (WidgetTester tester) async {
      await pumpRegisterPage(tester);

      // Find password visibility toggle button - it should show icons for toggle
      // Initial state should show visibility_off icons (password is obscured)
      expect(find.byIcon(Icons.visibility_off), findsNWidgets(2));

      // Toggle password visibility
      await tester.tap(find.byKey(const Key('password_visibility_toggle')));
      await tester.pump();

      // After toggle, should see visibility icon
      expect(find.byIcon(Icons.visibility), findsOneWidget);
      expect(find.byIcon(Icons.visibility_off), findsOneWidget);
    });

    testWidgets('Should display password requirements', (WidgetTester tester) async {
      await pumpRegisterPage(tester);
      final l10n = l10nOf(tester);

      // Check password requirements are displayed
      expect(find.text('${l10n.auth_password}:'), findsOneWidget);
      expect(find.text(l10n.auth_password_too_short), findsOneWidget);
      expect(find.text(l10n.auth_password_req_uppercase_short), findsOneWidget);
      expect(find.text(l10n.auth_password_req_lowercase_short), findsOneWidget);
      expect(find.text(l10n.auth_password_req_number_short), findsOneWidget);
    });
  });
}
