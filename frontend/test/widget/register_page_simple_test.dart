import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import 'package:personal_ai_assistant/features/auth/presentation/pages/register_page.dart';
import 'package:personal_ai_assistant/shared/widgets/custom_text_field.dart';

void main() {
  group('Register Page Widget Tests (Simple)', () {
    testWidgets('Should display all form fields', (WidgetTester tester) async {
      // Set a larger surface size for the test
      tester.binding.window.physicalSizeTestValue = const Size(800, 1200);
      tester.binding.window.devicePixelRatioTestValue = 1.0;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Check for all form fields
      expect(find.text('Username'), findsOneWidget);
      expect(find.text('Email'), findsOneWidget);
      expect(find.text('Password'), findsOneWidget);
      expect(find.text('Confirm Password'), findsOneWidget);
      expect(find.text('Create Account'), findsAtLeastNWidgets(1));
      expect(find.text('Password Requirements:'), findsOneWidget);
    });

    testWidgets('Should validate empty form fields', (WidgetTester tester) async {
      // Set a larger surface size for the test
      tester.binding.window.physicalSizeTestValue = const Size(800, 1200);
      tester.binding.window.devicePixelRatioTestValue = 1.0;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Try to submit empty form
      await tester.tap(find.byKey(Key('register_button')));
      await tester.pump();

      // Should show validation errors
      expect(find.text('Please enter your email'), findsOneWidget);
      expect(find.text('Please enter your password'), findsOneWidget);
      expect(find.text('Please confirm your password'), findsOneWidget);
    });

    testWidgets('Should validate email format', (WidgetTester tester) async {
      // Set a larger surface size for the test
      tester.binding.window.physicalSizeTestValue = const Size(800, 1200);
      tester.binding.window.devicePixelRatioTestValue = 1.0;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Fill username field (required)
      await tester.enterText(find.ancestor(
        of: find.text('Username'),
        matching: find.byType(CustomTextField),
      ).first, 'johndoe');

      // Enter invalid email
      await tester.enterText(find.ancestor(
        of: find.text('Email'),
        matching: find.byType(CustomTextField),
      ).first, 'invalid-email');

      // Try to submit
      await tester.tap(find.byKey(Key('register_button')));
      await tester.pump();

      // Should show email error
      expect(find.text('Please enter a valid email'), findsOneWidget);
    });

    testWidgets('Should validate password requirements', (WidgetTester tester) async {
      // Set a larger surface size for the test
      tester.binding.window.physicalSizeTestValue = const Size(800, 1200);
      tester.binding.window.devicePixelRatioTestValue = 1.0;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Fill username and email
      await tester.enterText(find.ancestor(
        of: find.text('Username'),
        matching: find.byType(CustomTextField),
      ).first, 'johndoe');

      await tester.enterText(find.ancestor(
        of: find.text('Email'),
        matching: find.byType(CustomTextField),
      ).first, 'john@example.com');

      // Test weak password
      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(CustomTextField),
      ).first, 'weak');

      await tester.tap(find.byKey(Key('register_button')));
      await tester.pump();

      expect(find.text('Password must be at least 8 characters'), findsOneWidget);

      // Test password without uppercase
      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(CustomTextField),
      ).first, 'password123');

      await tester.tap(find.byKey(Key('register_button')));
      await tester.pump();

      expect(find.text('Password must contain at least one uppercase letter (A-Z)'), findsOneWidget);

      // Test password without lowercase
      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(CustomTextField),
      ).first, 'PASSWORD123');

      await tester.tap(find.byKey(Key('register_button')));
      await tester.pump();

      expect(find.text('Password must contain at least one lowercase letter (a-z)'), findsOneWidget);

      // Test password without number
      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(CustomTextField),
      ).first, 'Password');

      await tester.tap(find.byKey(Key('register_button')));
      await tester.pump();

      expect(find.text('Password must contain at least one number (0-9)'), findsOneWidget);
    });

    testWidgets('Should validate password confirmation', (WidgetTester tester) async {
      // Set a larger surface size for the test
      tester.binding.window.physicalSizeTestValue = const Size(800, 1200);
      tester.binding.window.devicePixelRatioTestValue = 1.0;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Fill all fields with valid data except mismatched password
      await tester.enterText(find.ancestor(
        of: find.text('Username'),
        matching: find.byType(CustomTextField),
      ).first, 'johndoe');

      await tester.enterText(find.ancestor(
        of: find.text('Email'),
        matching: find.byType(CustomTextField),
      ).first, 'john@example.com');

      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(CustomTextField),
      ).first, 'Password123');

      await tester.enterText(find.ancestor(
        of: find.text('Confirm Password'),
        matching: find.byType(CustomTextField),
      ).first, 'DifferentPassword');

      await tester.tap(find.byKey(Key('register_button')));
      await tester.pump();

      expect(find.text('Passwords do not match'), findsOneWidget);
    });

    testWidgets('Should show terms agreement error', (WidgetTester tester) async {
      // Set a larger surface size for the test
      tester.binding.window.physicalSizeTestValue = const Size(800, 1200);
      tester.binding.window.devicePixelRatioTestValue = 1.0;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Fill all valid fields
      await tester.enterText(find.ancestor(
        of: find.text('Username'),
        matching: find.byType(CustomTextField),
      ).first, 'johndoe');

      await tester.enterText(find.ancestor(
        of: find.text('Email'),
        matching: find.byType(CustomTextField),
      ).first, 'john@example.com');

      await tester.enterText(find.ancestor(
        of: find.text('Password'),
        matching: find.byType(CustomTextField),
      ).first, 'Password123');

      await tester.enterText(find.ancestor(
        of: find.text('Confirm Password'),
        matching: find.byType(CustomTextField),
      ).first, 'Password123');

      // Don't check terms checkbox and try to submit
      await tester.tap(find.byKey(Key('register_button')));
      await tester.pump();

      // Should show snackbar
      expect(find.text('Please agree to the terms and conditions'), findsOneWidget);
    });

    testWidgets('Should toggle password visibility', (WidgetTester tester) async {
      // Set a larger surface size for the test
      tester.binding.window.physicalSizeTestValue = const Size(800, 1200);
      tester.binding.window.devicePixelRatioTestValue = 1.0;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Find password visibility toggle button
      final passwordVisibilityToggle = find.byKey(Key('password_visibility_toggle'));

      // Verify toggle button exists
      expect(passwordVisibilityToggle, findsOneWidget);

      // Toggle password visibility
      await tester.tap(passwordVisibilityToggle);
      await tester.pump();

      // Toggle back
      await tester.tap(passwordVisibilityToggle);
      await tester.pump();
    });

    testWidgets('Should display password requirements', (WidgetTester tester) async {
      // Set a larger surface size for the test
      tester.binding.window.physicalSizeTestValue = const Size(800, 1200);
      tester.binding.window.devicePixelRatioTestValue = 1.0;

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: RegisterPage(),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Check password requirements are displayed
      expect(find.text('Password Requirements:'), findsOneWidget);
      expect(find.text('At least 8 characters'), findsOneWidget);
      expect(find.text('One uppercase letter (A-Z)'), findsOneWidget);
      expect(find.text('One lowercase letter (a-z)'), findsOneWidget);
      expect(find.text('One number (0-9)'), findsOneWidget);
    });
  });
}