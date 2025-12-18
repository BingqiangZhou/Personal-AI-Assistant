// This is a basic Flutter widget test.
// To perform an interaction with a widget in your test, use the WidgetTester utility.
// Comprehensive individual test files will be created separately.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/main.dart';

void main() {
  testWidgets('App starts with splash screen', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    await tester.pumpWidget(const MyApp());

    // Verify that splash screen shows.
    expect(find.text('Personal AI Assistant'), findsOneWidget);
  });
}
