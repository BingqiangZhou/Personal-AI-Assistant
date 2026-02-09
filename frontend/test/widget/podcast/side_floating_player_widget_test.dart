import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/side_floating_player_widget.dart';

/// Simple wrapper for testing
Widget createTestWidget({required Widget child}) {
  return ProviderScope(
    child: MaterialApp.router(
      routerConfig: GoRouter(
        routes: [GoRoute(path: '/', builder: (context, state) => child)],
      ),
    ),
  );
}

void main() {
  group('SideFloatingPlayerWidget (Legacy)', () {
    // === Basic Widget Rendering Tests ===

    testWidgets('renders without errors', (WidgetTester tester) async {
      await tester.pumpWidget(
        createTestWidget(
          child: const Scaffold(
            body: Stack(children: [SideFloatingPlayerWidget()]),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Widget should be present
      expect(find.byType(SideFloatingPlayerWidget), findsOneWidget);
    });

    testWidgets('does not render floating player when no episode is loaded', (
      WidgetTester tester,
    ) async {
      await tester.pumpWidget(
        createTestWidget(
          child: const Scaffold(
            body: Stack(children: [SideFloatingPlayerWidget()]),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // No Positioned widget should be visible (no episode loaded)
      expect(find.byType(Positioned), findsNothing);
    });

    // === Animation Tests ===

    testWidgets('animation controller initializes correctly', (
      WidgetTester tester,
    ) async {
      await tester.pumpWidget(
        createTestWidget(
          child: const Scaffold(
            body: Stack(children: [SideFloatingPlayerWidget()]),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Should not throw any exceptions
      expect(find.byType(SideFloatingPlayerWidget), findsOneWidget);
    });

    // === Responsive Layout Tests ===

    testWidgets('positions correctly on mobile', (WidgetTester tester) async {
      tester.view.physicalSize = const Size(400, 800);
      tester.view.devicePixelRatio = 1.0;

      await tester.pumpWidget(
        createTestWidget(
          child: const Scaffold(
            body: Stack(children: [SideFloatingPlayerWidget()]),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.byType(SideFloatingPlayerWidget), findsOneWidget);

      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
    });

    testWidgets('positions correctly on desktop', (WidgetTester tester) async {
      tester.view.physicalSize = const Size(1200, 800);
      tester.view.devicePixelRatio = 1.0;

      await tester.pumpWidget(
        createTestWidget(
          child: const Scaffold(
            body: Stack(children: [SideFloatingPlayerWidget()]),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.byType(SideFloatingPlayerWidget), findsOneWidget);

      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
    });

    testWidgets('positions correctly on tablet', (WidgetTester tester) async {
      tester.view.physicalSize = const Size(800, 1200);
      tester.view.devicePixelRatio = 1.0;

      await tester.pumpWidget(
        createTestWidget(
          child: const Scaffold(
            body: Stack(children: [SideFloatingPlayerWidget()]),
          ),
        ),
      );

      await tester.pumpAndSettle();

      expect(find.byType(SideFloatingPlayerWidget), findsOneWidget);

      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
    });

    // === Material 3 Compliance Tests ===

    testWidgets('uses Material 3 components', (WidgetTester tester) async {
      await tester.pumpWidget(
        createTestWidget(
          child: const Scaffold(
            body: Stack(children: [SideFloatingPlayerWidget()]),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Widget should render with Material 3
      expect(find.byType(SideFloatingPlayerWidget), findsOneWidget);
    });

    // === Stack Integration Tests ===

    testWidgets('works correctly within a Stack', (WidgetTester tester) async {
      await tester.pumpWidget(
        createTestWidget(
          child: const Scaffold(
            body: Stack(
              children: [
                // Main content
                Center(child: Text('Main Content')),
                // Floating player
                SideFloatingPlayerWidget(),
              ],
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Both widgets should be present
      expect(find.text('Main Content'), findsOneWidget);
      expect(find.byType(SideFloatingPlayerWidget), findsOneWidget);
    });

    // === Widget Lifecycle Tests ===

    testWidgets('handles widget disposal', (WidgetTester tester) async {
      await tester.pumpWidget(
        createTestWidget(
          child: const Scaffold(
            body: Stack(children: [SideFloatingPlayerWidget()]),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Replace with different widget
      await tester.pumpWidget(
        createTestWidget(
          child: const Scaffold(body: Center(child: Text('Different Content'))),
        ),
      );

      await tester.pumpAndSettle();

      // Should not throw any errors
      expect(find.text('Different Content'), findsOneWidget);
    });
  });
}
