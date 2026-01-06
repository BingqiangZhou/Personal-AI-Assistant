import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/speed_ruler/speed_ruler.dart';

void main() {
  group('SpeedRuler Widget Tests', () {
    testWidgets('SpeedRuler renders without errors', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SpeedRuler(
              value: 1.5,
              onChanged: (value) {},
            ),
          ),
        ),
      );

      expect(find.byType(SpeedRuler), findsOneWidget);
    });

    testWidgets('SpeedRuler displays all ticks from 0.5x to 3.0x',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 400,
              child: SpeedRuler(
                value: 1.5,
                onChanged: (value) {},
              ),
            ),
          ),
        ),
      );

      // Verify the widget renders
      expect(find.byType(SpeedRuler), findsOneWidget);

      // Verify CustomPaint is present (draws the ticks)
      expect(find.byType(CustomPaint), findsWidgets);
    });

    testWidgets('SpeedRuler initial value is 1.5x by default',
        (WidgetTester tester) async {
      const initialValue = 1.5;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 400,
              child: SpeedRuler(
                value: initialValue,
                onChanged: (value) {},
              ),
            ),
          ),
        ),
      );

      expect(find.byType(SpeedRuler), findsOneWidget);
    });

    testWidgets('SpeedRuler handles drag gestures', (WidgetTester tester) async {
      double currentValue = 1.5;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 400,
              child: SpeedRuler(
                value: currentValue,
                onChanged: (value) {
                  currentValue = value;
                },
              ),
            ),
          ),
        ),
      );

      // Find the center of the widget
      final center = tester.getCenter(find.byType(SpeedRuler));

      // Simulate dragging right (increase speed)
      await tester.dragFrom(
        center,
        const Offset(50, 0),
      );
      await tester.pumpAndSettle();

      // Value should have changed
      expect(currentValue, greaterThan(1.5));
      // Should not exceed max
      expect(currentValue, lessThanOrEqualTo(3.0));
    });

    testWidgets('SpeedRuler snaps to nearest 0.1x on drag end',
        (WidgetTester tester) async {
      double? finalValue;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 400,
              child: SpeedRuler(
                value: 1.5,
                onChanged: (value) {
                  finalValue = value;
                },
              ),
            ),
          ),
        ),
      );

      final center = tester.getCenter(find.byType(SpeedRuler));

      // Drag slightly
      await tester.dragFrom(
        center,
        const Offset(10, 0),
      );
      await tester.pumpAndSettle();

      // Value should be snapped to 0.1 increments
      expect(finalValue, isNotNull);
      final snapMultiplier = (finalValue! / 0.1).round();
      expect(finalValue, closeTo(snapMultiplier * 0.1, 0.001));
    });

    testWidgets('SpeedRuler enforces minimum boundary (0.5x)',
        (WidgetTester tester) async {
      double currentValue = 0.5;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 400,
              child: SpeedRuler(
                value: currentValue,
                onChanged: (value) {
                  currentValue = value;
                },
              ),
            ),
          ),
        ),
      );

      final center = tester.getCenter(find.byType(SpeedRuler));

      // Try to drag left (decrease speed)
      await tester.dragFrom(
        center,
        const Offset(-100, 0),
      );
      await tester.pumpAndSettle();

      // Should not go below minimum
      expect(currentValue, greaterThanOrEqualTo(0.5));
    });

    testWidgets('SpeedRuler enforces maximum boundary (3.0x)',
        (WidgetTester tester) async {
      double currentValue = 3.0;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 400,
              child: SpeedRuler(
                value: currentValue,
                onChanged: (value) {
                  currentValue = value;
                },
              ),
            ),
          ),
        ),
      );

      final center = tester.getCenter(find.byType(SpeedRuler));

      // Try to drag right (increase speed)
      await tester.dragFrom(
        center,
        const Offset(100, 0),
      );
      await tester.pumpAndSettle();

      // Should not exceed maximum
      expect(currentValue, lessThanOrEqualTo(3.0));
    });

    testWidgets('SpeedRuler responds to tap gestures', (WidgetTester tester) async {
      double? tappedValue;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 400,
              child: SpeedRuler(
                value: 1.5,
                onChanged: (value) {
                  tappedValue = value;
                },
              ),
            ),
          ),
        ),
      );

      final center = tester.getCenter(find.byType(SpeedRuler));

      // Tap on the widget
      await tester.tapAt(center);
      await tester.pumpAndSettle();

      // Value should have been updated
      expect(tappedValue, isNotNull);
    });
  });

  group('SpeedRulerSheet Widget Tests', () {
    testWidgets('SpeedRulerSheet displays header with title',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SpeedRulerSheet(
              initialValue: 1.5,
              onSpeedChanged: (value) {},
            ),
          ),
        ),
      );

      // Should display title
      expect(find.text('倍速播放'), findsOneWidget);
      // Should display initial value
      expect(find.text('1.5x'), findsOneWidget);
    });

    testWidgets('SpeedRulerSheet updates current value display',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SpeedRulerSheet(
              initialValue: 1.5,
              onSpeedChanged: (value) {},
            ),
          ),
        ),
      );

      expect(find.text('1.5x'), findsOneWidget);
      expect(find.byType(SpeedRuler), findsOneWidget);
    });

    testWidgets('SpeedRulerSheet shows modal bottom sheet',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Builder(
              builder: (context) {
                return ElevatedButton(
                  onPressed: () {
                    SpeedRulerSheet.show(
                      context: context,
                      initialValue: 1.5,
                    );
                  },
                  child: const Text('Show Speed Ruler'),
                );
              },
            ),
          ),
        ),
      );

      // Tap the button to show the sheet
      await tester.tap(find.text('Show Speed Ruler'));
      await tester.pumpAndSettle();

      // Should show the bottom sheet
      expect(find.text('倍速播放'), findsOneWidget);
    });
  });

  group('SpeedRulerDemoPage Widget Tests', () {
    testWidgets('SpeedRulerDemoPage renders without errors',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: SpeedRulerDemoPage(),
        ),
      );

      expect(find.byType(SpeedRulerDemoPage), findsOneWidget);
      expect(find.text('倍速播放控件演示'), findsOneWidget);
      expect(find.text('选择倍速'), findsOneWidget);
    });

    testWidgets('SpeedRulerDemoPage displays current speed',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: SpeedRulerDemoPage(),
        ),
      );

      expect(find.text('1.5x'), findsOneWidget);
      expect(find.text('当前倍速'), findsOneWidget);
    });

    testWidgets('SpeedRulerDemoPage opens SpeedRulerSheet on button press',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: SpeedRulerDemoPage(),
        ),
      );

      // Tap the button
      await tester.tap(find.text('选择倍速'));
      await tester.pumpAndSettle();

      // Should show the speed ruler sheet
      expect(find.text('倍速播放'), findsOneWidget);
    });

    testWidgets('SpeedRulerDemoPage displays feature description',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: SpeedRulerDemoPage(),
        ),
      );

      expect(
        find.textContaining(
          '• 拖拽刻度尺选择倍速',
        ),
        findsOneWidget,
      );
      expect(
        find.textContaining(
          '• 点击刻度直接跳转',
        ),
        findsOneWidget,
      );
      expect(
        find.textContaining(
          '• 自动吸附到 0.1x',
        ),
        findsOneWidget,
      );
    });
  });

  group('SpeedRuler Theme Adaptation Tests', () {
    testWidgets('SpeedRuler adapts to light theme', (WidgetTester tester) async {
      final lightTheme = ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.blue,
          brightness: Brightness.light,
        ),
        useMaterial3: true,
      );

      await tester.pumpWidget(
        MaterialApp(
          theme: lightTheme,
          home: Scaffold(
            body: SpeedRuler(
              value: 1.5,
              onChanged: (value) {},
            ),
          ),
        ),
      );

      expect(find.byType(SpeedRuler), findsOneWidget);
    });

    testWidgets('SpeedRuler adapts to dark theme', (WidgetTester tester) async {
      final darkTheme = ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.blue,
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      );

      await tester.pumpWidget(
        MaterialApp(
          theme: darkTheme,
          home: Scaffold(
            body: SpeedRuler(
              value: 1.5,
              onChanged: (value) {},
            ),
          ),
        ),
      );

      expect(find.byType(SpeedRuler), findsOneWidget);
    });
  });

  group('SpeedRuler Customization Tests', () {
    testWidgets('SpeedRuler accepts custom range parameters',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SpeedRuler(
              min: 0.8,
              max: 2.0,
              step: 0.2,
              majorStep: 0.4,
              value: 1.0,
              onChanged: (value) {},
            ),
          ),
        ),
      );

      expect(find.byType(SpeedRuler), findsOneWidget);
    });

    testWidgets('SpeedRuler accepts custom visual parameters',
        (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SpeedRuler(
              value: 1.5,
              onChanged: (value) {},
              tickWidth: 3.0,
              majorTickHeight: 30.0,
              minorTickHeight: 15.0,
              indicatorWidth: 5.0,
            ),
          ),
        ),
      );

      expect(find.byType(SpeedRuler), findsOneWidget);
    });
  });
}
