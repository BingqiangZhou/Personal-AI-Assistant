import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/theme/apple_colors.dart';

void main() {
  group('AppleColors', () {
    group('Label Colors', () {
      test('provides correct label colors for light mode', () {
        expect(AppleColors.label.light, const Color(0xFF000000));
        expect(AppleColors.secondaryLabel.light, const Color(0xFF3C3C43));
        expect(AppleColors.tertiaryLabel.light, const Color(0xFF3C3C43));
      });

      test('provides correct label colors for dark mode', () {
        expect(AppleColors.label.dark, const Color(0xFFFFFFFF));
        expect(AppleColors.secondaryLabel.dark, const Color(0xFFEBEBF5));
        expect(AppleColors.tertiaryLabel.dark, const Color(0xFFEBEBF5));
      });

      testWidgets('of() returns correct label color - light mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData(brightness: Brightness.light),
            home: Builder(
              builder: (context) {
                expect(AppleColors.label.of(context), const Color(0xFF000000));
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('of() returns correct label color - dark mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData(brightness: Brightness.dark),
            home: Builder(
              builder: (context) {
                expect(AppleColors.label.of(context), const Color(0xFFFFFFFF));
                return const SizedBox();
              },
            ),
          ),
        );
      });
    });

    group('Background Colors', () {
      test('provides correct background colors for light mode', () {
        expect(
          AppleColors.systemGroupedBackground.light,
          const Color(0xFFF2F2F7),
        );
        expect(
          AppleColors.secondarySystemGroupedBackground.light,
          const Color(0xFFFFFFFF),
        );
        expect(
          AppleColors.tertiarySystemGroupedBackground.light,
          const Color(0xFFF2F2F7),
        );
      });

      test('provides correct background colors for dark mode', () {
        expect(
          AppleColors.systemGroupedBackground.dark,
          const Color(0xFF000000),
        );
        expect(
          AppleColors.secondarySystemGroupedBackground.dark,
          const Color(0xFF1C1C1E),
        );
        expect(
          AppleColors.tertiarySystemGroupedBackground.dark,
          const Color(0xFF2C2C2E),
        );
      });
    });

    group('Fill Colors', () {
      test('provides correct fill base colors', () {
        expect(AppleColors.systemFill.light, const Color(0xFF787880));
        expect(AppleColors.secondarySystemFill.light, const Color(0xFF787880));
        expect(AppleColors.tertiarySystemFill.light, const Color(0xFF767680));
      });

      testWidgets('of() applies correct alpha for fill colors in light mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData(brightness: Brightness.light),
            home: Builder(
              builder: (context) {
                final color = AppleColors.systemFill.of(context);
                expect(color.alpha, 51); // 20% of 255 ≈ 51
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('of() applies correct alpha for fill colors in dark mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData(brightness: Brightness.dark),
            home: Builder(
              builder: (context) {
                final color = AppleColors.systemFill.of(context);
                expect(color.alpha, 92); // 36% of 255 ≈ 92
                return const SizedBox();
              },
            ),
          ),
        );
      });
    });

    group('Separator Colors', () {
      test('provides correct separator base colors', () {
        expect(AppleColors.separator.light, const Color(0xFF3C3C43));
        expect(AppleColors.separator.dark, const Color(0xFF545458));
      });

      testWidgets('of() applies correct alpha for separator',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData(brightness: Brightness.light),
            home: Builder(
              builder: (context) {
                final color = AppleColors.separator.of(context);
                expect(color.alpha, 74); // 29% of 255 ≈ 74
                return const SizedBox();
              },
            ),
          ),
        );
      });
    });

    group('System Tint Colors', () {
      test('provides correct system tint colors for light mode', () {
        expect(AppleColors.systemBlue.light, const Color(0xFF007AFF));
        expect(AppleColors.systemGreen.light, const Color(0xFF34C759));
        expect(AppleColors.systemIndigo.light, const Color(0xFF5856D6));
        expect(AppleColors.systemOrange.light, const Color(0xFFFF9500));
        expect(AppleColors.systemPink.light, const Color(0xFFFF2D55));
        expect(AppleColors.systemPurple.light, const Color(0xFFAF52DE));
        expect(AppleColors.systemRed.light, const Color(0xFFFF3B30));
        expect(AppleColors.systemYellow.light, const Color(0xFFFFCC00));
        expect(AppleColors.systemTeal.light, const Color(0xFF5AC8FA));
      });

      test('provides correct system tint colors for dark mode', () {
        expect(AppleColors.systemBlue.dark, const Color(0xFF0A84FF));
        expect(AppleColors.systemGreen.dark, const Color(0xFF30D158));
        expect(AppleColors.systemIndigo.dark, const Color(0xFF5E5CE6));
        expect(AppleColors.systemOrange.dark, const Color(0xFFFF9F0A));
        expect(AppleColors.systemPink.dark, const Color(0xFFFF375F));
        expect(AppleColors.systemPurple.dark, const Color(0xFFBF5AF2));
        expect(AppleColors.systemRed.dark, const Color(0xFFFF453A));
        expect(AppleColors.systemYellow.dark, const Color(0xFFFFD60A));
        expect(AppleColors.systemTeal.dark, const Color(0xFF64D2FF));
      });
    });

    group('of() method', () {
      testWidgets('returns secondaryLabel with correct alpha',
          (WidgetTester tester) async {
        // Light mode - 60% opacity
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData(brightness: Brightness.light),
            home: Builder(
              builder: (context) {
                final color = AppleColors.secondaryLabel.of(context);
                expect(color.alpha, 153); // 0.6 * 255 = 153
                return const SizedBox();
              },
            ),
          ),
        );

        // Dark mode - 60% opacity
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData(brightness: Brightness.dark),
            home: Builder(
              builder: (context) {
                final color = AppleColors.secondaryLabel.of(context);
                expect(color.alpha, 153); // 0.6 * 255 = 153
                return const SizedBox();
              },
            ),
          ),
        );
      });
    });
  });
}
