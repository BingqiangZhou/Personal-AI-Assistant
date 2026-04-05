import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/theme/apple_colors.dart';

void main() {
  group('AppleColors', () {
    group('Label Colors', () {
      test('label has correct light/dark base colors', () {
        expect(AppleColors.label.light, const Color(0xFF000000));
        expect(AppleColors.label.dark, const Color(0xFFFFFFFF));
      });

      test('label has full alpha', () {
        expect(AppleColors.label.lightAlpha, 1.0);
        expect(AppleColors.label.darkAlpha, 1.0);
      });
    });

    group('Fill Colors', () {
      test('systemFill has correct base and alpha values', () {
        expect(AppleColors.systemFill.light, const Color(0xFF787880));
        expect(AppleColors.systemFill.dark, const Color(0xFF787880));
        expect(AppleColors.systemFill.lightAlpha, 0.2);
        expect(AppleColors.systemFill.darkAlpha, 0.36);
      });

      test('secondarySystemFill has correct alpha values', () {
        expect(AppleColors.secondarySystemFill.lightAlpha, 0.16);
        expect(AppleColors.secondarySystemFill.darkAlpha, 0.32);
      });

      test('tertiarySystemFill has correct alpha values', () {
        expect(AppleColors.tertiarySystemFill.lightAlpha, 0.12);
        expect(AppleColors.tertiarySystemFill.darkAlpha, 0.24);
      });
    });

    group('Separator Color', () {
      test('separator has correct base and alpha values', () {
        expect(AppleColors.separator.light, const Color(0xFF3C3C43));
        expect(AppleColors.separator.dark, const Color(0xFF545458));
        expect(AppleColors.separator.lightAlpha, closeTo(0.29, 0.01));
        expect(AppleColors.separator.darkAlpha, 0.6);
      });
    });

    group('System Tint Colors - Light Mode', () {
      test('all system tint light values are correct', () {
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
    });

    group('System Tint Colors - Dark Mode', () {
      test('all system tint dark values are correct', () {
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

    group('Static Color Getters', () {
      test('provides correct light/dark getter pairs', () {
        expect(AppleColors.systemIndigoLight, const Color(0xFF5856D6));
        expect(AppleColors.systemIndigoDark, const Color(0xFF5E5CE6));
        expect(AppleColors.systemOrangeLight, const Color(0xFFFF9500));
        expect(AppleColors.systemOrangeDark, const Color(0xFFFF9F0A));
        expect(AppleColors.systemPinkLight, const Color(0xFFFF2D55));
        expect(AppleColors.systemPinkDark, const Color(0xFFFF375F));
        expect(AppleColors.systemRedLight, const Color(0xFFFF3B30));
        expect(AppleColors.systemRedDark, const Color(0xFFFF453A));
        expect(AppleColors.systemGreenLight, const Color(0xFF34C759));
        expect(AppleColors.systemGreenDark, const Color(0xFF30D158));
        expect(AppleColors.systemBlueLight, const Color(0xFF007AFF));
        expect(AppleColors.systemBlueDark, const Color(0xFF0A84FF));
      });
    });
  });
}
