import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/glass/glass_style.dart';
import 'package:personal_ai_assistant/core/glass/glass_tokens.dart';

void main() {
  group('GlassStyle', () {
    group('forTier factory', () {
      test('creates style for ultraHeavy tier in dark mode', () {
        final style = GlassStyle.forTier(GlassTier.ultraHeavy, Brightness.dark);

        expect(style.sigma, 30);
        expect(style.fill, const Color(0x47FFFFFF));
        expect(style.borderTop, const Color(0x5CFFFFFF));
        expect(style.borderBottom, const Color(0x40FFFFFF));
        expect(style.innerGlow, const Color(0x0AFFFFFF));
        expect(style.shadow, const Color(0x8C000000));
        expect(style.noiseOpacity, 0.06);
        expect(style.saturationBoost, 2.0);
        expect(style.contentScrim, const Color(0x4CFFFFFF));
      });

      test('creates style for heavy tier in dark mode', () {
        final style = GlassStyle.forTier(GlassTier.heavy, Brightness.dark);

        expect(style.sigma, 24);
        expect(style.fill, const Color(0x3DFFFFFF));
        expect(style.borderTop, const Color(0x52FFFFFF));
        expect(style.borderBottom, const Color(0x35FFFFFF));
        expect(style.innerGlow, const Color(0x0AFFFFFF));
        expect(style.shadow, const Color(0x73000000));
        expect(style.noiseOpacity, 0.05);
        expect(style.saturationBoost, 1.8);
        expect(style.contentScrim, const Color(0x38FFFFFF));
      });

      test('creates style for medium tier in dark mode', () {
        final style = GlassStyle.forTier(GlassTier.medium, Brightness.dark);

        expect(style.sigma, 16);
        expect(style.fill, const Color(0x2EFFFFFF));
        expect(style.borderTop, const Color(0x47FFFFFF));
        expect(style.borderBottom, const Color(0x28FFFFFF));
        expect(style.innerGlow, const Color(0x0DFFFFFF));
        expect(style.shadow, const Color(0x59000000));
        expect(style.noiseOpacity, 0.04);
        expect(style.saturationBoost, 1.5);
        expect(style.contentScrim, const Color(0x2DFFFFFF));
      });

      test('creates style for light tier in dark mode', () {
        final style = GlassStyle.forTier(GlassTier.light, Brightness.dark);

        expect(style.sigma, 10);
        expect(style.fill, const Color(0x24FFFFFF));
        expect(style.borderTop, const Color(0x40FFFFFF));
        expect(style.borderBottom, const Color(0x1EFFFFFF));
        expect(style.innerGlow, const Color(0x0FFFFFFF));
        expect(style.shadow, const Color(0x40000000));
        expect(style.noiseOpacity, 0.03);
        expect(style.saturationBoost, 1.3);
        expect(style.contentScrim, const Color(0x24FFFFFF));
      });

      test('creates style for ultraHeavy tier in light mode', () {
        final style = GlassStyle.forTier(GlassTier.ultraHeavy, Brightness.light);

        expect(style.sigma, 30);
        expect(style.fill, const Color(0x38000000));
        expect(style.borderTop, const Color(0x44000000));
        expect(style.borderBottom, const Color(0x2C000000));
        expect(style.innerGlow, const Color(0x0AFFFFFF));
        expect(style.shadow, const Color(0x1F000000));
        expect(style.noiseOpacity, 0.04);
        expect(style.saturationBoost, 1.08);
        expect(style.contentScrim, const Color(0x32000000));
      });

      test('creates style for medium tier in light mode', () {
        final style = GlassStyle.forTier(GlassTier.medium, Brightness.light);

        expect(style.sigma, 16);
        expect(style.fill, const Color(0x22000000));
        expect(style.borderTop, const Color(0x2E000000));
        expect(style.borderBottom, const Color(0x1A000000));
        expect(style.innerGlow, const Color(0x06FFFFFF));
        expect(style.shadow, const Color(0x14000000));
        expect(style.noiseOpacity, 0.03);
        expect(style.saturationBoost, 1.05);
        expect(style.contentScrim, const Color(0x1E000000));
      });
    });

    group('withHover modifier', () {
      test('increases sigma by 2', () {
        final baseStyle = GlassStyle.forTier(GlassTier.light, Brightness.dark);
        final hoverStyle = baseStyle.withHover();

        expect(hoverStyle.sigma, baseStyle.sigma + 2);
      });

      test('increases fill alpha by 3%', () {
        final baseStyle = GlassStyle.forTier(GlassTier.light, Brightness.dark);
        final hoverStyle = baseStyle.withHover();

        final baseAlpha = baseStyle.fill.alpha / 255;
        final hoverAlpha = hoverStyle.fill.alpha / 255;
        expect(hoverAlpha - baseAlpha, closeTo(0.03, 0.005));
      });

      test('scales border alpha by 1.5', () {
        final baseStyle = GlassStyle.forTier(GlassTier.light, Brightness.dark);
        final hoverStyle = baseStyle.withHover();

        final baseAlpha = baseStyle.borderTop.alpha / 255;
        final hoverAlpha = hoverStyle.borderTop.alpha / 255;
        expect(hoverAlpha / baseAlpha, closeTo(1.5, 0.01));
      });

      test('increases contentScrim alpha by 2%', () {
        final baseStyle = GlassStyle.forTier(GlassTier.light, Brightness.dark);
        final hoverStyle = baseStyle.withHover();

        final baseAlpha = baseStyle.contentScrim.alpha / 255;
        final hoverAlpha = hoverStyle.contentScrim.alpha / 255;
        expect(hoverAlpha - baseAlpha, closeTo(0.02, 0.005));
      });

      test('preserves other properties', () {
        final baseStyle = GlassStyle.forTier(GlassTier.light, Brightness.dark);
        final hoverStyle = baseStyle.withHover();

        expect(hoverStyle.innerGlow, baseStyle.innerGlow);
        expect(hoverStyle.shadow, baseStyle.shadow);
        expect(hoverStyle.noiseOpacity, baseStyle.noiseOpacity);
        expect(hoverStyle.saturationBoost, baseStyle.saturationBoost);
      });
    });

    group('withPress modifier', () {
      test('increases sigma by 4', () {
        final baseStyle = GlassStyle.forTier(GlassTier.light, Brightness.dark);
        final pressStyle = baseStyle.withPress();

        expect(pressStyle.sigma, baseStyle.sigma + 4);
      });

      test('preserves all other properties', () {
        final baseStyle = GlassStyle.forTier(GlassTier.light, Brightness.dark);
        final pressStyle = baseStyle.withPress();

        expect(pressStyle.fill, baseStyle.fill);
        expect(pressStyle.borderTop, baseStyle.borderTop);
        expect(pressStyle.borderBottom, baseStyle.borderBottom);
        expect(pressStyle.innerGlow, baseStyle.innerGlow);
        expect(pressStyle.shadow, baseStyle.shadow);
        expect(pressStyle.noiseOpacity, baseStyle.noiseOpacity);
        expect(pressStyle.saturationBoost, baseStyle.saturationBoost);
        expect(pressStyle.contentScrim, baseStyle.contentScrim);
      });
    });

    group('copyWith', () {
      test('copies with new sigma', () {
        final baseStyle = GlassStyle.forTier(GlassTier.light, Brightness.dark);
        final newStyle = baseStyle.copyWith(sigma: 99);

        expect(newStyle.sigma, 99);
        expect(newStyle.fill, baseStyle.fill);
        expect(newStyle.contentScrim, baseStyle.contentScrim);
      });

      test('copies with new fill', () {
        final baseStyle = GlassStyle.forTier(GlassTier.light, Brightness.dark);
        const newFill = Color(0x80FFFFFF);
        final newStyle = baseStyle.copyWith(fill: newFill);

        expect(newStyle.fill, newFill);
        expect(newStyle.sigma, baseStyle.sigma);
      });

      test('copies with new contentScrim', () {
        final baseStyle = GlassStyle.forTier(GlassTier.light, Brightness.dark);
        const newScrim = Color(0x40FFFFFF);
        final newStyle = baseStyle.copyWith(contentScrim: newScrim);

        expect(newStyle.contentScrim, newScrim);
        expect(newStyle.fill, baseStyle.fill);
      });

      test('copies with multiple overrides', () {
        final baseStyle = GlassStyle.forTier(GlassTier.light, Brightness.dark);
        final newStyle = baseStyle.copyWith(
          sigma: 50,
          saturationBoost: 3.0,
        );

        expect(newStyle.sigma, 50);
        expect(newStyle.saturationBoost, 3.0);
        expect(newStyle.fill, baseStyle.fill);
      });
    });

    group('equality', () {
      test('identical styles are equal', () {
        final style1 = GlassStyle.forTier(GlassTier.medium, Brightness.dark);
        final style2 = GlassStyle.forTier(GlassTier.medium, Brightness.dark);

        expect(style1, equals(style2));
      });

      test('different tiers are not equal', () {
        final style1 = GlassStyle.forTier(GlassTier.light, Brightness.dark);
        final style2 = GlassStyle.forTier(GlassTier.medium, Brightness.dark);

        expect(style1, isNot(equals(style2)));
      });

      test('different brightness are not equal', () {
        final style1 = GlassStyle.forTier(GlassTier.medium, Brightness.dark);
        final style2 = GlassStyle.forTier(GlassTier.medium, Brightness.light);

        expect(style1, isNot(equals(style2)));
      });

      test('different contentScrim are not equal', () {
        final style1 = GlassStyle.forTier(GlassTier.light, Brightness.dark);
        final style2 = style1.copyWith(contentScrim: const Color(0xFFFFFFFF));

        expect(style1, isNot(equals(style2)));
      });
    });
  });
}
