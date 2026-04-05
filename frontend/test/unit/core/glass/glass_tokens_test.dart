import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/glass/glass_tokens.dart';

void main() {
  group('GlassTier', () {
    test('has correct sigma values', () {
      expect(GlassTier.ultraHeavy.sigma, 30);
      expect(GlassTier.heavy.sigma, 24);
      expect(GlassTier.medium.sigma, 16);
      expect(GlassTier.light.sigma, 10);
    });
  });

  group('GlassTokens', () {
    group('dark mode factory', () {
      const tokens = GlassTokens.dark();

      test('has dark brightness', () {
        expect(tokens.brightness, Brightness.dark);
      });

      test('ultraHeavy params match spec', () {
        final params = tokens.ultraHeavy;
        expect(params.fill, const Color(0x47FFFFFF)); // white 28%
        expect(params.borderTop, const Color(0x5CFFFFFF)); // white 36%
        expect(params.borderBottom, const Color(0x40FFFFFF)); // white 25%
        expect(params.innerGlow, const Color(0x0AFFFFFF)); // white 4%
        expect(params.shadow, const Color(0x8C000000)); // black 55%
        expect(params.saturationBoost, 2.0);
        expect(params.noiseOpacity, 0.06);
        expect(params.contentScrim, const Color(0x4CFFFFFF)); // white 30%
      });

      test('heavy params match spec', () {
        final params = tokens.heavy;
        expect(params.fill, const Color(0x3DFFFFFF)); // white 24%
        expect(params.borderTop, const Color(0x52FFFFFF)); // white 32%
        expect(params.borderBottom, const Color(0x35FFFFFF)); // white 21%
        expect(params.innerGlow, const Color(0x0AFFFFFF)); // white 4%
        expect(params.shadow, const Color(0x73000000)); // black 45%
        expect(params.saturationBoost, 1.8);
        expect(params.noiseOpacity, 0.05);
        expect(params.contentScrim, const Color(0x38FFFFFF)); // white 22%
      });

      test('medium params match spec', () {
        final params = tokens.medium;
        expect(params.fill, const Color(0x2EFFFFFF)); // white 18%
        expect(params.borderTop, const Color(0x47FFFFFF)); // white 28%
        expect(params.borderBottom, const Color(0x28FFFFFF)); // white 16%
        expect(params.innerGlow, const Color(0x0DFFFFFF)); // white 5%
        expect(params.shadow, const Color(0x59000000)); // black 35%
        expect(params.saturationBoost, 1.5);
        expect(params.noiseOpacity, 0.04);
        expect(params.contentScrim, const Color(0x2DFFFFFF)); // white 18%
      });

      test('light params match spec', () {
        final params = tokens.light;
        expect(params.fill, const Color(0x24FFFFFF)); // white 14%
        expect(params.borderTop, const Color(0x40FFFFFF)); // white 25%
        expect(params.borderBottom, const Color(0x1EFFFFFF)); // white 12%
        expect(params.innerGlow, const Color(0x0FFFFFFF)); // white 6%
        expect(params.shadow, const Color(0x40000000)); // black 25%
        expect(params.saturationBoost, 1.3);
        expect(params.noiseOpacity, 0.03);
        expect(params.contentScrim, const Color(0x24FFFFFF)); // white 14%
      });

      test('paramsForTier returns correct params', () {
        expect(tokens.paramsForTier(GlassTier.ultraHeavy), same(tokens.ultraHeavy));
        expect(tokens.paramsForTier(GlassTier.heavy), same(tokens.heavy));
        expect(tokens.paramsForTier(GlassTier.medium), same(tokens.medium));
        expect(tokens.paramsForTier(GlassTier.light), same(tokens.light));
      });

      test('glassFill returns medium tier fill', () {
        expect(tokens.glassFill, tokens.medium.fill);
      });
    });

    group('light mode factory', () {
      const tokens = GlassTokens.light();

      test('has light brightness', () {
        expect(tokens.brightness, Brightness.light);
      });

      test('ultraHeavy params match spec', () {
        final params = tokens.ultraHeavy;
        expect(params.fill, const Color(0x38000000)); // black 22%
        expect(params.borderTop, const Color(0x44000000)); // black 27%
        expect(params.borderBottom, const Color(0x2C000000)); // black 17%
        expect(params.innerGlow, const Color(0x0AFFFFFF)); // white 4%
        expect(params.shadow, const Color(0x1F000000)); // black 12%
        expect(params.saturationBoost, 1.08);
        expect(params.noiseOpacity, 0.04);
        expect(params.contentScrim, const Color(0x32000000)); // black 20%
      });

      test('heavy params match spec', () {
        final params = tokens.heavy;
        expect(params.fill, const Color(0x2C000000)); // black 17%
        expect(params.borderTop, const Color(0x38000000)); // black 22%
        expect(params.borderBottom, const Color(0x22000000)); // black 13%
        expect(params.innerGlow, const Color(0x08FFFFFF)); // white 3%
        expect(params.shadow, const Color(0x19000000)); // black 10%
        expect(params.saturationBoost, 1.06);
        expect(params.noiseOpacity, 0.03);
        expect(params.contentScrim, const Color(0x26000000)); // black 15%
      });

      test('medium params match spec', () {
        final params = tokens.medium;
        expect(params.fill, const Color(0x22000000)); // black 13%
        expect(params.borderTop, const Color(0x2E000000)); // black 18%
        expect(params.borderBottom, const Color(0x1A000000)); // black 10%
        expect(params.innerGlow, const Color(0x06FFFFFF)); // white 2.5%
        expect(params.shadow, const Color(0x14000000)); // black 8%
        expect(params.saturationBoost, 1.05);
        expect(params.noiseOpacity, 0.03);
        expect(params.contentScrim, const Color(0x1E000000)); // black 12%
      });

      test('light params match spec', () {
        final params = tokens.light;
        expect(params.fill, const Color(0x1A000000)); // black 10%
        expect(params.borderTop, const Color(0x28000000)); // black 16%
        expect(params.borderBottom, const Color(0x13000000)); // black 7.5%
        expect(params.innerGlow, const Color(0x05FFFFFF)); // white 2%
        expect(params.shadow, const Color(0x0F000000)); // black 6%
        expect(params.saturationBoost, 1.03);
        expect(params.noiseOpacity, 0.02);
        expect(params.contentScrim, const Color(0x15000000)); // black 8%
      });

      test('glassFill returns medium tier fill', () {
        expect(tokens.glassFill, tokens.medium.fill);
      });
    });
  });
}
