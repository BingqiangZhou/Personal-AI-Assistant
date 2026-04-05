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
        expect(params.fill, const Color(0x1AFFFFFF)); // white 10%
        expect(params.borderTop, const Color(0x66FFFFFF)); // white 40%
        expect(params.borderBottom, const Color(0x1AFFFFFF)); // white 10%
        expect(params.innerGlow, const Color(0x0AFFFFFF)); // white 4%
        expect(params.shadow, const Color(0x1F000000)); // black 12%
        expect(params.saturationBoost, 1.8);
        expect(params.noiseOpacity, 0.04);
        expect(params.contentScrim, const Color(0x33FFFFFF)); // white 20%
      });

      test('heavy params match spec', () {
        final params = tokens.heavy;
        expect(params.fill, const Color(0x14FFFFFF)); // white 8%
        expect(params.borderTop, const Color(0x66FFFFFF)); // white 40%
        expect(params.borderBottom, const Color(0x1AFFFFFF)); // white 10%
        expect(params.innerGlow, const Color(0x0AFFFFFF)); // white 4%
        expect(params.shadow, const Color(0x19000000)); // black 10%
        expect(params.saturationBoost, 1.8);
        expect(params.noiseOpacity, 0.03);
        expect(params.contentScrim, const Color(0x29FFFFFF)); // white 16%
      });

      test('medium params match spec', () {
        final params = tokens.medium;
        expect(params.fill, const Color(0x0FFFFFFF)); // white 6%
        expect(params.borderTop, const Color(0x66FFFFFF)); // white 40%
        expect(params.borderBottom, const Color(0x1AFFFFFF)); // white 10%
        expect(params.innerGlow, const Color(0x0AFFFFFF)); // white 4%
        expect(params.shadow, const Color(0x14000000)); // black 8%
        expect(params.saturationBoost, 1.8);
        expect(params.noiseOpacity, 0.03);
        expect(params.contentScrim, const Color(0x1FFFFFFF)); // white 12%
      });

      test('light params match spec', () {
        final params = tokens.light;
        expect(params.fill, const Color(0x0DFFFFFF)); // white 5%
        expect(params.borderTop, const Color(0x66FFFFFF)); // white 40%
        expect(params.borderBottom, const Color(0x1AFFFFFF)); // white 10%
        expect(params.innerGlow, const Color(0x0AFFFFFF)); // white 4%
        expect(params.shadow, const Color(0x0F000000)); // black 6%
        expect(params.saturationBoost, 1.8);
        expect(params.noiseOpacity, 0.03);
        expect(params.contentScrim, const Color(0x14FFFFFF)); // white 8%
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
        expect(params.fill, const Color(0x14000000)); // black 8%
        expect(params.borderTop, const Color(0x66000000)); // black 40%
        expect(params.borderBottom, const Color(0x1A000000)); // black 10%
        expect(params.innerGlow, const Color(0x0AFFFFFF)); // white 4%
        expect(params.shadow, const Color(0x1F000000)); // black 12%
        expect(params.saturationBoost, 1.8);
        expect(params.noiseOpacity, 0.04);
        expect(params.contentScrim, const Color(0x26000000)); // black 15%
      });

      test('heavy params match spec', () {
        final params = tokens.heavy;
        expect(params.fill, const Color(0x0F000000)); // black 6%
        expect(params.borderTop, const Color(0x66000000)); // black 40%
        expect(params.borderBottom, const Color(0x1A000000)); // black 10%
        expect(params.innerGlow, const Color(0x0AFFFFFF)); // white 4%
        expect(params.shadow, const Color(0x19000000)); // black 10%
        expect(params.saturationBoost, 1.8);
        expect(params.noiseOpacity, 0.03);
        expect(params.contentScrim, const Color(0x1F000000)); // black 12%
      });

      test('medium params match spec', () {
        final params = tokens.medium;
        expect(params.fill, const Color(0x0D000000)); // black 5%
        expect(params.borderTop, const Color(0x66000000)); // black 40%
        expect(params.borderBottom, const Color(0x1A000000)); // black 10%
        expect(params.innerGlow, const Color(0x0AFFFFFF)); // white 4%
        expect(params.shadow, const Color(0x14000000)); // black 8%
        expect(params.saturationBoost, 1.8);
        expect(params.noiseOpacity, 0.03);
        expect(params.contentScrim, const Color(0x14000000)); // black 8%
      });

      test('light params match spec', () {
        final params = tokens.light;
        expect(params.fill, const Color(0x08000000)); // black 3%
        expect(params.borderTop, const Color(0x66000000)); // black 40%
        expect(params.borderBottom, const Color(0x1A000000)); // black 10%
        expect(params.innerGlow, const Color(0x0AFFFFFF)); // white 4%
        expect(params.shadow, const Color(0x0F000000)); // black 6%
        expect(params.saturationBoost, 1.8);
        expect(params.noiseOpacity, 0.03);
        expect(params.contentScrim, const Color(0x0D000000)); // black 5%
      });

      test('glassFill returns medium tier fill', () {
        expect(tokens.glassFill, tokens.medium.fill);
      });
    });
  });
}
