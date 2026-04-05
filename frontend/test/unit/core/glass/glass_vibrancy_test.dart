import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/glass/glass_tokens.dart';
import 'package:personal_ai_assistant/core/glass/glass_vibrancy.dart';

void main() {
  group('GlassVibrancy', () {
    group('primaryText', () {
      testWidgets('returns black in light mode regardless of tier',
          (WidgetTester tester) async {
        for (final tier in GlassTier.values) {
          await tester.pumpWidget(
            MaterialApp(
              theme: ThemeData.light(),
              home: Builder(
                builder: (context) {
                  final color = GlassVibrancy.primaryText(context, tier: tier);
                  expect(color, const Color(0xFF000000));
                  return const SizedBox();
                },
              ),
            ),
          );
        }
      });

      testWidgets('returns white in dark mode regardless of tier',
          (WidgetTester tester) async {
        for (final tier in GlassTier.values) {
          await tester.pumpWidget(
            MaterialApp(
              theme: ThemeData.dark(),
              home: Builder(
                builder: (context) {
                  final color = GlassVibrancy.primaryText(context, tier: tier);
                  expect(color, const Color(0xFFFFFFFF));
                  return const SizedBox();
                },
              ),
            ),
          );
        }
      });

      testWidgets('always has full opacity', (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.dark(),
            home: Builder(
              builder: (context) {
                for (final tier in GlassTier.values) {
                  final color = GlassVibrancy.primaryText(context, tier: tier);
                  expect(color.alpha, 255);
                }
                return const SizedBox();
              },
            ),
          ),
        );
      });
    });

    group('secondaryText', () {
      testWidgets('returns correct base color in light mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.light(),
            home: Builder(
              builder: (context) {
                final color = GlassVibrancy.secondaryText(
                  context,
                  tier: GlassTier.medium,
                );
                // Base color is #3C3C43
                expect(color.red, equals(0x3C));
                expect(color.green, equals(0x3C));
                expect(color.blue, equals(0x43));
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('returns correct base color in dark mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.dark(),
            home: Builder(
              builder: (context) {
                final color = GlassVibrancy.secondaryText(
                  context,
                  tier: GlassTier.medium,
                );
                // Base color is #EBEBF5
                expect(color.red, equals(0xEB));
                expect(color.green, equals(0xEB));
                expect(color.blue, equals(0xF5));
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('applies 60% base alpha on heavy/ultraHeavy tiers in light mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.light(),
            home: Builder(
              builder: (context) {
                final heavyColor =
                    GlassVibrancy.secondaryText(context, tier: GlassTier.heavy);
                final ultraHeavyColor = GlassVibrancy.secondaryText(
                  context,
                  tier: GlassTier.ultraHeavy,
                );
                // 60% of 255 = 153
                expect(heavyColor.alpha, 153);
                expect(ultraHeavyColor.alpha, 153);
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('boosts alpha to 70% on medium tier in light mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.light(),
            home: Builder(
              builder: (context) {
                final color = GlassVibrancy.secondaryText(
                  context,
                  tier: GlassTier.medium,
                );
                // (0.6 + 0.1) * 255 = 178.5 ≈ 179
                expect(color.alpha, 179);
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('boosts alpha to 75% on light tier in light mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.light(),
            home: Builder(
              builder: (context) {
                final color = GlassVibrancy.secondaryText(
                  context,
                  tier: GlassTier.light,
                );
                // (0.6 + 0.15) * 255 = 191.25 ≈ 191
                expect(color.alpha, 191);
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('applies 60% base alpha on heavy/ultraHeavy tiers in dark mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.dark(),
            home: Builder(
              builder: (context) {
                final heavyColor =
                    GlassVibrancy.secondaryText(context, tier: GlassTier.heavy);
                final ultraHeavyColor = GlassVibrancy.secondaryText(
                  context,
                  tier: GlassTier.ultraHeavy,
                );
                // 60% of 255 = 153
                expect(heavyColor.alpha, 153);
                expect(ultraHeavyColor.alpha, 153);
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('boosts alpha to 70% on medium tier in dark mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.dark(),
            home: Builder(
              builder: (context) {
                final color = GlassVibrancy.secondaryText(
                  context,
                  tier: GlassTier.medium,
                );
                // (0.6 + 0.1) * 255 = 178.5 ≈ 179
                expect(color.alpha, 179);
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('boosts alpha to 75% on light tier in dark mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.dark(),
            home: Builder(
              builder: (context) {
                final color = GlassVibrancy.secondaryText(
                  context,
                  tier: GlassTier.light,
                );
                // (0.6 + 0.15) * 255 = 191.25 ≈ 191
                expect(color.alpha, 191);
                return const SizedBox();
              },
            ),
          ),
        );
      });
    });

    group('tertiaryText', () {
      testWidgets('returns correct base color in light mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.light(),
            home: Builder(
              builder: (context) {
                final color = GlassVibrancy.tertiaryText(
                  context,
                  tier: GlassTier.medium,
                );
                // Base color is #3C3C43
                expect(color.red, equals(0x3C));
                expect(color.green, equals(0x3C));
                expect(color.blue, equals(0x43));
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('returns correct base color in dark mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.dark(),
            home: Builder(
              builder: (context) {
                final color = GlassVibrancy.tertiaryText(
                  context,
                  tier: GlassTier.medium,
                );
                // Base color is #EBEBF5
                expect(color.red, equals(0xEB));
                expect(color.green, equals(0xEB));
                expect(color.blue, equals(0xF5));
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('applies 30% base alpha on heavy/ultraHeavy tiers in light mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.light(),
            home: Builder(
              builder: (context) {
                final heavyColor =
                    GlassVibrancy.tertiaryText(context, tier: GlassTier.heavy);
                final ultraHeavyColor = GlassVibrancy.tertiaryText(
                  context,
                  tier: GlassTier.ultraHeavy,
                );
                // 30% of 255 = 76.5 ≈ 77
                expect(heavyColor.alpha, 77);
                expect(ultraHeavyColor.alpha, 77);
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('boosts alpha to 45% on medium tier in light mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.light(),
            home: Builder(
              builder: (context) {
                final color = GlassVibrancy.tertiaryText(
                  context,
                  tier: GlassTier.medium,
                );
                // (0.3 + 0.15) * 255 = 114.75 ≈ 115
                expect(color.alpha, 115);
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('boosts alpha to 45% on light tier in light mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.light(),
            home: Builder(
              builder: (context) {
                final color = GlassVibrancy.tertiaryText(
                  context,
                  tier: GlassTier.light,
                );
                // (0.3 + 0.15) * 255 = 114.75 ≈ 115
                expect(color.alpha, 115);
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('applies 30% base alpha on heavy/ultraHeavy tiers in dark mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.dark(),
            home: Builder(
              builder: (context) {
                final heavyColor =
                    GlassVibrancy.tertiaryText(context, tier: GlassTier.heavy);
                final ultraHeavyColor = GlassVibrancy.tertiaryText(
                  context,
                  tier: GlassTier.ultraHeavy,
                );
                // 30% of 255 = 76.5 ≈ 77
                expect(heavyColor.alpha, 77);
                expect(ultraHeavyColor.alpha, 77);
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('boosts alpha to 45% on medium tier in dark mode',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.dark(),
            home: Builder(
              builder: (context) {
                final color = GlassVibrancy.tertiaryText(
                  context,
                  tier: GlassTier.medium,
                );
                // (0.3 + 0.15) * 255 = 114.75 ≈ 115
                expect(color.alpha, 115);
                return const SizedBox();
              },
            ),
          ),
        );
      });
    });

    group('Alpha progression across tiers', () {
      testWidgets('secondaryText alpha increases from light to ultraHeavy',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.light(),
            home: Builder(
              builder: (context) {
                final lightAlpha =
                    GlassVibrancy.secondaryText(context, tier: GlassTier.light).alpha;
                final mediumAlpha = GlassVibrancy.secondaryText(
                  context,
                  tier: GlassTier.medium,
                ).alpha;
                final heavyAlpha =
                    GlassVibrancy.secondaryText(context, tier: GlassTier.heavy).alpha;
                final ultraHeavyAlpha = GlassVibrancy.secondaryText(
                  context,
                  tier: GlassTier.ultraHeavy,
                ).alpha;

                // Light tier should have highest alpha (most boosted)
                expect(lightAlpha, greaterThan(mediumAlpha));
                // Medium should be higher than heavy (boosted)
                expect(mediumAlpha, greaterThan(heavyAlpha));
                // Heavy and ultraHeavy should be the same (base alpha)
                expect(heavyAlpha, equals(ultraHeavyAlpha));
                return const SizedBox();
              },
            ),
          ),
        );
      });

      testWidgets('tertiaryText alpha is highest on light/medium tiers',
          (WidgetTester tester) async {
        await tester.pumpWidget(
          MaterialApp(
            theme: ThemeData.light(),
            home: Builder(
              builder: (context) {
                final lightAlpha =
                    GlassVibrancy.tertiaryText(context, tier: GlassTier.light).alpha;
                final mediumAlpha = GlassVibrancy.tertiaryText(
                  context,
                  tier: GlassTier.medium,
                ).alpha;
                final heavyAlpha =
                    GlassVibrancy.tertiaryText(context, tier: GlassTier.heavy).alpha;
                final ultraHeavyAlpha = GlassVibrancy.tertiaryText(
                  context,
                  tier: GlassTier.ultraHeavy,
                ).alpha;

                // Light and medium should have the same highest alpha (both boosted to 0.45)
                expect(lightAlpha, equals(mediumAlpha));
                // Light/medium should be higher than heavy (boosted)
                expect(lightAlpha, greaterThan(heavyAlpha));
                // Heavy and ultraHeavy should be the same (base alpha 0.3)
                expect(heavyAlpha, equals(ultraHeavyAlpha));
                return const SizedBox();
              },
            ),
          ),
        );
      });
    });
  });
}
