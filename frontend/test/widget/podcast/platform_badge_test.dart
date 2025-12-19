import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/platform_badge.dart';

void main() {
  group('PlatformBadge Widget Tests', () {
    testWidgets('renders Xiaoyuzhou badge correctly', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: PlatformBadge(platform: 'xiaoyuzhou'),
          ),
        ),
      );

      expect(find.text('小宇宙'), findsOneWidget);

      final container = tester.widget<Container>(
        find.ancestor(
          of: find.text('小宇宙'),
          matching: find.byType(Container),
        ).first,
      );

      final decoration = container.decoration as BoxDecoration;
      expect(decoration.color, const Color(0xFFFF6B35).withOpacity(0.1));
    });

    testWidgets('renders Ximalaya badge correctly', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: PlatformBadge(platform: 'ximalaya'),
          ),
        ),
      );

      expect(find.text('喜马拉雅'), findsOneWidget);

      final container = tester.widget<Container>(
        find.ancestor(
          of: find.text('喜马拉雅'),
          matching: find.byType(Container),
        ).first,
      );

      final decoration = container.decoration as BoxDecoration;
      expect(decoration.color, const Color(0xFFE53935).withOpacity(0.1));
    });

    testWidgets('hides badge when platform is null', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: PlatformBadge(platform: null),
          ),
        ),
      );

      expect(find.byType(Container), findsNothing);
      expect(find.byType(SizedBox), findsOneWidget);
    });

    testWidgets('hides badge when platform is empty string', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: PlatformBadge(platform: ''),
          ),
        ),
      );

      expect(find.byType(Container), findsNothing);
      expect(find.byType(SizedBox), findsOneWidget);
    });

    testWidgets('hides badge when platform is generic', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: PlatformBadge(platform: 'generic'),
          ),
        ),
      );

      expect(find.byType(Container), findsNothing);
      expect(find.byType(SizedBox), findsOneWidget);
    });

    testWidgets('handles case insensitive platform names', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: Column(
              children: [
                PlatformBadge(platform: 'XIAOYUZHOU'),
                PlatformBadge(platform: 'XiMaLaYa'),
              ],
            ),
          ),
        ),
      );

      expect(find.text('小宇宙'), findsOneWidget);
      expect(find.text('喜马拉雅'), findsOneWidget);
    });

    testWidgets('renders unknown platform with default styling', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: PlatformBadge(platform: 'unknown_platform'),
          ),
        ),
      );

      expect(find.text('unknown_platform'), findsOneWidget);

      final container = tester.widget<Container>(
        find.ancestor(
          of: find.text('unknown_platform'),
          matching: find.byType(Container),
        ).first,
      );

      final decoration = container.decoration as BoxDecoration;
      expect(decoration.color, const Color(0xFF757575).withOpacity(0.1));
    });

    testWidgets('badge has correct padding and border radius', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: PlatformBadge(platform: 'xiaoyuzhou'),
          ),
        ),
      );

      final container = tester.widget<Container>(
        find.ancestor(
          of: find.text('小宇宙'),
          matching: find.byType(Container),
        ).first,
      );

      expect(container.padding, const EdgeInsets.symmetric(horizontal: 6, vertical: 2));

      final decoration = container.decoration as BoxDecoration;
      expect(decoration.borderRadius, BorderRadius.circular(4));
    });

    testWidgets('badge text has correct styling', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: PlatformBadge(platform: 'xiaoyuzhou'),
          ),
        ),
      );

      final text = tester.widget<Text>(find.text('小宇宙'));
      expect(text.style?.fontSize, 10);
      expect(text.style?.fontWeight, FontWeight.w600);
      expect(text.style?.color, const Color(0xFFFF6B35));
    });

    testWidgets('badge has border with correct color', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: PlatformBadge(platform: 'ximalaya'),
          ),
        ),
      );

      final container = tester.widget<Container>(
        find.ancestor(
          of: find.text('喜马拉雅'),
          matching: find.byType(Container),
        ).first,
      );

      final decoration = container.decoration as BoxDecoration;
      final border = decoration.border as Border;
      expect(border.top.width, 1);
      expect(border.top.color, const Color(0xFFE53935).withOpacity(0.3));
    });
  });
}
