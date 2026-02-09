import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/widgets/custom_adaptive_navigation.dart';

void main() {
  group('CustomAdaptiveNavigation bottomAccessory layout', () {
    testWidgets('desktop: accessory stays in right content area only', (
      tester,
    ) async {
      await _pumpWithSize(
        tester: tester,
        size: const Size(1200, 900),
        child: _buildNavigation(),
      );

      final accessoryRect = tester.getRect(
        find.byKey(const Key('test_bottom_accessory')),
      );

      expect(accessoryRect.left, greaterThan(250));
      expect(accessoryRect.width, lessThan(1200));
      expect(accessoryRect.width, greaterThan(800));
      expect(accessoryRect.bottom, greaterThan(840));
    });

    testWidgets('tablet: accessory stays in right content area only', (
      tester,
    ) async {
      await _pumpWithSize(
        tester: tester,
        size: const Size(800, 900),
        child: _buildNavigation(),
      );

      final accessoryRect = tester.getRect(
        find.byKey(const Key('test_bottom_accessory')),
      );

      expect(accessoryRect.left, greaterThan(70));
      expect(accessoryRect.width, lessThan(800));
      expect(accessoryRect.width, greaterThan(650));
      expect(accessoryRect.bottom, greaterThan(840));
    });

    testWidgets('mobile: accessory remains above navigation bar', (
      tester,
    ) async {
      await _pumpWithSize(
        tester: tester,
        size: const Size(390, 844),
        child: _buildNavigation(),
      );

      final accessoryRect = tester.getRect(
        find.byKey(const Key('test_bottom_accessory')),
      );
      final navRect = tester.getRect(find.byType(NavigationBar));

      expect(accessoryRect.width, closeTo(390, 2));
      expect(accessoryRect.top, lessThan(navRect.top));
      expect(accessoryRect.bottom, lessThanOrEqualTo(navRect.top + 1));
    });
  });
}

Future<void> _pumpWithSize({
  required WidgetTester tester,
  required Size size,
  required Widget child,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  await tester.pumpWidget(child);
  await tester.pumpAndSettle();
}

Widget _buildNavigation() {
  return MaterialApp(
    home: MediaQuery(
      data: const MediaQueryData(
        size: Size(1200, 900),
        textScaler: TextScaler.linear(1.0),
      ),
      child: CustomAdaptiveNavigation(
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.home_outlined),
            selectedIcon: Icon(Icons.home),
            label: 'Feed',
          ),
          NavigationDestination(
            icon: Icon(Icons.podcasts_outlined),
            selectedIcon: Icon(Icons.podcasts),
            label: 'Podcast',
          ),
          NavigationDestination(
            icon: Icon(Icons.person_outline),
            selectedIcon: Icon(Icons.person),
            label: 'Profile',
          ),
        ],
        selectedIndex: 0,
        body: const SizedBox.expand(child: ColoredBox(color: Colors.white)),
        bottomAccessory: Container(
          key: const Key('test_bottom_accessory'),
          height: 60,
          color: Colors.blue,
        ),
      ),
    ),
  );
}
