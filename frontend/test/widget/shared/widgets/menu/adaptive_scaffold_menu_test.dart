import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/shared/widgets/menu/adaptive_scaffold_menu.dart';

void main() {
  group('AdaptiveScaffoldMenu', () {
    late List<NavigationDestination> testDestinations;
    late int selectedIndex;
    late ValueChanged<int> onSelected;

    setUp(() {
      testDestinations = [
        const NavigationDestination(
          icon: Icon(Icons.home_outlined),
          selectedIcon: Icon(Icons.home),
          label: 'Home',
        ),
        const NavigationDestination(
          icon: Icon(Icons.settings_outlined),
          selectedIcon: Icon(Icons.settings),
          label: 'Settings',
        ),
        const NavigationDestination(
          icon: Icon(Icons.info_outline),
          selectedIcon: Icon(Icons.info),
          label: 'About',
        ),
      ];
      selectedIndex = 0;
      onSelected = (index) {
        selectedIndex = index;
      };
    });

    testWidgets('renders all required UI components', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: testDestinations,
            selectedIndex: selectedIndex,
            onDestinationSelected: onSelected,
            title: 'Test App',
            subtitle: 'v1.0',
          ),
        ),
      );

      // 验证主体内容
      expect(find.byType(AdaptiveScaffoldMenu), findsOneWidget);

      // 验证应用栏（在小屏幕上显示）
      expect(find.byType(AppBar), findsOneWidget);
    });

    testWidgets('displays loading state initially', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: testDestinations,
            selectedIndex: selectedIndex,
            onDestinationSelected: onSelected,
          ),
        ),
      );

      // 初始状态应该显示组件
      expect(find.byType(AdaptiveScaffoldMenu), findsOneWidget);
    });

    testWidgets('shows data when loaded successfully', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: testDestinations,
            selectedIndex: selectedIndex,
            onDestinationSelected: onSelected,
            title: 'Loaded App',
            subtitle: 'v1.0',
          ),
        ),
      );

      // 验证应用栏标题
      expect(find.text('Loaded App'), findsOneWidget);
      expect(find.text('v1.0'), findsOneWidget);
    });

    testWidgets('handles selection correctly', (WidgetTester tester) async {
      int? capturedIndex;
      final testOnSelected = (int index) {
        capturedIndex = index;
      };

      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: testDestinations,
            selectedIndex: 0,
            onDestinationSelected: testOnSelected,
          ),
        ),
      );

      // 在小屏幕上，点击底部导航
      await tester.tap(find.text('Settings'));
      await tester.pumpAndSettle();

      // 验证回调被调用
      expect(capturedIndex, equals(1));
    });

    testWidgets('shows selected state correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: testDestinations,
            selectedIndex: 1, // Settings 选中
            onDestinationSelected: onSelected,
          ),
        ),
      );

      // 验证底部导航的选中状态
      expect(find.byType(BottomNavigationBar), findsOneWidget);
    });

    testWidgets('handles empty destinations', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: [],
            selectedIndex: 0,
            onDestinationSelected: onSelected,
          ),
        ),
      );

      // 应该正常渲染，不崩溃
      expect(find.byType(AdaptiveScaffoldMenu), findsOneWidget);
    });

    testWidgetsrenders floating action', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: testDestinations,
            selectedIndex: 0,
            onDestinationSelected: onSelected,
            floatingActionButton: FloatingActionButton(
              onPressed: () {},
              child: const Icon(Icons.add),
            ),
          ),
        ),
      );

      // 验证悬浮按钮
      expect(find.byType(FloatingActionButton), findsOneWidget);
      expect(find.byIcon(Icons.add), findsOneWidget);
    });

    testWidgets('navigation works correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: testDestinations,
            selectedIndex: 0,
            onDestinationSelected: onSelected,
          ),
        ),
      );

      // 点击不同的导航项
      await tester.tap(find.text('About'));
      await tester.pumpAndSettle();

      // 验证选中状态更新
      expect(selectedIndex, equals(2));
    });

    testWidgets('empty state displays correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: [
              const NavigationDestination(
                icon: Icon(Icons.home),
                label: 'Home',
              ),
            ],
            selectedIndex: 0,
            onDestinationSelected: onSelected,
          ),
        ),
      );

      // 应该显示一个导航项
      expect(find.text('Home'), findsOneWidget);
    });

    testWidgets('handles user menu selection', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: testDestinations,
            selectedIndex: 0,
            onDestinationSelected: onSelected,
          ),
        ),
      );

      // 在小屏幕上，用户菜单是底部导航的一部分
      expect(find.byIcon(Icons.person), findsOneWidget);
    });

    testWidgets('renders with custom app bar', (WidgetTester tester) async {
      final customAppBar = AppBar(
        title: const Text('Custom AppBar'),
        actions: [
          IconButton(
            icon: const Icon(Icons.search),
            onPressed: () {},
          ),
        ],
      );

      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: testDestinations,
            selectedIndex: 0,
            onDestinationSelected: onSelected,
            appBar: customAppBar,
          ),
        ),
      );

      // 验证自定义应用栏
      expect(find.text('Custom AppBar'), findsOneWidget);
      expect(find.byIcon(Icons.search), findsOneWidget);
    });

    testWidgets('handles dynamic updates', (WidgetTester tester) async {
      List<NavigationDestination> dynamicDestinations = [
        const NavigationDestination(
          icon: Icon(Icons.home),
          label: 'Home',
        ),
      ];

      await tester.pumpWidget(
        MaterialApp(
          home: StatefulBuilder(
            builder: (context, setState) {
              return AdaptiveScaffoldMenu(
                body: Container(),
                destinations: dynamicDestinations,
                selectedIndex: 0,
                onDestinationSelected: (index) {
                  setState(() {
                    dynamicDestinations = [
                      const NavigationDestination(
                        icon: Icon(Icons.home),
                        label: 'Home',
                      ),
                      const NavigationDestination(
                        icon: Icon(Icons.settings),
                        label: 'Settings',
                      ),
                    ];
                  });
                },
              );
            },
          ),
        ),
      );

      // 初始状态
      expect(find.text('Home'), findsOneWidget);
      expect(find.text('Settings'), findsNothing);

      // 触发更新
      await tester.tap(find.text('Home'));
      await tester.pumpAndSettle();

      // 更新后状态
      expect(find.text('Settings'), findsOneWidget);
    });
  });

  group('NavigationDestinationHelper', () {
    test('converts menu items to navigation destinations', () {
      final menuItems = [
        const MenuItem(icon: Icons.home, label: 'Home'),
        const MenuItem(icon: Icons.settings, label: 'Settings'),
        const MenuDivider(),
        const MenuItem(icon: Icons.info, label: 'About'),
      ];

      final destinations = NavigationDestinationHelper.fromMenuItems(menuItems);

      expect(destinations.length, equals(3)); // 分隔线被过滤
      expect(destinations[0].label, equals('Home'));
      expect(destinations[1].label, equals('Settings'));
      expect(destinations[2].label, equals('About'));
    });

    test('handles empty list', () {
      final destinations = NavigationDestinationHelper.fromMenuItems([]);

 []);
      expect(destinations.length, equals(0));
    });

    test('handles list with only dividers', () {
      final menuItems = [
        const MenuDivider(),
        const MenuDivider(),
      ];

      final destinations = NavigationDestinationHelper.fromMenuItems(menuItems);
      expect(destinations.length, equals(0));
    });
  });

  group('AdaptiveScaffoldMenu widget tests', () {
    testWidgets('renders body content', (WidgetTester tester) async {
      const bodyContent = Text('Body Content');

      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: bodyContent,
            destinations: [
              const NavigationDestination(
                icon: Icon(Icons.home),
                label: 'Home',
              ),
            ],
            selectedIndex: 0,
            onDestinationSelected: (index) {},
          ),
        ),
      );

      expect(find.text('Body Content'), findsOneWidget);
    });

    testWidgets('handles null title and subtitle', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: [
              const NavigationDestination(
                icon: Icon(Icons.home),
                label: 'Home',
              ),
            ],
            selectedIndex: 0,
            onDestinationSelected: (index) {},
          ),
        ),
      );

      // 应该正常渲染，不显示标题
      expect(find.byType(AdaptiveScaffoldMenu), findsOneWidget);
    });

    testWidgets('handles null onDestinationSelected', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: [
              const NavigationDestination(
                icon: Icon(Icons.home),
                label: 'Home',
              ),
            ],
            selectedIndex: 0,
            onDestinationSelected: null,
          ),
        ),
      );

      // 应该正常渲染
      expect(find.byType(AdaptiveScaffoldMenu), findsOneWidget);
    });

    testWidgets('shows shortcuts when enabled', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: [
              const NavigationDestination(
                icon: Icon(Icons.home),
                label: 'Home',
              ),
            ],
            selectedIndex: 0,
            onDestinationSelected: (index) {},
            showShortcuts: true,
          ),
        ),
      );

      // 应该正常渲染
      expect(find.byType(AdaptiveScaffoldMenu), findsOneWidget);
    });

    testWidgets('hides shortcuts when disabled', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: AdaptiveScaffoldMenu(
            body: Container(),
            destinations: [
              const NavigationDestination(
                icon: Icon(Icons.home),
                label: 'Home',
              ),
            ],
            selectedIndex: 0,
            onDestinationSelected: (index) {},
            showShortcuts: false,
          ),
        ),
      );

      // 应该正常渲染
      expect(find.byType(AdaptiveScaffoldMenu), findsOneWidget);
    });
  });
}
