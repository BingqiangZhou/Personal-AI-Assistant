import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/shared/widgets/menu/menu.dart';

void main() {
  group('Menu Integration Tests', () {
    testWidgets('AdaptiveMenu complete workflow', (WidgetTester tester) async {
      // 准备测试数据
      final items = [
        const MenuItem(icon: Icons.home, label: 'Home', shortcut: 'Ctrl+1'),
        const MenuItem(icon: Icons.settings, label: 'Settings', shortcut: 'Ctrl+2', badgeCount: 2),
        const MenuDivider(),
        const MenuItem(icon: Icons.info, label: 'About'),
      ];

      int selectedIndex = 0;
      int callbackCount = 0;

      await tester.pumpWidget(
        MaterialApp(
          home: StatefulBuilder(
            builder: (context, setState) {
              return Scaffold(
                body: AdaptiveMenu(
                  config: AdaptiveMenuConfig(
                    items: items,
                    selectedIndex: selectedIndex,
                    onSelected: (index) {
                      setState(() {
                        selectedIndex = index;
                        callbackCount++;
                      });
                    },
                    title: 'Integration Test',
                    subtitle: 'v1.0',
                  ),
                ),
              );
            },
          ),
        ),
      );

      // 验证初始状态
      expect(find.text('Integration Test'), findsOneWidget);
      expect(find.text('v1.0'), findsOneWidget);
      expect(find.text('Home'), findsOneWidget);
      expect(find.text('Settings'), findsOneWidget);
      expect(find.text('About'), findsOneWidget);
      expect(find.text('Ctrl+1'), findsOneWidget);
      expect(find.text('Ctrl+2'), findsOneWidget);
      expect(find.text('2'), findsOneWidget); // 徽章

      // 测试选择功能
      await tester.tap(find.text('Settings'));
      await tester.pumpAndSettle();

      expect(selectedIndex, equals(1));
      expect(callbackCount, equals(1));

      // 测试再次选择
      await tester.tap(find.text('About'));
      await tester.pumpAndSettle();

      expect(selectedIndex, equals(3));
      expect(callbackCount, equals(2));

      // 测试折叠功能
      await tester.tap(find.byIcon(Icons.chevron_left));
      await tester.pumpAndSettle();

      // 验证折叠状态（文字应该隐藏）
      expect(find.text('Integration Test'), findsNothing);
      expect(find.text('v1.0'), findsNothing);
    });

    testWidgets('AdaptiveScaffoldMenu complete workflow', (WidgetTester tester) async {
      final destinations = [
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

      int selectedIndex = 0;
      int callbackCount = 0;

      await tester.pumpWidget(
        MaterialApp(
          home: StatefulBuilder(
            builder: (context, setState) {
              return AdaptiveScaffoldMenu(
                body: Center(
                  child: Text('Selected: $selectedIndex'),
                ),
                destinations: destinations,
                selectedIndex: selectedIndex,
                onDestinationSelected: (index) {
                  setState(() {
                    selectedIndex = index;
                    callbackCount++;
                  });
                },
                title: 'Scaffold Test',
                subtitle: 'v2.0',
                floatingActionButton: FloatingActionButton(
                  onPressed: () {},
                  child: const Icon(Icons.add),
                ),
              );
            },
          ),
        ),
      );

      // 验证初始状态
      expect(find.text('Scaffold Test'), findsOneWidget);
      expect(find.text('v2.0'), findsOneWidget);
      expect(find.text('Selected: 0'), findsOneWidget);
      expect(find.byIcon(Icons.add), findsOneWidget);

      // 测试导航选择
      await tester.tap(find.text('Settings'));
      await tester.pumpAndSettle();

      expect(selectedIndex, equals(1));
      expect(callbackCount, equals(1));
      expect(find.text('Selected: 1'), findsOneWidget);

      // 测试悬浮按钮
      await tester.tap(find.byIcon(Icons.add));
      await tester.pumpAndSettle();

      // 验证应用栏操作
      expect(find.byIcon(Icons.search), findsOneWidget);
      expect(find.byIcon(Icons.notifications_outlined), findsOneWidget);
    });

    testWidgets('Both components work together', (WidgetTester tester) async {
      final menuItems = [
        const MenuItem(icon: Icons.home, label: 'Home'),
        const MenuItem(icon: Icons.settings, label: 'Settings'),
      ];

      final destinations = [
        const NavigationDestination(
          icon: Icon(Icons.home),
          label: 'Home',
        ),
        const NavigationDestination(
          icon: Icon(Icons.settings),
          label: 'Settings',
        ),
      ];

      int selectedIndex = 0;

      await tester.pumpWidget(
        MaterialApp(
          home: StatefulBuilder(
            builder: (context, setState) {
              return Scaffold(
                body: Row(
                  children: [
                    // 自定义菜单
                    SizedBox(
                      width: 200,
                      child: AdaptiveMenu(
                        config: AdaptiveMenuConfig(
                          items: menuItems,
                          selectedIndex: selectedIndex,
                          onSelected: (index) {
                            setState(() {
                              selectedIndex = index;
                            });
                          },
                        ),
                      ),
                    ),
                    // AdaptiveScaffoldMenu
                    Expanded(
                      child: AdaptiveScaffoldMenu(
                        body: Container(
                          color: Colors.grey[100],
                          child: Center(
                            child: Text('Content: $selectedIndex'),
                          ),
                        ),
                        destinations: destinations,
                        selectedIndex: selectedIndex,
                        onDestinationSelected: (index) {
                          setState(() {
                            selectedIndex = index;
                          });
                        },
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
        ),
      );

      // 验证两个组件都存在
      expect(find.byType(AdaptiveMenu), findsOneWidget);
      expect(find.byType(AdaptiveScaffoldMenu), findsOneWidget);

      // 验证同步状态
      expect(find.text('Content: 0'), findsOneWidget);

      // 在自定义菜单中选择
      await tester.tap(find.text('Settings').first);
      await tester.pumpAndSettle();

      expect(selectedIndex, equals(1));
      expect(find.text('Content: 1'), findsOneWidget);

      // 在AdaptiveScaffoldMenu中选择
      await tester.tap(find.text('Home').last);
      await tester.pumpAndSettle();

      expect(selectedIndex, equals(0));
      expect(find.text('Content: 0'), findsOneWidget);
    });

    testWidgets('Demo page renders correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: AdaptiveMenuDemoPage(),
        ),
      );

      // 验证演示页面标题
      expect(find.text('自适应菜单演示'), findsOneWidget);

      // 验证说明文字
      expect(find.text('调整窗口大小查看自适应效果'), findsOneWidget);

      // 验证两个菜单组件都存在
      expect(find.byType(AdaptiveMenu), findsOneWidget);
      expect(find.byType(AdaptiveScaffoldMenu), findsOneWidget);

      // 验证信息按钮
      expect(find.byIcon(Icons.info_outline), findsOneWidget);
    });

    testWidgets('Custom menu page renders correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: CustomAdaptiveMenuPage(),
        ),
      );

      // 验证页面标题
      expect(find.text('MyApp'), findsOneWidget);
      expect(find.text('v1.0.0'), findsOneWidget);

      // 验证菜单项
      expect(find.text('仪表板'), findsOneWidget);
      expect(find.text('用户管理'), findsOneWidget);
      expect(find.text('数据分析'), findsOneWidget);

      // 验证主体内容
      expect(find.text('仪表板'), findsWidgets); // 菜单和内容中都有
    });

    testWidgets('Scaffold menu page renders correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: ScaffoldAdaptiveMenuPage(),
        ),
      );

      // 验证页面标题
      expect(find.text('Adaptive App'), findsOneWidget);
      expect(find.text('自适应应用'), findsOneWidget);

      // 验证导航项
      expect(find.text('首页'), findsOneWidget);
      expect(find.text('探索'), findsOneWidget);
      expect(find.text('收藏'), findsOneWidget);

      // 验证悬浮按钮
      expect(find.byIcon(Icons.add), findsOneWidget);
    });

    testWidgets('User menu interactions', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: AdaptiveMenu(
              config: AdaptiveMenuConfig(
                items: [
                  const MenuItem(icon: Icons.home, label: 'Home'),
                ],
                selectedIndex: 0,
                onSelected: (index) {},
              ),
            ),
          ),
        ),
      );

      // 点击用户菜单
      await tester.tap(find.byIcon(Icons.person));
      await tester.pumpAndSettle();

      // 验证弹出菜单项
      expect(find.text('Profile'), findsOneWidget);
      expect(find.text('Settings'), findsOneWidget);
      expect(find.text('Logout'), findsOneWidget);
    });

    testWidgets('Badge count updates', (WidgetTester tester) async {
      List<MenuItem> items = [
        const MenuItem(icon: Icons.home, label: 'Home', badgeCount: 1),
      ];

      await tester.pumpWidget(
        MaterialApp(
          home: StatefulBuilder(
            builder: (context, setState) {
              return Scaffold(
                body: AdaptiveMenu(
                  config: AdaptiveMenuConfig(
                    items: items,
                    selectedIndex: 0,
                    onSelected: (index) {
                      setState(() {
                        items = [
                          const MenuItem(icon: Icons.home, label: 'Home', badgeCount: 5),
                        ];
                      });
                    },
                  ),
                ),
              );
            },
          ),
        ),
      );

      // 初始徽章
      expect(find.text('1'), findsOneWidget);

      // 更新徽章
      await tester.tap(find.text('Home'));
      await tester.pumpAndSettle();

      // 更新后的徽章
      expect(find.text('5'), findsOneWidget);
    });

    testWidgets('Disabled menu items', (WidgetTester tester) async {
      final items = [
        const MenuItem(icon: Icons.home, label: 'Home', enabled: false),
        const MenuItem(icon: Icons.settings, label: 'Settings', enabled: true),
      ];

      int? selectedIndex;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: AdaptiveMenu(
              config: AdaptiveMenuConfig(
                items: items,
                selectedIndex: 0,
                onSelected: (index) {
                  selectedIndex = index;
                },
              ),
            ),
          ),
        ),
      );

      // 尝试点击禁用项
      await tester.tap(find.text('Home'));
      await tester.pumpAndSettle();

      // 应该没有变化
      expect(selectedIndex, isNull);

      // 点击启用项
      await tester.tap(find.text('Settings'));
      await tester.pumpAndSettle();

      // 应该有变化
      expect(selectedIndex, equals(1));
    });

    testWidgets('Responsive behavior simulation', (WidgetTester tester) async {
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

      // 在默认窗口大小下（小屏幕），应该显示底部导航
      expect(find.byType(BottomNavigationBar), findsOneWidget);

      // 验证组件可以响应不同屏幕大小
      // 注意：实际的响应式行为需要在不同的窗口大小下测试
      // 这里只验证组件的基本渲染
      expect(find.byType(AdaptiveScaffoldMenu), findsOneWidget);
    });
  });
}
