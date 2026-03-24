import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/shared/widgets/lazy_indexed_stack.dart';

void main() {
  group('LazyIndexedStack Widget Tests', () {
    testWidgets('renders initially selected tab content', (tester) async {
      int buildCount = 0;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: LazyIndexedStack(
              index: 0,
              itemCount: 3,
              itemBuilder: (context, index) {
                buildCount++;
                return ColoredBox(
                  color: [Colors.red, Colors.green, Colors.blue][index],
                  child: Text('Tab $index'),
                );
              },
            ),
          ),
        ),
      );

      // Only the initial tab should be built
      expect(buildCount, equals(1));
      expect(find.text('Tab 0'), findsOneWidget);
      expect(find.text('Tab 1'), findsNothing);
      expect(find.text('Tab 2'), findsNothing);
    });

    testWidgets('only builds content when tab is first visited', (tester) async {
      final Set<int> builtIndices = {};

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: LazyIndexedStack(
              index: 0,
              itemCount: 3,
              itemBuilder: (context, index) {
                builtIndices.add(index);
                return Text('Tab $index');
              },
            ),
          ),
        ),
      );

      // Only tab 0 should be built initially
      expect(builtIndices, contains(0));
      expect(builtIndices, isNot(contains(1)));
      expect(builtIndices, isNot(contains(2)));
    });

    testWidgets('builds new tab content when switching to unvisited tab',
        (tester) async {
      int selectedIndex = 0;
      final Set<int> builtIndices = {};

      await tester.pumpWidget(
        _TestLazyStackWrapper(
          selectedIndex: selectedIndex,
          builtIndices: builtIndices,
        ),
      );

      // Initially only tab 0 is built
      expect(builtIndices, {0});

      // Switch to tab 1
      selectedIndex = 1;
      await tester.pumpWidget(
        _TestLazyStackWrapper(
          selectedIndex: selectedIndex,
          builtIndices: builtIndices,
        ),
      );
      await tester.pump();

      // Now both tab 0 and tab 1 should be built
      expect(builtIndices, {0, 1});
    });

    testWidgets('preserves state of previously visited tabs', (tester) async {
      int selectedIndex = 0;
      final testKey = GlobalKey<_TestWidgetState>();

      await tester.pumpWidget(
        _TestLazyStackWrapperWithKey(
          selectedIndex: selectedIndex,
          testKey: testKey,
        ),
      );

      // Find the TestWidget and increment its counter
      final testWidget = testKey.currentState;
      expect(testWidget, isNotNull);
      expect(testWidget!.counter, equals(0));

      // Increment counter
      testWidget.increment();
      await tester.pump();
      expect(testWidget.counter, equals(1));

      // Switch to tab 1
      selectedIndex = 1;
      await tester.pumpWidget(
        _TestLazyStackWrapperWithKey(
          selectedIndex: selectedIndex,
          testKey: testKey,
        ),
      );
      await tester.pump();

      // Tab 0 should no longer be visible
      expect(find.byType(_TestWidget), findsNothing);

      // Switch back to tab 0
      selectedIndex = 0;
      await tester.pumpWidget(
        _TestLazyStackWrapperWithKey(
          selectedIndex: selectedIndex,
          testKey: testKey,
        ),
      );
      await tester.pump();

      // Tab 0's state should be preserved
      final sameTestWidget = testKey.currentState;
      expect(sameTestWidget, isNotNull);
      expect(sameTestWidget!.counter, equals(1));
    });

    testWidgets('calls onTabVisited callback when tab is first visited',
        (tester) async {
      final Set<int> visitedTabs = {};
      int selectedIndex = 0;

      await tester.pumpWidget(
        _TestLazyStackWrapperWithCallback(
          selectedIndex: selectedIndex,
          visitedTabs: visitedTabs,
        ),
      );

      // Switch to tab 1
      selectedIndex = 1;
      await tester.pumpWidget(
        _TestLazyStackWrapperWithCallback(
          selectedIndex: selectedIndex,
          visitedTabs: visitedTabs,
        ),
      );
      await tester.pump();

      expect(visitedTabs, contains(1));

      // Switching back to an already visited tab should not trigger callback
      final previousLength = visitedTabs.length;
      selectedIndex = 0;
      await tester.pumpWidget(
        _TestLazyStackWrapperWithCallback(
          selectedIndex: selectedIndex,
          visitedTabs: visitedTabs,
        ),
      );
      await tester.pump();

      expect(visitedTabs.length, equals(previousLength));
    });

    testWidgets('handles index changes correctly', (tester) async {
      int selectedIndex = 0;

      await tester.pumpWidget(
        _TestLazyStackWrapperSimple(selectedIndex: selectedIndex),
      );

      // Tab 0 is visible
      expect(find.text('Tab 0'), findsOneWidget);
      expect(find.text('Tab 1'), findsNothing);

      // Switch to tab 1
      selectedIndex = 1;
      await tester.pumpWidget(
        _TestLazyStackWrapperSimple(selectedIndex: selectedIndex),
      );
      await tester.pump();

      expect(find.text('Tab 0'), findsNothing);
      expect(find.text('Tab 1'), findsOneWidget);

      // Switch to tab 2
      selectedIndex = 2;
      await tester.pumpWidget(
        _TestLazyStackWrapperSimple(selectedIndex: selectedIndex),
      );
      await tester.pump();

      expect(find.text('Tab 1'), findsNothing);
      expect(find.text('Tab 2'), findsOneWidget);
    });

    testWidgets('returns SizedBox.shrink for unvisited tabs', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: LazyIndexedStack(
              index: 0,
              itemCount: 3,
              itemBuilder: (context, index) => Text('Tab $index'),
            ),
          ),
        ),
      );

      // Only tab 0 content should exist
      expect(find.text('Tab 0'), findsOneWidget);

      // Unvisited tabs should not have their content built
      expect(find.text('Tab 1'), findsNothing);
      expect(find.text('Tab 2'), findsNothing);

      // When we switch to tab 1, its content should appear
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: LazyIndexedStack(
              index: 1,
              itemCount: 3,
              itemBuilder: (context, index) => Text('Tab $index'),
            ),
          ),
        ),
      );

      expect(find.text('Tab 1'), findsOneWidget);
    });

    testWidgets('handles zero itemCount gracefully', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: LazyIndexedStack(
              index: 0,
              itemCount: 0,
              itemBuilder: (context, index) => Text('Tab $index'),
            ),
          ),
        ),
      );

      // Should not crash and render nothing
      expect(find.byType(LazyIndexedStack), findsOneWidget);
    });

    testWidgets('initializes with provided index', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: LazyIndexedStack(
              index: 2,
              itemCount: 3,
              itemBuilder: (context, index) => Text('Tab $index'),
            ),
          ),
        ),
      );

      // Tab 2 should be the initial visible tab
      expect(find.text('Tab 2'), findsOneWidget);
      expect(find.text('Tab 0'), findsNothing);
      expect(find.text('Tab 1'), findsNothing);
    });

    testWidgets('works with complex widget hierarchies', (tester) async {
      int selectedIndex = 0;

      await tester.pumpWidget(
        _TestLazyStackWrapperComplex(selectedIndex: selectedIndex),
      );

      // Tab 0 should have its content
      expect(find.text('AppBar 0'), findsOneWidget);
      expect(find.text('Item 0 in tab 0'), findsOneWidget);
      expect(find.text('Item 4 in tab 0'), findsOneWidget);

      // Switch to tab 1
      selectedIndex = 1;
      await tester.pumpWidget(
        _TestLazyStackWrapperComplex(selectedIndex: selectedIndex),
      );
      await tester.pump();

      // Tab 1 content should be visible
      expect(find.text('AppBar 1'), findsOneWidget);
      expect(find.text('Item 0 in tab 1'), findsOneWidget);
    });
  });
}

// Test helper widgets

class _TestLazyStackWrapper extends StatelessWidget {
  final int selectedIndex;
  final Set<int> builtIndices;

  const _TestLazyStackWrapper({
    required this.selectedIndex,
    required this.builtIndices,
  });

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        body: LazyIndexedStack(
          index: selectedIndex,
          itemCount: 3,
          itemBuilder: (context, index) {
            builtIndices.add(index);
            return Text('Tab $index');
          },
        ),
      ),
    );
  }
}

class _TestLazyStackWrapperWithKey extends StatelessWidget {
  final int selectedIndex;
  final GlobalKey<_TestWidgetState> testKey;

  const _TestLazyStackWrapperWithKey({
    required this.selectedIndex,
    required this.testKey,
  });

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        body: LazyIndexedStack(
          index: selectedIndex,
          itemCount: 2,
          itemBuilder: (context, index) {
            if (index == 0) {
              return _TestWidget(key: testKey);
            }
            return const Text('Tab 1');
          },
        ),
      ),
    );
  }
}

class _TestLazyStackWrapperWithCallback extends StatelessWidget {
  final int selectedIndex;
  final Set<int> visitedTabs;

  const _TestLazyStackWrapperWithCallback({
    required this.selectedIndex,
    required this.visitedTabs,
  });

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        body: LazyIndexedStack(
          index: selectedIndex,
          itemCount: 3,
          itemBuilder: (context, index) => Text('Tab $index'),
          onTabVisited: (index) {
            visitedTabs.add(index);
          },
        ),
      ),
    );
  }
}

class _TestLazyStackWrapperSimple extends StatelessWidget {
  final int selectedIndex;

  const _TestLazyStackWrapperSimple({required this.selectedIndex});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        body: LazyIndexedStack(
          index: selectedIndex,
          itemCount: 3,
          itemBuilder: (context, index) => Text('Tab $index'),
        ),
      ),
    );
  }
}

class _TestLazyStackWrapperComplex extends StatelessWidget {
  final int selectedIndex;

  const _TestLazyStackWrapperComplex({required this.selectedIndex});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        body: LazyIndexedStack(
          index: selectedIndex,
          itemCount: 2,
          itemBuilder: (context, index) {
            return Scaffold(
              appBar: AppBar(title: Text('AppBar $index')),
              body: ListView.builder(
                itemCount: 5,
                itemBuilder: (context, i) => ListTile(
                  title: Text('Item $i in tab $index'),
                ),
              ),
            );
          },
        ),
      ),
    );
  }
}

// Test helper widget with mutable state
class _TestWidget extends StatefulWidget {
  const _TestWidget({super.key});

  @override
  State<_TestWidget> createState() => _TestWidgetState();
}

class _TestWidgetState extends State<_TestWidget> {
  int counter = 0;

  void increment() {
    setState(() {
      counter++;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Text('Counter: $counter');
  }
}
