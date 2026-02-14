import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/theme/app_theme.dart';
import 'package:personal_ai_assistant/core/widgets/top_floating_notice.dart';

void main() {
  group('TopFloatingNotice', () {
    testWidgets('uses default 3s duration and stays in upper area', (
      tester,
    ) async {
      tester.view.physicalSize = const Size(400, 800);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      await _pumpHost(tester);

      await tester.tap(find.byKey(const Key('show_notice_default')));
      await tester.pump();

      final noticeFinder = find.byKey(const Key('top_floating_notice'));
      expect(noticeFinder, findsOneWidget);

      final noticeRect = tester.getRect(noticeFinder);
      expect(noticeRect.top, greaterThan(kToolbarHeight));
      expect(noticeRect.top, lessThan(220));
      expect(noticeRect.center.dy, lessThan(400));

      await tester.pump(const Duration(seconds: 2));
      expect(noticeFinder, findsOneWidget);

      await tester.pump(const Duration(seconds: 1));
      expect(noticeFinder, findsNothing);
    });

    testWidgets('replaces previous notice without stacking', (tester) async {
      await _pumpHost(tester);

      await tester.tap(find.byKey(const Key('show_notice_first')));
      await tester.pump();
      expect(find.text('First Notice'), findsOneWidget);

      await tester.tap(find.byKey(const Key('show_notice_second')));
      await tester.pump();

      expect(find.text('First Notice'), findsNothing);
      expect(find.text('Second Notice'), findsOneWidget);
      expect(find.byKey(const Key('top_floating_notice')), findsOneWidget);
      await tester.pump(const Duration(seconds: 4));
    });

    testWidgets('applies extraTopOffset below page header', (tester) async {
      await _pumpHost(tester);

      await tester.tap(find.byKey(const Key('show_notice_default')));
      await tester.pump();
      final defaultTop = tester
          .getTopLeft(find.byKey(const Key('top_floating_notice')))
          .dy;

      await tester.tap(find.byKey(const Key('show_notice_with_offset')));
      await tester.pump();
      final offsetTop = tester
          .getTopLeft(find.byKey(const Key('top_floating_notice')))
          .dy;

      expect(offsetTop, greaterThan(defaultTop + 60));
      await tester.pump(const Duration(seconds: 4));
    });

    testWidgets('uses error icon for error notice', (tester) async {
      await _pumpHost(tester);

      await tester.tap(find.byKey(const Key('show_notice_error')));
      await tester.pump();

      expect(find.byIcon(Icons.error_outline), findsOneWidget);
      await tester.pump(const Duration(seconds: 4));
    });

    testWidgets('uses success icon for success notice', (tester) async {
      await _pumpHost(tester);

      await tester.tap(find.byKey(const Key('show_notice_default')));
      await tester.pump();

      expect(find.byIcon(Icons.check_circle_outline), findsOneWidget);
      expect(
        find.byKey(const Key('top_floating_notice_message')),
        findsOneWidget,
      );
      await tester.pump(const Duration(seconds: 4));
    });

    testWidgets('uses light theme surface + black for success notice', (
      tester,
    ) async {
      await _pumpHost(tester);

      await tester.tap(find.byKey(const Key('show_notice_default')));
      await tester.pump();

      final context = tester.element(
        find.byKey(const Key('top_floating_notice')),
      );
      final theme = Theme.of(context);
      final decoration = _noticeDecoration(tester);
      expect(decoration.color, theme.colorScheme.surface);

      final messageText = tester.widget<Text>(
        find.byKey(const Key('top_floating_notice_message')),
      );
      expect(messageText.style?.color, Colors.black);

      final successIcon = tester.widget<Icon>(
        find.byIcon(Icons.check_circle_outline),
      );
      expect(successIcon.color, Colors.black);
      await tester.pump(const Duration(seconds: 4));
    });

    testWidgets('uses light theme surface + error colors for error notice', (
      tester,
    ) async {
      await _pumpHost(tester);

      await tester.tap(find.byKey(const Key('show_notice_error')));
      await tester.pump();

      final context = tester.element(
        find.byKey(const Key('top_floating_notice')),
      );
      final theme = Theme.of(context);
      final decoration = _noticeDecoration(tester);
      expect(decoration.color, theme.colorScheme.surface);

      final messageText = tester.widget<Text>(
        find.byKey(const Key('top_floating_notice_message')),
      );
      expect(messageText.style?.color, theme.colorScheme.error);

      final errorIcon = tester.widget<Icon>(find.byIcon(Icons.error_outline));
      expect(errorIcon.color, theme.colorScheme.error);
      await tester.pump(const Duration(seconds: 4));
    });

    testWidgets('uses dark theme primary + white for success notice', (
      tester,
    ) async {
      await _pumpHost(tester, themeMode: ThemeMode.dark);

      await tester.tap(find.byKey(const Key('show_notice_default')));
      await tester.pump();

      final context = tester.element(
        find.byKey(const Key('top_floating_notice')),
      );
      final theme = Theme.of(context);
      final decoration = _noticeDecoration(tester);
      expect(decoration.color, theme.colorScheme.primary);

      final messageText = tester.widget<Text>(
        find.byKey(const Key('top_floating_notice_message')),
      );
      expect(messageText.style?.color, Colors.white);

      final successIcon = tester.widget<Icon>(
        find.byIcon(Icons.check_circle_outline),
      );
      expect(successIcon.color, Colors.white);
      await tester.pump(const Duration(seconds: 4));
    });

    testWidgets('uses dark theme primary + error for error notice', (
      tester,
    ) async {
      await _pumpHost(tester, themeMode: ThemeMode.dark);

      await tester.tap(find.byKey(const Key('show_notice_error')));
      await tester.pump();

      final context = tester.element(
        find.byKey(const Key('top_floating_notice')),
      );
      final theme = Theme.of(context);
      final decoration = _noticeDecoration(tester);
      expect(decoration.color, theme.colorScheme.primary);

      final messageText = tester.widget<Text>(
        find.byKey(const Key('top_floating_notice_message')),
      );
      expect(messageText.style?.color, theme.colorScheme.error);

      final errorIcon = tester.widget<Icon>(find.byIcon(Icons.error_outline));
      expect(errorIcon.color, theme.colorScheme.error);
      await tester.pump(const Duration(seconds: 4));
    });

    testWidgets('border and shadow are fully opaque', (tester) async {
      await _pumpHost(tester);

      await tester.tap(find.byKey(const Key('show_notice_default')));
      await tester.pump();

      final decoration = _noticeDecoration(tester);
      final border = decoration.border as Border;
      expect(border.top.color.alpha, 255);
      expect(border.bottom.color.alpha, 255);
      expect(border.left.color.alpha, 255);
      expect(border.right.color.alpha, 255);
      expect(decoration.boxShadow, isNotEmpty);
      expect(decoration.boxShadow!.first.color.alpha, 255);
      await tester.pump(const Duration(seconds: 4));
    });

    testWidgets('uses latest theme when shown after theme toggle', (tester) async {
      await tester.pumpWidget(const _ThemeSwitchingApp());

      await tester.tap(find.byKey(const Key('toggle_theme')));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('show_notice_default')));
      await tester.pump();
      expect(find.byKey(const Key('top_floating_notice')), findsOneWidget);
      expect(_noticeDecoration(tester).color, AppTheme.darkTheme.colorScheme.primary);
      await tester.pump(const Duration(seconds: 4));
    });
  });
}

Future<void> _pumpHost(
  WidgetTester tester, {
  ThemeMode themeMode = ThemeMode.light,
}) {
  return tester.pumpWidget(
    MaterialApp(
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: themeMode,
      home: const _TopNoticeHost(),
    ),
  );
}

BoxDecoration _noticeDecoration(WidgetTester tester) {
  final decoratedBox = tester.widget<DecoratedBox>(
    find.byKey(const Key('top_floating_notice')),
  );
  return decoratedBox.decoration as BoxDecoration;
}

class _TopNoticeHost extends StatelessWidget {
  const _TopNoticeHost({this.onToggleTheme});

  final VoidCallback? onToggleTheme;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Host')),
      body: Builder(
        builder: (context) {
          return Column(
            children: [
              const SizedBox(height: 120),
              if (onToggleTheme != null)
                TextButton(
                  key: const Key('toggle_theme'),
                  onPressed: onToggleTheme,
                  child: const Text('Toggle theme'),
                ),
              TextButton(
                key: const Key('show_notice_default'),
                onPressed: () {
                  showTopFloatingNotice(context, message: 'Quick Notice');
                },
                child: const Text('Show default'),
              ),
              TextButton(
                key: const Key('show_notice_with_offset'),
                onPressed: () {
                  showTopFloatingNotice(
                    context,
                    message: 'Offset Notice',
                    extraTopOffset: 80,
                  );
                },
                child: const Text('Show offset'),
              ),
              TextButton(
                key: const Key('show_notice_first'),
                onPressed: () {
                  showTopFloatingNotice(
                    context,
                    message: 'First Notice',
                    duration: const Duration(seconds: 3),
                  );
                },
                child: const Text('Show first'),
              ),
              TextButton(
                key: const Key('show_notice_second'),
                onPressed: () {
                  showTopFloatingNotice(
                    context,
                    message: 'Second Notice',
                    duration: const Duration(seconds: 3),
                  );
                },
                child: const Text('Show second'),
              ),
              TextButton(
                key: const Key('show_notice_error'),
                onPressed: () {
                  showTopFloatingNotice(
                    context,
                    message: 'Error Notice',
                    isError: true,
                    duration: const Duration(seconds: 3),
                  );
                },
                child: const Text('Show error'),
              ),
            ],
          );
        },
      ),
    );
  }
}

class _ThemeSwitchingApp extends StatefulWidget {
  const _ThemeSwitchingApp();

  @override
  State<_ThemeSwitchingApp> createState() => _ThemeSwitchingAppState();
}

class _ThemeSwitchingAppState extends State<_ThemeSwitchingApp> {
  ThemeMode _themeMode = ThemeMode.light;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: _themeMode,
      home: _TopNoticeHost(
        onToggleTheme: () {
          setState(() {
            _themeMode =
                _themeMode == ThemeMode.light ? ThemeMode.dark : ThemeMode.light;
          });
        },
      ),
    );
  }
}
