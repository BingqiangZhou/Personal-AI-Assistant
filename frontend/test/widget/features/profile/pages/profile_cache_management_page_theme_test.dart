import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/core/theme/app_theme.dart';
import 'package:personal_ai_assistant/features/profile/presentation/pages/profile_cache_management_page.dart';

const MethodChannel _pathProviderChannel = MethodChannel(
  'plugins.flutter.io/path_provider',
);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUpAll(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_pathProviderChannel, (methodCall) async {
          final base = Directory.systemTemp.path;
          switch (methodCall.method) {
            case 'getTemporaryDirectory':
            case 'getApplicationSupportDirectory':
            case 'getApplicationDocumentsDirectory':
            case 'getDownloadsDirectory':
              return base;
            default:
              return base;
          }
        });
  });

  tearDownAll(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_pathProviderChannel, null);
  });

  group('ProfileCacheManagementPage theme', () {
    testWidgets('uses profile-style horizontal gutters on mobile', (
      tester,
    ) async {
      _setSurfaceSize(tester, const Size(560, 1600));
      await tester.pumpWidget(_buildTestApp(themeMode: ThemeMode.light));
      await tester.pumpAndSettle();

      final cards = tester.widgetList<Card>(find.byType(Card)).toList();
      expect(cards, hasLength(4));
      expect(cards.first.margin, const EdgeInsets.symmetric(horizontal: 4));

      for (final card in cards.skip(1)) {
        expect(
          card.margin,
          const EdgeInsets.symmetric(horizontal: 4, vertical: 6),
        );
      }

      final detailsRect = tester.getRect(find.text('DETAILS'));
      final noticeRect = tester.getRect(
        find.byKey(const Key('cache_manage_notice_box')),
      );
      final deepCleanRect = tester.getRect(
        find.byKey(const Key('cache_manage_deep_clean_all')),
      );

      expect(noticeRect.left, closeTo(detailsRect.left, 0.1));
      expect(deepCleanRect.left, closeTo(detailsRect.left, 0.1));
    });

    testWidgets('removes extra horizontal gutters on desktop', (tester) async {
      _setSurfaceSize(tester, const Size(1024, 1600));
      await tester.pumpWidget(_buildTestApp(themeMode: ThemeMode.light));
      await tester.pumpAndSettle();

      final cards = tester.widgetList<Card>(find.byType(Card)).toList();
      expect(cards, hasLength(4));
      expect(cards.first.margin, EdgeInsets.zero);

      for (final card in cards.skip(1)) {
        expect(
          card.margin,
          const EdgeInsets.symmetric(horizontal: 0, vertical: 6),
        );
      }

      final detailsRect = tester.getRect(find.text('DETAILS'));
      final noticeRect = tester.getRect(
        find.byKey(const Key('cache_manage_notice_box')),
      );
      final deepCleanRect = tester.getRect(
        find.byKey(const Key('cache_manage_deep_clean_all')),
      );

      expect(noticeRect.left, closeTo(detailsRect.left, 0.1));
      expect(deepCleanRect.left, closeTo(detailsRect.left, 0.1));
    });

    testWidgets('renders semantic category icons', (tester) async {
      await tester.pumpWidget(_buildTestApp(themeMode: ThemeMode.light));
      await tester.pumpAndSettle();

      expect(find.byIcon(Icons.image_outlined), findsOneWidget);
      expect(find.byIcon(Icons.headphones), findsOneWidget);
      expect(find.byIcon(Icons.folder_outlined), findsOneWidget);
    });

    testWidgets('maps legend and segment colors to palette in light mode', (
      tester,
    ) async {
      await tester.pumpWidget(_buildTestApp(themeMode: ThemeMode.light));
      await tester.pumpAndSettle();

      final audioSegment = tester.widget<Container>(
        find.byKey(const Key('cache_segment_audio')),
      );
      expect(audioSegment.color, AppTheme.lightTheme.colorScheme.tertiary);

      final otherSegment = tester.widget<Container>(
        find.byKey(const Key('cache_segment_other')),
      );
      expect(otherSegment.color, AppTheme.lightTheme.colorScheme.outline);
      expect(
        otherSegment.color,
        isNot(AppTheme.lightTheme.colorScheme.secondary),
      );

      final audioLegend = tester.widget<Container>(
        find.byKey(const Key('cache_legend_audio')),
      );
      final audioLegendDecoration = audioLegend.decoration as BoxDecoration;
      expect(
        audioLegendDecoration.color,
        AppTheme.lightTheme.colorScheme.tertiary,
      );

      final cleanButton = tester.widget<ButtonStyleButton>(
        find.byKey(const Key('cache_manage_clean_images')),
      );
      final cleanForeground = cleanButton.style?.foregroundColor?.resolve(
        <WidgetState>{},
      );
      expect(cleanForeground, AppTheme.lightTheme.colorScheme.onSurfaceVariant);

      final noticeBox = tester.widget<Container>(
        find.byKey(const Key('cache_manage_notice_box')),
      );
      final noticeDecoration = noticeBox.decoration as BoxDecoration;
      expect(
        noticeDecoration.color,
        AppTheme.lightTheme.colorScheme.onSurfaceVariant.withValues(
          alpha: 0.16,
        ),
      );
      final noticeIcon = tester.widget<Icon>(
        find.byKey(const Key('cache_manage_notice_icon')),
      );
      expect(
        noticeIcon.color,
        AppTheme.lightTheme.colorScheme.onSurfaceVariant,
      );
    });

    testWidgets('uses high-contrast deep clean button in dark mode', (
      tester,
    ) async {
      await tester.pumpWidget(_buildTestApp(themeMode: ThemeMode.dark));
      await tester.pumpAndSettle();

      final deepCleanFinder = find.byKey(
        const Key('cache_manage_deep_clean_all'),
      );
      final scrollable = find.descendant(
        of: find.byType(ProfileCacheManagementPage),
        matching: find.byType(Scrollable),
      );
      await tester.scrollUntilVisible(
        deepCleanFinder,
        200,
        scrollable: scrollable.first,
      );

      final deepCleanButton = tester.widget<ButtonStyleButton>(deepCleanFinder);
      final resolvedBackground = deepCleanButton.style?.backgroundColor
          ?.resolve(<WidgetState>{});
      final resolvedForeground = deepCleanButton.style?.foregroundColor
          ?.resolve(<WidgetState>{});

      expect(resolvedBackground, AppTheme.darkTheme.colorScheme.surface);
      expect(resolvedForeground, AppTheme.darkTheme.colorScheme.onSurface);
    });

    testWidgets('stays stable in zero-data state', (tester) async {
      await tester.pumpWidget(_buildTestApp(themeMode: ThemeMode.dark));
      await tester.pumpAndSettle();

      expect(find.byType(ProfileCacheManagementPage), findsOneWidget);
      final noticeBox = tester.widget<Container>(
        find.byKey(const Key('cache_manage_notice_box')),
      );
      final noticeDecoration = noticeBox.decoration as BoxDecoration;
      expect(
        noticeDecoration.color,
        AppTheme.darkTheme.colorScheme.onSurfaceVariant.withValues(alpha: 0.24),
      );
      expect(find.textContaining('0'), findsWidgets);
      expect(tester.takeException(), isNull);
    });
  });
}

void _setSurfaceSize(WidgetTester tester, Size size) {
  tester.view.devicePixelRatio = 1.0;
  tester.view.physicalSize = size;
  addTearDown(() {
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
  });
}

Widget _buildTestApp({required ThemeMode themeMode}) {
  return ProviderScope(
    child: MaterialApp(
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: themeMode,
      locale: const Locale('en'),
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: const ProfileCacheManagementPage(),
    ),
  );
}
