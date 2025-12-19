import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';

import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_player_page.dart';

import '../../../helpers/widget_test_helpers.dart';

void main() {
  group('PodcastPlayerPage Comprehensive Widget Tests', () {
    // === Basic Widget Rendering Tests ===

    testWidgets('renders all required UI components', (WidgetTester tester) async {
      // Arrange
      const episodeId = '123';

      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(episodeId: episodeId),
      ));

      // Assert - Check for key UI elements
      expect(find.byType(AppBar), findsOneWidget);
      expect(find.text('Podcast Player'), findsOneWidget);
      expect(find.byIcon(Icons.audiotrack), findsOneWidget);
      expect(find.text('Podcast Episode Title'), findsOneWidget);
      expect(find.text('Podcast Show Name'), findsOneWidget);
      expect(find.byIcon(Icons.replay_30), findsOneWidget);
      expect(find.byIcon(Icons.play_arrow), findsOneWidget);
      expect(find.byIcon(Icons.forward_30), findsOneWidget);
      expect(find.text('Coming Soon'), findsOneWidget);
    });

    testWidgets('renders without episode ID', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      // Assert - Should still render without errors
      expect(find.byType(AppBar), findsOneWidget);
      expect(find.text('Podcast Player'), findsOneWidget);
      expect(find.byIcon(Icons.audiotrack), findsOneWidget);
    });

    testWidgets('displays correct app bar title', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      // Assert
      expect(find.text('Podcast Player'), findsOneWidget);
    });

    // === Layout and UI Structure Tests ===

    testWidgets('displays episode placeholder image', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      // Assert - Check for placeholder container
      final container = tester.widget<Container>(find.byType(Container).first);
      expect(container.width, 200);
      expect(container.height, 200);

      final decoration = container.decoration as BoxDecoration;
      expect(decoration.color, Colors.grey.shade200);
      expect(decoration.borderRadius, BorderRadius.circular(12));
    });

    testWidgets('displays episode title text', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Assert
      expect(find.text('Podcast Episode Title'), findsOneWidget);

      // Check text styling
      final titleText = tester.widget<Text>(find.text('Podcast Episode Title'));
      expect(titleText.style?.fontSize, 20); // headlineSmall
      expect(titleText.textAlign, TextAlign.center);
    });

    testWidgets('displays show name text', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Assert
      expect(find.text('Podcast Show Name'), findsOneWidget);

      // Check text styling
      final showNameText = tester.widget<Text>(find.text('Podcast Show Name'));
      expect(showNameText.style?.fontSize, 14); // bodyMedium
      expect(showNameText.style?.color, Colors.grey.shade600);
    });

    // === Player Controls Tests ===

    testWidgets('displays all player control buttons', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Assert - Check for all control buttons
      expect(find.byIcon(Icons.replay_30), findsOneWidget);
      expect(find.byIcon(Icons.play_arrow), findsOneWidget);
      expect(find.byIcon(Icons.forward_30), findsOneWidget);

      // Check button sizes
      final rewindButton = tester.widget<IconButton>(find.byIcon(Icons.replay_30));
      expect(rewindButton.iconSize, 32);

      final playButton = tester.widget<IconButton>(find.byIcon(Icons.play_arrow));
      expect(playButton.iconSize, 48);

      final forwardButton = tester.widget<IconButton>(find.byIcon(Icons.forward_30));
      expect(forwardButton.iconSize, 32);
    });

    testWidgets('arranges controls in correct layout', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Assert - Check that controls are in a Row
      final row = find.byType(Row);
      expect(row, findsOneWidget);

      // Check that Row has center alignment
      final rowWidget = tester.widget<Row>(row);
      expect(rowWidget.mainAxisAlignment, MainAxisAlignment.center);

      // Check spacing between buttons
      expect(find.text(' '), findsAtLeastNWidgets(2));
    });

    testWidgets('highlights play button differently', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Assert - Play button should be IconButton.filled (highlighted)
      final playButtons = find.widgetWithIcon(IconButton.filled, Icons.play_arrow);
      expect(playButtons, findsOneWidget);

      // Other buttons should be regular IconButton
      expect(find.widgetWithIcon(IconButton, Icons.replay_30), findsOneWidget);
      expect(find.widgetWithIcon(IconButton, Icons.forward_30), findsOneWidget);
    });

    // === Coming Soon State Tests ===

    testWidgets('displays coming soon message', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Assert
      expect(find.text('Coming Soon'), findsOneWidget);

      // Check text styling
      final comingSoonText = tester.widget<Text>(find.text('Coming Soon'));
      expect(comingSoonText.style?.fontSize, 18);
      expect(comingSoonText.style?.fontWeight, FontWeight.w600);
      expect(comingSoonText.style?.color, Colors.orange);
    });

    // === User Interaction Tests ===

    testWidgets('rewind button is present and tappable', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Act
      await tester.tap(find.byIcon(Icons.replay_30));
      await tester.pump();

      // Assert - Button should be tappable without errors
      expect(find.byType(SnackBar), findsNothing); // No error should appear
    });

    testWidgets('play button is present and tappable', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Act
      await tester.tap(find.byIcon(Icons.play_arrow));
      await tester.pump();

      // Assert - Button should be tappable without errors
      expect(find.byType(SnackBar), findsNothing); // No error should appear
    });

    testWidgets('forward button is present and tappable', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Act
      await tester.tap(find.byIcon(Icons.forward_30));
      await tester.pump();

      // Assert - Button should be tappable without errors
      expect(find.byType(SnackBar), findsNothing); // No error should appear
    });

    // === Navigation Tests ===

    testWidgets('app bar back button is present', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      // Assert - AppBar should have a back navigation
      expect(find.byType(BackButton), findsOneWidget);
    });

    // === Theme Adaptation Tests ===

    testWidgets('adapts to light theme', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        theme: ThemeData.light(),
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Assert - Should use theme colors
      final appBar = tester.widget<AppBar>(find.byType(AppBar));
      expect(appBar.backgroundColor, isNotNull);
    });

    testWidgets('adapts to dark theme', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        theme: ThemeData.dark(),
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Assert - Should use dark theme colors
      final appBar = tester.widget<AppBar>(find.byType(AppBar));
      expect(appBar.backgroundColor, isNotNull);
    });

    // === Layout Responsiveness Tests ===

    testWidgets('handles small screen sizes', (WidgetTester tester) async {
      // Arrange
      tester.binding.window.physicalSizeTestValue = const Size(300, 600);
      tester.binding.window.devicePixelRatioTestValue = 1.0;

      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Assert - Should still render correctly on small screens
      expect(find.byType(AppBar), findsOneWidget);
      expect(find.byType(Center), findsOneWidget);
      expect(find.byType(Column), findsOneWidget);

      // Reset to original size
      addTearDown(() {
        tester.binding.window.clearPhysicalSizeTestValue();
        tester.binding.window.clearDevicePixelRatioTestValue();
      });
    });

    testWidgets('handles large screen sizes', (WidgetTester tester) async {
      // Arrange
      tester.binding.window.physicalSizeTestValue = const Size(800, 1200);
      tester.binding.window.devicePixelRatioTestValue = 1.0;

      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Assert - Should still render correctly on large screens
      expect(find.byType(AppBar), findsOneWidget);
      expect(find.byType(Center), findsOneWidget);

      // Reset to original size
      addTearDown(() {
        tester.binding.window.clearPhysicalSizeTestValue();
        tester.binding.window.clearDevicePixelRatioTestValue();
      });
    });

    // === Accessibility Tests ===

    testWidgets('supports semantic labels for screen readers', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Assert - Verify semantic labels exist
      expect(
        tester.semantics.findByLabel('Back'),
        findsOneWidget,
      );

      // Control buttons should have proper semantics
      expect(
        tester.semantics.hasLabel('Rewind 30 seconds'),
        isTrue,
      );

      expect(
        tester.semantics.hasLabel('Play'),
        isTrue,
      );

      expect(
        tester.semantics.hasLabel('Forward 30 seconds'),
        isTrue,
      );
    });

    testWidgets('buttons are focusable with keyboard', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      await tester.pumpAndSettle();

      // Assert - IconButton widgets should be focusable
      final rewindButton = tester.widget<IconButton>(find.byIcon(Icons.replay_30));
      expect(rewindButton.focusNode?.canFocus, isTrue);

      final playButton = tester.widget<IconButton.filled>(find.byIcon(Icons.play_arrow));
      expect(playButton.focusNode?.canFocus, isTrue);

      final forwardButton = tester.widget<IconButton>(find.byIcon(Icons.forward_30));
      expect(forwardButton.focusNode?.canFocus, isTrue);
    });

    // === Performance Tests ===

    testWidgets('widget builds within reasonable time', (WidgetTester tester) async {
      // Arrange
      final stopwatch = Stopwatch()..start();

      // Act
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(),
      ));

      stopwatch.stop();

      // Assert - Build should complete within reasonable time (less than 100ms)
      expect(stopwatch.elapsedMilliseconds, lessThan(100));
    });

    testWidgets('widget does not rebuild unnecessarily', (WidgetTester tester) async {
      // Arrange
      int buildCount = 0;

      await tester.pumpWidget(createTestWidget(
        child: Builder(
          builder: (context) {
            buildCount++;
            return const PodcastPlayerPage();
          },
        ),
      ));

      // Act - Trigger a rebuild
      await tester.pump();

      // Assert - Should only build once (no unnecessary rebuilds)
      expect(buildCount, equals(1));
    });

    // === Error Handling Tests ===

    testWidgets('gracefully handles missing episode ID', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(episodeId: null),
      ));

      await tester.pumpAndSettle();

      // Assert - Should still render without errors
      expect(find.byType(PodcastPlayerPage), findsOneWidget);
      expect(find.byType(AppBar), findsOneWidget);
      expect(find.text('Podcast Player'), findsOneWidget);
    });

    testWidgets('gracefully handles empty episode ID', (WidgetTester tester) async {
      // Arrange
      await tester.pumpWidget(createTestWidget(
        child: const PodcastPlayerPage(episodeId: ''),
      ));

      await tester.pumpAndSettle();

      // Assert - Should still render without errors
      expect(find.byType(PodcastPlayerPage), findsOneWidget);
      expect(find.byType(AppBar), findsOneWidget);
    });
  });
}