import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/audio_player_state_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_conversation_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_playback_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_transcription_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/pages/podcast_episode_detail_page.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/conversation_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/summary_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/transcription_providers.dart';

void main() {
  group('PodcastEpisodeDetailPage mobile tab indicator', () {
    testWidgets('initial state shows only indicator_0', (tester) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(390, 844));

      await tester.pumpWidget(_createWidget(themeMode: ThemeMode.light));
      await tester.pumpAndSettle();

      expect(_indicatorColor(tester, 0), isNot(Colors.transparent));
      expect(_indicatorColor(tester, 1), Colors.transparent);
      expect(_indicatorColor(tester, 2), Colors.transparent);
      expect(_indicatorColor(tester, 3), Colors.transparent);
    });

    testWidgets('first tab starts near 8px from left edge', (tester) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(390, 844));

      await tester.pumpWidget(_createWidget(themeMode: ThemeMode.light));
      await tester.pumpAndSettle();

      final firstTabLeft = tester
          .getTopLeft(find.byKey(const Key('episode_detail_mobile_tab_0')))
          .dx;

      expect(firstTabLeft, greaterThanOrEqualTo(6));
      expect(firstTabLeft, lessThanOrEqualTo(14));
    });

    testWidgets('first tab stays left-aligned on wide mobile width', (
      tester,
    ) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(700, 844));

      await tester.pumpWidget(_createWidget(themeMode: ThemeMode.light));
      await tester.pumpAndSettle();

      final firstTabLeft = tester
          .getTopLeft(find.byKey(const Key('episode_detail_mobile_tab_0')))
          .dx;

      expect(firstTabLeft, greaterThanOrEqualTo(6));
      expect(firstTabLeft, lessThanOrEqualTo(14));
    });

    testWidgets('tab bar top padding is reduced to 6px', (tester) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(390, 844));

      await tester.pumpWidget(_createWidget(themeMode: ThemeMode.light));
      await tester.pumpAndSettle();

      final tabBarContainer = find
          .ancestor(
            of: find.byKey(const Key('episode_detail_mobile_tab_0')),
            matching: find.byWidgetPredicate((widget) {
              if (widget is! Container) return false;
              final decoration = widget.decoration;
              if (decoration is! BoxDecoration) return false;
              final border = decoration.border;
              if (border is! Border) return false;
              return border.bottom.width == 1;
            }),
          )
          .first;

      final containerWidget = tester.widget<Container>(tabBarContainer);
      final padding = containerWidget.padding;

      expect(padding, isA<EdgeInsets>());
      expect((padding as EdgeInsets).top, 6);
    });

    testWidgets('indicator line is aligned with tab bar bottom divider line', (
      tester,
    ) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(390, 844));

      await tester.pumpWidget(_createWidget(themeMode: ThemeMode.light));
      await tester.pumpAndSettle();

      final tabBarContainer = find
          .ancestor(
            of: find.byKey(const Key('episode_detail_mobile_tab_0')),
            matching: find.byWidgetPredicate((widget) {
              if (widget is! Container) return false;
              final decoration = widget.decoration;
              if (decoration is! BoxDecoration) return false;
              final border = decoration.border;
              if (border is! Border) return false;
              return border.bottom.width == 1;
            }),
          )
          .first;

      final dividerBottomY = tester.getBottomLeft(tabBarContainer).dy;
      final indicatorBottomY = tester
          .getBottomLeft(
            find.byKey(const Key('episode_detail_mobile_tab_indicator_0')),
          )
          .dy;

      expect((indicatorBottomY - dividerBottomY).abs(), lessThanOrEqualTo(1.5));
    });

    testWidgets('indicator width matches selected tab text width', (
      tester,
    ) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(390, 844));

      await tester.pumpWidget(_createWidget(themeMode: ThemeMode.light));
      await tester.pumpAndSettle();

      final tabFinder = find.byKey(const Key('episode_detail_mobile_tab_0'));
      final textFinder = find
          .descendant(of: tabFinder, matching: find.byType(Text))
          .first;
      final indicatorFinder = find.byKey(
        const Key('episode_detail_mobile_tab_indicator_0'),
      );

      final textWidth = tester.getSize(textFinder).width;
      final indicatorWidth = tester.getSize(indicatorFinder).width;

      expect((indicatorWidth - textWidth).abs(), lessThanOrEqualTo(2.5));
    });

    testWidgets('tap summary tab shows only indicator_2', (tester) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(390, 844));

      await tester.pumpWidget(_createWidget(themeMode: ThemeMode.light));
      await tester.pumpAndSettle();

      final summaryTabFinder = find.byKey(
        const Key('episode_detail_mobile_tab_2'),
      );
      await tester.ensureVisible(summaryTabFinder);
      await tester.pumpAndSettle();
      await tester.tap(summaryTabFinder);
      await tester.pumpAndSettle();

      expect(_indicatorColor(tester, 0), Colors.transparent);
      expect(_indicatorColor(tester, 1), Colors.transparent);
      expect(_indicatorColor(tester, 2), isNot(Colors.transparent));
      expect(_indicatorColor(tester, 3), Colors.transparent);
    });

    testWidgets('swipe page view to chat shows indicator_3', (tester) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(390, 844));

      await tester.pumpWidget(_createWidget(themeMode: ThemeMode.light));
      await tester.pumpAndSettle();

      final pageViewFinder = find.byType(PageView);
      expect(pageViewFinder, findsOneWidget);

      await tester.drag(pageViewFinder, const Offset(-450, 0));
      await tester.pumpAndSettle();
      await tester.drag(pageViewFinder, const Offset(-450, 0));
      await tester.pumpAndSettle();
      await tester.drag(pageViewFinder, const Offset(-450, 0));
      await tester.pumpAndSettle();

      expect(_indicatorColor(tester, 0), Colors.transparent);
      expect(_indicatorColor(tester, 1), Colors.transparent);
      expect(_indicatorColor(tester, 2), Colors.transparent);
      expect(_indicatorColor(tester, 3), isNot(Colors.transparent));
    });

    testWidgets('light theme indicator color uses colorScheme.primary', (
      tester,
    ) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(390, 844));

      await tester.pumpWidget(_createWidget(themeMode: ThemeMode.light));
      await tester.pumpAndSettle();

      final context = tester.element(
        find.byKey(const Key('episode_detail_mobile_tab_indicator_0')),
      );

      expect(_indicatorColor(tester, 0), Theme.of(context).colorScheme.primary);
    });

    testWidgets('dark theme indicator color uses colorScheme.primary', (
      tester,
    ) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(390, 844));

      await tester.pumpWidget(_createWidget(themeMode: ThemeMode.dark));
      await tester.pumpAndSettle();

      final context = tester.element(
        find.byKey(const Key('episode_detail_mobile_tab_indicator_0')),
      );

      expect(_indicatorColor(tester, 0), Theme.of(context).colorScheme.primary);
    });
  });
}

Widget _createWidget({required ThemeMode themeMode}) {
  return ProviderScope(
    overrides: [
      audioPlayerProvider.overrideWith(_MockAudioPlayerNotifier.new),
      episodeDetailProvider.overrideWith((ref, episodeId) async => _episode()),
      getSummaryProvider(1).overrideWith(() => _SummaryWithContentNotifier()),
      getTranscriptionProvider(
        1,
      ).overrideWith(() => _NoopTranscriptionNotifier(1)),
      getConversationProvider(
        1,
      ).overrideWith(() => _ConversationWithoutMessagesNotifier()),
      getSessionListProvider(1).overrideWith(() => _EmptySessionListNotifier()),
      getCurrentSessionIdProvider(
        1,
      ).overrideWith(() => _NullSessionIdNotifier()),
      availableModelsProvider.overrideWith((ref) async => <SummaryModelInfo>[]),
    ],
    child: MaterialApp(
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: Colors.blue),
      darkTheme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        colorSchemeSeed: Colors.blue,
      ),
      themeMode: themeMode,
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: const PodcastEpisodeDetailPage(episodeId: 1),
    ),
  );
}

PodcastEpisodeDetailResponse _episode() {
  final now = DateTime.now();
  return PodcastEpisodeDetailResponse(
    id: 1,
    subscriptionId: 1,
    title: 'Test Episode',
    description: 'Description',
    audioUrl: 'https://example.com/audio.mp3',
    audioDuration: 180,
    publishedAt: now,
    aiSummary: 'summary',
    transcriptContent: 'Transcript content',
    status: 'published',
    createdAt: now,
    updatedAt: now,
    relatedEpisodes: const [],
  );
}

Color _indicatorColor(WidgetTester tester, int index) {
  final indicator = tester.widget<Container>(
    find.byKey(Key('episode_detail_mobile_tab_indicator_$index')),
  );
  final decoration = indicator.decoration as BoxDecoration?;
  return decoration?.color ?? Colors.transparent;
}

class _MockAudioPlayerNotifier extends AudioPlayerNotifier {
  @override
  AudioPlayerState build() {
    return const AudioPlayerState();
  }
}

class _NoopTranscriptionNotifier extends TranscriptionNotifier {
  _NoopTranscriptionNotifier(super.episodeId);

  @override
  Future<PodcastTranscriptionResponse?> build() async {
    return PodcastTranscriptionResponse(
      id: 1,
      episodeId: episodeId,
      status: 'completed',
      transcriptContent: 'Transcript content',
      createdAt: DateTime.now(),
    );
  }

  @override
  Future<void> checkOrStartTranscription() async {}

  @override
  Future<void> startTranscription() async {}

  @override
  Future<void> loadTranscription() async {}
}

class _SummaryWithContentNotifier extends SummaryNotifier {
  _SummaryWithContentNotifier() : super(1);

  @override
  SummaryState build() {
    return const SummaryState(summary: 'Generated summary');
  }
}

class _ConversationWithoutMessagesNotifier extends ConversationNotifier {
  _ConversationWithoutMessagesNotifier() : super(1);

  @override
  ConversationState build() {
    return const ConversationState(messages: []);
  }
}

class _EmptySessionListNotifier extends SessionListNotifier {
  _EmptySessionListNotifier() : super(1);

  @override
  Future<List<ConversationSession>> build() async => [];
}

class _NullSessionIdNotifier extends SessionIdNotifier {
  @override
  int? build() => null;
}
