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
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/shownotes_display_widget.dart';

void main() {
  group('PodcastEpisodeDetailPage new layout tests', () {
    testWidgets('renders header and all mobile tabs', (tester) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(390, 844));

      await tester.pumpWidget(
        _createWidget(themeMode: ThemeMode.light, episode: _episode()),
      );
      await tester.pumpAndSettle();

      final context = tester.element(find.byType(PodcastEpisodeDetailPage));
      final l10n = AppLocalizations.of(context)!;

      expect(find.text('Test Episode'), findsOneWidget);
      expect(find.text(l10n.podcast_tab_shownotes), findsWidgets);
      expect(find.text(l10n.podcast_tab_transcript), findsOneWidget);
      expect(find.text(l10n.podcast_filter_with_summary), findsOneWidget);
      expect(find.text(l10n.podcast_tab_chat), findsOneWidget);

      expect(
        find.byKey(const Key('episode_detail_mobile_tab_0')),
        findsOneWidget,
      );
      expect(
        find.byKey(const Key('episode_detail_mobile_tab_1')),
        findsOneWidget,
      );
      expect(
        find.byKey(const Key('episode_detail_mobile_tab_2')),
        findsOneWidget,
      );
      expect(
        find.byKey(const Key('episode_detail_mobile_tab_3')),
        findsOneWidget,
      );

      expect(find.byType(ShownotesDisplayWidget), findsOneWidget);
      expect(find.text(l10n.podcast_source), findsOneWidget);
    });

    testWidgets('tap summary tab updates indicator selection', (tester) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(390, 844));

      await tester.pumpWidget(
        _createWidget(themeMode: ThemeMode.light, episode: _episode()),
      );
      await tester.pumpAndSettle();

      final summaryTabFinder = find.byKey(
        const Key('episode_detail_mobile_tab_2'),
      );
      await tester.ensureVisible(summaryTabFinder);
      await tester.tap(summaryTabFinder);
      await tester.pumpAndSettle();

      expect(_indicatorColor(tester, 0), Colors.transparent);
      expect(_indicatorColor(tester, 1), Colors.transparent);
      expect(_indicatorColor(tester, 2), isNot(Colors.transparent));
      expect(_indicatorColor(tester, 3), Colors.transparent);
      expect(find.text('Generated summary'), findsOneWidget);
    });

    testWidgets('tap transcript tab updates indicator selection', (
      tester,
    ) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(390, 844));

      await tester.pumpWidget(
        _createWidget(themeMode: ThemeMode.light, episode: _episode()),
      );
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('episode_detail_mobile_tab_1')));
      await tester.pumpAndSettle();

      expect(_indicatorColor(tester, 0), Colors.transparent);
      expect(_indicatorColor(tester, 1), isNot(Colors.transparent));
      expect(_indicatorColor(tester, 2), Colors.transparent);
      expect(_indicatorColor(tester, 3), Colors.transparent);
      expect(find.textContaining('Transcript content'), findsOneWidget);
    });

    testWidgets('shows localized error state when episode is not found', (
      tester,
    ) async {
      addTearDown(() async => tester.binding.setSurfaceSize(null));
      await tester.binding.setSurfaceSize(const Size(390, 844));

      await tester.pumpWidget(
        _createWidget(themeMode: ThemeMode.light, episode: null),
      );
      await tester.pumpAndSettle();

      final context = tester.element(find.byType(PodcastEpisodeDetailPage));
      final l10n = AppLocalizations.of(context)!;

      expect(find.text(l10n.podcast_error_loading), findsOneWidget);
      expect(find.text(l10n.podcast_episode_not_found), findsOneWidget);
      expect(find.text(l10n.podcast_go_back), findsOneWidget);
      expect(find.byIcon(Icons.error_outline), findsOneWidget);
    });
  });
}

Widget _createWidget({
  required ThemeMode themeMode,
  required PodcastEpisodeDetailResponse? episode,
}) {
  return ProviderScope(
    overrides: [
      audioPlayerProvider.overrideWith(_MockAudioPlayerNotifier.new),
      episodeDetailProvider.overrideWith((ref, episodeId) async => episode),
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
    itemLink: 'https://example.com/source',
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
