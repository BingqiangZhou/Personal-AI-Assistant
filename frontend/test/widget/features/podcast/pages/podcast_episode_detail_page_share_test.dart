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
  testWidgets('AI summary tab shows share-all when summary exists', (
    tester,
  ) async {
    await tester.pumpWidget(
      _createWidget(hasSummary: true, episodeSummary: null),
    );

    await tester.pumpAndSettle();
    final context = tester.element(find.byType(PodcastEpisodeDetailPage));
    final l10n = AppLocalizations.of(context)!;

    await tester.tap(find.text(l10n.podcast_filter_with_summary).first);
    await tester.pumpAndSettle();

    expect(find.text(l10n.podcast_share_all_content), findsOneWidget);
  });

  testWidgets('AI summary tab hides share-all when summary is empty', (
    tester,
  ) async {
    await tester.pumpWidget(
      _createWidget(hasSummary: false, episodeSummary: null),
    );

    await tester.pumpAndSettle();
    final context = tester.element(find.byType(PodcastEpisodeDetailPage));
    final l10n = AppLocalizations.of(context)!;

    await tester.tap(find.text(l10n.podcast_filter_with_summary).first);
    await tester.pumpAndSettle();

    expect(find.text(l10n.podcast_share_all_content), findsNothing);
  });
}

Widget _createWidget({
  required bool hasSummary,
  required String? episodeSummary,
}) {
  return ProviderScope(
    overrides: [
      audioPlayerProvider.overrideWith(_MockAudioPlayerNotifier.new),
      episodeDetailProvider.overrideWith(
        (ref, episodeId) async => _episodeDetail(episodeSummary),
      ),
      getSummaryProvider(1).overrideWith(
        () => hasSummary
            ? _SummaryWithContentNotifier()
            : _SummaryEmptyNotifier(),
      ),
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
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: const PodcastEpisodeDetailPage(episodeId: 1),
    ),
  );
}

PodcastEpisodeDetailResponse _episodeDetail(String? summary) {
  final now = DateTime.now();
  return PodcastEpisodeDetailResponse(
    id: 1,
    subscriptionId: 1,
    title: 'Test Episode',
    description: 'Description',
    audioUrl: 'https://example.com/audio.mp3',
    audioDuration: 180,
    publishedAt: now,
    aiSummary: summary,
    createdAt: now,
    updatedAt: now,
    relatedEpisodes: const [],
  );
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

class _SummaryEmptyNotifier extends SummaryNotifier {
  _SummaryEmptyNotifier() : super(1);

  @override
  SummaryState build() {
    return const SummaryState();
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
