import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_conversation_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_playback_model.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_transcription_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/conversation_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/summary_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/conversation_chat_widget.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/transcript_display_widget.dart';

void main() {
  testWidgets('Conversation chat shows share-all entry when messages exist', (
    tester,
  ) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          getConversationProvider(
            1,
          ).overrideWith(() => _ConversationWithMessagesNotifier()),
          getSessionListProvider(
            1,
          ).overrideWith(() => _EmptySessionListNotifier()),
          getCurrentSessionIdProvider(
            1,
          ).overrideWith(() => _NullSessionIdNotifier()),
          availableModelsProvider.overrideWith(
            (ref) async => <SummaryModelInfo>[],
          ),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const Scaffold(
            body: ConversationChatWidget(
              episodeId: 1,
              episodeTitle: 'Test Episode',
              aiSummary: 'Summary exists',
            ),
          ),
        ),
      ),
    );

    await tester.pumpAndSettle();

    expect(find.byTooltip('Share All'), findsOneWidget);
  });

  testWidgets('Transcript widget has no share-all entry', (tester) async {
    final transcription = PodcastTranscriptionResponse(
      id: 1,
      episodeId: 1,
      status: 'completed',
      transcriptContent: 'This is a transcript sentence.',
      createdAt: DateTime.now(),
    );

    await tester.pumpWidget(
      ProviderScope(
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: Scaffold(
            body: TranscriptDisplayWidget(
              episodeId: 1,
              episodeTitle: 'Test Episode',
              transcription: transcription,
            ),
          ),
        ),
      ),
    );

    await tester.pumpAndSettle();

    expect(find.byTooltip('Share All'), findsNothing);
    expect(find.text('Share All'), findsNothing);
  });
}

class _ConversationWithMessagesNotifier extends ConversationNotifier {
  _ConversationWithMessagesNotifier() : super(1);

  @override
  ConversationState build() {
    return ConversationState(
      messages: [
        PodcastConversationMessage(
          id: 1,
          role: 'assistant',
          content: 'Hello from assistant',
          conversationTurn: 1,
          createdAt: DateTime.now().toIso8601String(),
        ),
      ],
    );
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
