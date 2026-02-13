import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/feed_style_episode_card.dart';

void main() {
  testWidgets(
    'FeedStyleEpisodeCard shows 2-line description and metadata row with right play button',
    (WidgetTester tester) async {
      final episode = PodcastEpisodeModel(
        id: 1,
        subscriptionId: 1,
        subscriptionTitle: 'Sample Show',
        title: 'S2E7 Why does luck look effortless?',
        description:
            'What is luck, really? Is it money, connections, or freedom? '
            'Why do some people burn out while others seem to move smoothly? '
            'This episode explores myths and reality around good fortune.',
        audioUrl: 'https://example.com/audio.mp3',
        audioDuration: 4143,
        publishedAt: DateTime(2026, 2, 13),
        createdAt: DateTime(2026, 2, 13),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: Scaffold(
              body: FeedStyleEpisodeCard(episode: episode, onPlay: () {}),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      final descriptionFinder = find.byKey(const Key('feed_style_description'));
      final metadataFinder = find.byKey(const Key('feed_style_metadata'));
      final playButtonFinder = find.byKey(const Key('feed_style_play_button'));

      expect(descriptionFinder, findsOneWidget);
      expect(metadataFinder, findsOneWidget);
      expect(playButtonFinder, findsOneWidget);

      final descriptionText = tester.widget<Text>(descriptionFinder);
      expect(descriptionText.maxLines, 2);

      final descriptionRect = tester.getRect(descriptionFinder);
      final metadataRect = tester.getRect(metadataFinder);
      final playButtonRect = tester.getRect(playButtonFinder);

      expect(metadataRect.top, greaterThan(descriptionRect.bottom));
      expect(playButtonRect.center.dx, greaterThan(metadataRect.center.dx));
    },
  );
}
