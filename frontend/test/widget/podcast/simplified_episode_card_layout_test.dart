import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_episode_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/simplified_episode_card.dart';

void main() {
  group('SimplifiedEpisodeCard layout', () {
    testWidgets(
      'mobile layout removes cover and subscription tag, keeps metadata and action icons',
      (WidgetTester tester) async {
        tester.view.physicalSize = const Size(390, 844);
        tester.view.devicePixelRatio = 1.0;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        final episode = _buildEpisode();

        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              localizationsDelegates: AppLocalizations.localizationsDelegates,
              supportedLocales: AppLocalizations.supportedLocales,
              home: Scaffold(
                body: SimplifiedEpisodeCard(
                  episode: episode,
                  onTap: () {},
                  onPlay: () {},
                  onAddToQueue: () {},
                ),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();

        final headerFinder = find.byKey(
          const Key('simplified_episode_header_row'),
        );
        final descriptionFinder = find.byKey(
          const Key('simplified_episode_description'),
        );
        final metadataFinder = find.byKey(
          const Key('simplified_episode_metadata'),
        );
        final metaActionRowFinder = find.byKey(
          const Key('simplified_episode_meta_action_row'),
        );
        final addButtonFinder = find.byKey(
          const Key('simplified_episode_add_to_queue'),
        );
        final playButtonFinder = find.byKey(
          const Key('simplified_episode_play'),
        );

        expect(headerFinder, findsOneWidget);
        expect(descriptionFinder, findsOneWidget);
        expect(metadataFinder, findsOneWidget);
        expect(metaActionRowFinder, findsOneWidget);
        expect(addButtonFinder, findsOneWidget);
        expect(playButtonFinder, findsOneWidget);

        expect(find.text(episode.title), findsOneWidget);
        expect(find.text('Sample Show'), findsNothing);
        expect(find.byIcon(Icons.podcasts), findsNothing);

        final descriptionText = tester.widget<Text>(descriptionFinder);
        expect(descriptionText.maxLines, 2);

        expect(find.text('2026-02-10'), findsOneWidget);
        expect(find.text(episode.formattedDuration), findsOneWidget);

        final metadataRect = tester.getRect(metadataFinder);
        final addButtonRect = tester.getRect(addButtonFinder);
        final playButtonRect = tester.getRect(playButtonFinder);

        expect(addButtonRect.center.dx, greaterThan(metadataRect.center.dx));
        expect(playButtonRect.center.dx, greaterThan(addButtonRect.center.dx));
        expect(
          (playButtonRect.center.dy - addButtonRect.center.dy).abs(),
          lessThan(1),
        );
      },
    );

    testWidgets(
      'desktop layout keeps same structure and uses 4-line description',
      (WidgetTester tester) async {
        tester.view.physicalSize = const Size(1200, 900);
        tester.view.devicePixelRatio = 1.0;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        final episode = _buildEpisode();

        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              localizationsDelegates: AppLocalizations.localizationsDelegates,
              supportedLocales: AppLocalizations.supportedLocales,
              home: Scaffold(
                body: Center(
                  child: SizedBox(
                    width: 360,
                    child: SimplifiedEpisodeCard(
                      episode: episode,
                      onTap: () {},
                      onPlay: () {},
                      onAddToQueue: () {},
                    ),
                  ),
                ),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();

        final descriptionFinder = find.byKey(
          const Key('simplified_episode_description'),
        );
        final metadataFinder = find.byKey(
          const Key('simplified_episode_metadata'),
        );
        final addButtonFinder = find.byKey(
          const Key('simplified_episode_add_to_queue'),
        );
        final playButtonFinder = find.byKey(
          const Key('simplified_episode_play'),
        );

        expect(descriptionFinder, findsOneWidget);
        expect(metadataFinder, findsOneWidget);
        expect(addButtonFinder, findsOneWidget);
        expect(playButtonFinder, findsOneWidget);

        expect(find.text('Sample Show'), findsNothing);
        expect(find.byIcon(Icons.podcasts), findsNothing);

        final descriptionText = tester.widget<Text>(descriptionFinder);
        expect(descriptionText.maxLines, 4);

        final metadataRect = tester.getRect(metadataFinder);
        final addButtonRect = tester.getRect(addButtonFinder);
        final playButtonRect = tester.getRect(playButtonFinder);

        expect(addButtonRect.center.dx, greaterThan(metadataRect.center.dx));
        expect(playButtonRect.center.dx, greaterThan(addButtonRect.center.dx));
      },
    );
  });
}

PodcastEpisodeModel _buildEpisode() {
  return PodcastEpisodeModel(
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
    publishedAt: DateTime(2026, 2, 10),
    createdAt: DateTime(2026, 2, 10),
  );
}
