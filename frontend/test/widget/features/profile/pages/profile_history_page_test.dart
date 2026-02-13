import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/playback_history_lite_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_image_widget.dart';
import 'package:personal_ai_assistant/features/profile/presentation/pages/profile_history_page.dart';

void main() {
  testWidgets('renders history list from lightweight provider', (
    WidgetTester tester,
  ) async {
    final now = DateTime.now();

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          playbackHistoryLiteProvider.overrideWith((ref) async {
            return PlaybackHistoryLiteResponse(
              episodes: [
                PlaybackHistoryLiteItem(
                  id: 101,
                  subscriptionId: 2,
                  subscriptionTitle: 'Podcast X',
                  subscriptionImageUrl: null,
                  title: 'Episode X',
                  imageUrl: null,
                  audioDuration: 1800,
                  playbackPosition: 120,
                  lastPlayedAt: now,
                  publishedAt: now.subtract(const Duration(days: 1)),
                ),
                PlaybackHistoryLiteItem(
                  id: 102,
                  subscriptionId: 3,
                  subscriptionTitle: 'Podcast Y',
                  subscriptionImageUrl: 'https://example.com/sub.png',
                  title: 'Episode Y',
                  imageUrl: 'https://example.com/ep.png',
                  audioDuration: 2400,
                  playbackPosition: 300,
                  lastPlayedAt: now.subtract(const Duration(minutes: 3)),
                  publishedAt: now.subtract(const Duration(days: 2)),
                ),
              ],
              total: 2,
              page: 1,
              size: 100,
              pages: 1,
            );
          }),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const ProfileHistoryPage(),
        ),
      ),
    );

    await tester.pumpAndSettle();

    expect(find.text('Episode X'), findsOneWidget);
    expect(find.text('Episode Y'), findsOneWidget);
    expect(find.byType(ListTile), findsNWidgets(2));
    expect(find.byType(PodcastImageWidget), findsNWidgets(2));
  });
}
