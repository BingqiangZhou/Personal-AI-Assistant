import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_search_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/constants/podcast_ui_constants.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_search_result_card.dart';

void main() {
  group('PodcastSearchResultCard layout', () {
    testWidgets('uses subscription-style shell and keeps search metadata', (
      tester,
    ) async {
      const result = PodcastSearchResult(
        collectionName: 'Daily Pod',
        artistName: 'Jane Host',
        feedUrl: 'https://example.com/feed.xml',
        primaryGenreName: 'Technology',
        trackCount: 42,
      );

      await tester.pumpWidget(
        const MaterialApp(
          locale: Locale('en'),
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: Scaffold(body: PodcastSearchResultCard(result: result)),
        ),
      );
      await tester.pumpAndSettle();

      final card = tester.widget<Card>(find.byType(Card));
      expect(
        card.margin,
        const EdgeInsets.symmetric(
          horizontal: kPodcastRowCardHorizontalMargin,
          vertical: kPodcastRowCardVerticalMargin,
        ),
      );
      expect(card.shape, isA<RoundedRectangleBorder>());
      final rounded = card.shape! as RoundedRectangleBorder;
      final radius = rounded.borderRadius.resolve(TextDirection.ltr);
      expect(radius.topLeft.x, kPodcastRowCardCornerRadius);
      expect(radius.topRight.x, kPodcastRowCardCornerRadius);

      final artwork = tester.widget<SizedBox>(
        find.byKey(const Key('podcast_search_result_card_artwork')),
      );
      expect(artwork.width, kPodcastRowCardImageSize);
      expect(artwork.height, kPodcastRowCardImageSize);

      expect(find.text('Daily Pod'), findsOneWidget);
      expect(find.text('Jane Host'), findsOneWidget);
      expect(find.text('Technology'), findsOneWidget);
      expect(find.textContaining('42'), findsOneWidget);
      expect(find.byIcon(Icons.add_circle_outline), findsOneWidget);
    });
  });
}
