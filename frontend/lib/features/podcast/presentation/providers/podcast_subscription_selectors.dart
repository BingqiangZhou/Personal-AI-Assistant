import 'dart:collection';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:personal_ai_assistant/features/podcast/data/utils/podcast_url_utils.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';

final subscribedNormalizedFeedUrlsProvider = Provider<Set<String>>((ref) {
  final subscriptions = ref.watch(
    podcastSubscriptionProvider.select((state) => state.subscriptions),
  );
  return UnmodifiableSetView(
    subscriptions
        .map((sub) => PodcastUrlUtils.normalizeFeedUrl(sub.sourceUrl))
        .toSet(),
  );
});

final subscribingNormalizedFeedUrlsProvider = Provider<Set<String>>((ref) {
  final subscribingFeedUrls = ref.watch(
    podcastSubscriptionProvider.select((state) => state.subscribingFeedUrls),
  );
  return UnmodifiableSetView(
    subscribingFeedUrls.map(PodcastUrlUtils.normalizeFeedUrl).toSet(),
  );
});
