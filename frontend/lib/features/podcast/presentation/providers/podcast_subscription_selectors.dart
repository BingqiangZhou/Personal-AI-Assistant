import 'dart:collection';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../data/utils/podcast_url_utils.dart';
import 'podcast_providers.dart';

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
