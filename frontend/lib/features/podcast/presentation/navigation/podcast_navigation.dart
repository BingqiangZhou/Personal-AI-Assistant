import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../data/models/podcast_subscription_model.dart';

/// Navigation arguments for podcast episodes page
class PodcastEpisodesPageArgs {
  final int subscriptionId;
  final String? podcastTitle;
  final PodcastSubscriptionModel? subscription;

  const PodcastEpisodesPageArgs({
    required this.subscriptionId,
    this.podcastTitle,
    this.subscription,
  });

  /// Creates args from a subscription object
  factory PodcastEpisodesPageArgs.fromSubscription(PodcastSubscriptionModel subscription) {
    return PodcastEpisodesPageArgs(
      subscriptionId: subscription.id,
      podcastTitle: subscription.title,
      subscription: subscription,
    );
  }

  /// Extracts args from GoRouter state
  static PodcastEpisodesPageArgs? extractFromState(GoRouterState state) {
    final subscriptionIdStr = state.pathParameters['subscriptionId'];
    if (subscriptionIdStr == null) return null;

    final subscriptionId = int.tryParse(subscriptionIdStr);
    if (subscriptionId == null) return null;

    return PodcastEpisodesPageArgs(
      subscriptionId: subscriptionId,
      podcastTitle: state.uri.queryParameters['title'],
    );
  }
}

/// Navigation arguments for podcast episode detail page
class PodcastEpisodeDetailPageArgs {
  final int episodeId;
  final int subscriptionId;
  final String? episodeTitle;

  const PodcastEpisodeDetailPageArgs({
    required this.episodeId,
    required this.subscriptionId,
    this.episodeTitle,
  });

  /// Extracts args from GoRouter state
  static PodcastEpisodeDetailPageArgs? extractFromState(GoRouterState state) {
    final episodeIdStr = state.pathParameters['episodeId'];
    final subscriptionIdStr = state.pathParameters['subscriptionId'];

    if (episodeIdStr == null || subscriptionIdStr == null) return null;

    final episodeId = int.tryParse(episodeIdStr);
    final subscriptionId = int.tryParse(subscriptionIdStr);

    if (episodeId == null || subscriptionId == null) return null;

    return PodcastEpisodeDetailPageArgs(
      episodeId: episodeId,
      subscriptionId: subscriptionId,
      episodeTitle: state.uri.queryParameters['title'],
    );
  }
}

/// Navigation arguments for podcast player page
class PodcastPlayerPageArgs {
  final int episodeId;
  final int subscriptionId;
  final String? episodeTitle;
  final String? audioUrl;
  final int? startPosition;

  const PodcastPlayerPageArgs({
    required this.episodeId,
    required this.subscriptionId,
    this.episodeTitle,
    this.audioUrl,
    this.startPosition,
  });

  /// Extracts args from GoRouter state
  static PodcastPlayerPageArgs? extractFromState(GoRouterState state) {
    final episodeIdStr = state.pathParameters['episodeId'];
    final subscriptionIdStr = state.pathParameters['subscriptionId'];

    if (episodeIdStr == null || subscriptionIdStr == null) return null;

    final episodeId = int.tryParse(episodeIdStr);
    final subscriptionId = int.tryParse(subscriptionIdStr);

    if (episodeId == null || subscriptionId == null) return null;

    final startPositionStr = state.uri.queryParameters['position'];
    final startPosition = startPositionStr != null ? int.tryParse(startPositionStr) : null;

    return PodcastPlayerPageArgs(
      episodeId: episodeId,
      subscriptionId: subscriptionId,
      episodeTitle: state.uri.queryParameters['title'],
      audioUrl: state.uri.queryParameters['audioUrl'],
      startPosition: startPosition,
    );
  }
}

/// Helper class for podcast navigation
class PodcastNavigation {
  const PodcastNavigation._();

  /// Navigate to episodes page
  static void goToEpisodes(
    BuildContext context, {
    required int subscriptionId,
    String? podcastTitle,
  }) {
    context.pushNamed(
      'podcastEpisodes',
      pathParameters: {'subscriptionId': subscriptionId.toString()},
      queryParameters: podcastTitle != null ? {'title': podcastTitle} : null,
    );
  }

  /// Navigate to episodes page from subscription object
  static void goToEpisodesFromSubscription(
    BuildContext context,
    PodcastSubscriptionModel subscription,
  ) {
    goToEpisodes(
      context,
      subscriptionId: subscription.id,
      podcastTitle: subscription.title,
    );
  }

  /// Navigate to episode detail page
  static void goToEpisodeDetail(
    BuildContext context, {
    required int episodeId,
    required int subscriptionId,
    String? episodeTitle,
  }) {
    context.pushNamed(
      'episodeDetail',
      pathParameters: {
        'subscriptionId': subscriptionId.toString(),
        'episodeId': episodeId.toString(),
      },
      queryParameters: episodeTitle != null ? {'title': episodeTitle} : null,
    );
  }

  /// Navigate to player page
  static void goToPlayer(
    BuildContext context, {
    required int episodeId,
    required int subscriptionId,
    String? episodeTitle,
    String? audioUrl,
    int? startPosition,
  }) {
    context.pushNamed(
      'episodePlayer',
      pathParameters: {
        'subscriptionId': subscriptionId.toString(),
        'episodeId': episodeId.toString(),
      },
      queryParameters: {
        if (episodeTitle != null) 'title': episodeTitle,
        if (audioUrl != null) 'audioUrl': audioUrl,
        if (startPosition != null) 'position': startPosition.toString(),
      },
    );
  }

  /// Pop to podcast list
  static void popToList(BuildContext context) {
    context.popUntil((route) => route.settings.name == 'podcastList');
  }
}