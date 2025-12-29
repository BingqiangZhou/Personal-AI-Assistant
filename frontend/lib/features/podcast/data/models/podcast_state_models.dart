import 'package:equatable/equatable.dart';
import 'podcast_episode_model.dart';
import 'podcast_subscription_model.dart';

class PodcastFeedState extends Equatable {
  final List<PodcastEpisodeModel> episodes;
  final bool hasMore;
  final int? nextPage;
  final int total;
  final bool isLoading;
  final bool isLoadingMore;
  final String? error;

  const PodcastFeedState({
    this.episodes = const [],
    this.hasMore = true,
    this.nextPage,
    this.total = 0,
    this.isLoading = false,
    this.isLoadingMore = false,
    this.error,
  });

  PodcastFeedState copyWith({
    List<PodcastEpisodeModel>? episodes,
    bool? hasMore,
    int? nextPage,
    int? total,
    bool? isLoading,
    bool? isLoadingMore,
    String? error,
  }) {
    return PodcastFeedState(
      episodes: episodes ?? this.episodes,
      hasMore: hasMore ?? this.hasMore,
      nextPage: nextPage ?? this.nextPage,
      total: total ?? this.total,
      isLoading: isLoading ?? this.isLoading,
      isLoadingMore: isLoadingMore ?? this.isLoadingMore,
      error: error ?? this.error,
    );
  }

  @override
  List<Object?> get props => [
        episodes,
        hasMore,
        nextPage,
        total,
        isLoading,
        isLoadingMore,
        error,
      ];
}

class PodcastEpisodesState extends Equatable {
  final List<PodcastEpisodeModel> episodes;
  final bool hasMore;
  final int? nextPage;
  final int currentPage;
  final int total;
  final bool isLoading;
  final bool isLoadingMore;
  final String? error;

  const PodcastEpisodesState({
    this.episodes = const [],
    this.hasMore = true,
    this.nextPage,
    this.currentPage = 1,
    this.total = 0,
    this.isLoading = false,
    this.isLoadingMore = false,
    this.error,
  });

  PodcastEpisodesState copyWith({
    List<PodcastEpisodeModel>? episodes,
    bool? hasMore,
    int? nextPage,
    int? currentPage,
    int? total,
    bool? isLoading,
    bool? isLoadingMore,
    String? error,
  }) {
    return PodcastEpisodesState(
      episodes: episodes ?? this.episodes,
      hasMore: hasMore ?? this.hasMore,
      nextPage: nextPage ?? this.nextPage,
      currentPage: currentPage ?? this.currentPage,
      total: total ?? this.total,
      isLoading: isLoading ?? this.isLoading,
      isLoadingMore: isLoadingMore ?? this.isLoadingMore,
      error: error ?? this.error,
    );
  }

  @override
  List<Object?> get props => [
        episodes,
        hasMore,
        nextPage,
        currentPage,
        total,
        isLoading,
        isLoadingMore,
        error,
      ];
}

class PodcastSubscriptionState extends Equatable {
  final List<PodcastSubscriptionModel> subscriptions;
  final bool hasMore;
  final int? nextPage;
  final int currentPage;
  final int total;
  final bool isLoading;
  final bool isLoadingMore;
  final String? error;

  const PodcastSubscriptionState({
    this.subscriptions = const [],
    this.hasMore = true,
    this.nextPage,
    this.currentPage = 1,
    this.total = 0,
    this.isLoading = false,
    this.isLoadingMore = false,
    this.error,
  });

  PodcastSubscriptionState copyWith({
    List<PodcastSubscriptionModel>? subscriptions,
    bool? hasMore,
    int? nextPage,
    int? currentPage,
    int? total,
    bool? isLoading,
    bool? isLoadingMore,
    String? error,
  }) {
    return PodcastSubscriptionState(
      subscriptions: subscriptions ?? this.subscriptions,
      hasMore: hasMore ?? this.hasMore,
      nextPage: nextPage ?? this.nextPage,
      currentPage: currentPage ?? this.currentPage,
      total: total ?? this.total,
      isLoading: isLoading ?? this.isLoading,
      isLoadingMore: isLoadingMore ?? this.isLoadingMore,
      error: error ?? this.error,
    );
  }

  @override
  List<Object?> get props => [
        subscriptions,
        hasMore,
        nextPage,
        currentPage,
        total,
        isLoading,
        isLoadingMore,
        error,
      ];
}
