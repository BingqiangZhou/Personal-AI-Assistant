import 'package:equatable/equatable.dart';
import 'package:json_annotation/json_annotation.dart';

part 'podcast_subscription_model.g.dart';

@JsonSerializable()
class PodcastSubscriptionModel extends Equatable {
  final int id;
  @JsonKey(name: 'user_id')
  final int userId;
  final String title;
  final String? description;
  @JsonKey(name: 'source_url')
  final String sourceUrl;
  final String status;
  @JsonKey(name: 'last_fetched_at')
  final DateTime? lastFetchedAt;
  @JsonKey(name: 'error_message')
  final String? errorMessage;
  @JsonKey(name: 'fetch_interval')
  final int fetchInterval;
  @JsonKey(name: 'episode_count')
  final int episodeCount;
  @JsonKey(name: 'unplayed_count')
  final int unplayedCount;
  @JsonKey(name: 'latest_episode')
  final Map<String, dynamic>? latestEpisode;
  final List<Category>? categories;
  @JsonKey(name: 'created_at')
  final DateTime createdAt;
  @JsonKey(name: 'updated_at')
  final DateTime? updatedAt;

  const PodcastSubscriptionModel({
    required this.id,
    required this.userId,
    required this.title,
    this.description,
    required this.sourceUrl,
    required this.status,
    this.lastFetchedAt,
    this.errorMessage,
    required this.fetchInterval,
    this.episodeCount = 0,
    this.unplayedCount = 0,
    this.latestEpisode,
    this.categories,
    required this.createdAt,
    this.updatedAt,
  });

  factory PodcastSubscriptionModel.fromJson(Map<String, dynamic> json) =>
      _$PodcastSubscriptionModelFromJson(json);

  Map<String, dynamic> toJson() => _$PodcastSubscriptionModelToJson(this);

  PodcastSubscriptionModel copyWith({
    int? id,
    int? userId,
    String? title,
    String? description,
    String? sourceUrl,
    String? status,
    DateTime? lastFetchedAt,
    String? errorMessage,
    int? fetchInterval,
    int? episodeCount,
    int? unplayedCount,
    Map<String, dynamic>? latestEpisode,
    List<Category>? categories,
    DateTime? createdAt,
    DateTime? updatedAt,
  }) {
    return PodcastSubscriptionModel(
      id: id ?? this.id,
      userId: userId ?? this.userId,
      title: title ?? this.title,
      description: description ?? this.description,
      sourceUrl: sourceUrl ?? this.sourceUrl,
      status: status ?? this.status,
      lastFetchedAt: lastFetchedAt ?? this.lastFetchedAt,
      errorMessage: errorMessage ?? this.errorMessage,
      fetchInterval: fetchInterval ?? this.fetchInterval,
      episodeCount: episodeCount ?? this.episodeCount,
      unplayedCount: unplayedCount ?? this.unplayedCount,
      latestEpisode: latestEpisode ?? this.latestEpisode,
      categories: categories ?? this.categories,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
    );
  }

  @override
  List<Object?> get props => [
        id,
        userId,
        title,
        description,
        sourceUrl,
        status,
        lastFetchedAt,
        errorMessage,
        fetchInterval,
        episodeCount,
        unplayedCount,
        latestEpisode,
        categories,
        createdAt,
        updatedAt,
      ];
}

@JsonSerializable()
class Category extends Equatable {
  final int id;
  @JsonKey(name: 'user_id')
  final int userId;
  final String name;
  final String? description;
  final String? color;
  @JsonKey(name: 'subscription_count')
  final int subscriptionCount;
  @JsonKey(name: 'created_at')
  final DateTime createdAt;
  @JsonKey(name: 'updated_at')
  final DateTime? updatedAt;

  const Category({
    required this.id,
    required this.userId,
    required this.name,
    this.description,
    this.color,
    this.subscriptionCount = 0,
    required this.createdAt,
    this.updatedAt,
  });

  factory Category.fromJson(Map<String, dynamic> json) =>
      _$CategoryFromJson(json);

  Map<String, dynamic> toJson() => _$CategoryToJson(this);

  @override
  List<Object?> get props => [
        id,
        userId,
        name,
        description,
        color,
        subscriptionCount,
        createdAt,
        updatedAt,
      ];
}

@JsonSerializable()
class PodcastSubscriptionListResponse extends Equatable {
  final List<PodcastSubscriptionModel> subscriptions;
  final int total;
  final int page;
  final int size;
  final int pages;

  const PodcastSubscriptionListResponse({
    required this.subscriptions,
    required this.total,
    required this.page,
    required this.size,
    required this.pages,
  });

  factory PodcastSubscriptionListResponse.fromJson(Map<String, dynamic> json) =>
      _$PodcastSubscriptionListResponseFromJson(json);

  Map<String, dynamic> toJson() => _$PodcastSubscriptionListResponseToJson(this);

  @override
  List<Object?> get props => [subscriptions, total, page, size, pages];
}

@JsonSerializable()
class PodcastSubscriptionCreateRequest extends Equatable {
  @JsonKey(name: 'feed_url')
  final String feedUrl;
  @JsonKey(name: 'custom_name')
  final String? customName;
  @JsonKey(name: 'category_ids')
  final List<int>? categoryIds;

  const PodcastSubscriptionCreateRequest({
    required this.feedUrl,
    this.customName,
    this.categoryIds,
  });

  Map<String, dynamic> toJson() => _$PodcastSubscriptionCreateRequestToJson(this);

  @override
  List<Object?> get props => [feedUrl, customName, categoryIds];
}