import 'package:equatable/equatable.dart';
import 'package:json_annotation/json_annotation.dart';

import 'category_model.dart';

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
  @JsonKey(name: 'image_url')
  final String? imageUrl;
  final String? author;
  final String? platform;
  @JsonKey(name: 'update_frequency')
  final String? updateFrequency;
  @JsonKey(name: 'update_time')
  final String? updateTime;
  @JsonKey(name: 'update_day_of_week')
  final int? updateDayOfWeek;
  @JsonKey(name: 'next_update_at')
  final DateTime? nextUpdateAt;
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
    this.imageUrl,
    this.author,
    this.platform,
    this.updateFrequency,
    this.updateTime,
    this.updateDayOfWeek,
    this.nextUpdateAt,
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
    String? imageUrl,
    String? author,
    String? platform,
    String? updateFrequency,
    String? updateTime,
    int? updateDayOfWeek,
    DateTime? nextUpdateAt,
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
      imageUrl: imageUrl ?? this.imageUrl,
      author: author ?? this.author,
      platform: platform ?? this.platform,
      updateFrequency: updateFrequency ?? this.updateFrequency,
      updateTime: updateTime ?? this.updateTime,
      updateDayOfWeek: updateDayOfWeek ?? this.updateDayOfWeek,
      nextUpdateAt: nextUpdateAt ?? this.nextUpdateAt,
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
        imageUrl,
        author,
        platform,
        updateFrequency,
        updateTime,
        updateDayOfWeek,
        nextUpdateAt,
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
  @JsonKey(name: 'category_ids')
  final List<int>? categoryIds;

  const PodcastSubscriptionCreateRequest({
    required this.feedUrl,
    this.categoryIds,
  });

  Map<String, dynamic> toJson() => _$PodcastSubscriptionCreateRequestToJson(this);

  @override
  List<Object?> get props => [feedUrl, categoryIds];
}

@JsonSerializable()
class ReparseResponse extends Equatable {
  @JsonKey(defaultValue: false)
  final bool success;
  final Map<String, dynamic> result;

  const ReparseResponse({
    required this.success,
    required this.result,
  });

  factory ReparseResponse.fromJson(Map<String, dynamic> json) =>
      _$ReparseResponseFromJson(json);

  Map<String, dynamic> toJson() => _$ReparseResponseToJson(this);

  @override
  List<Object?> get props => [success, result];
}

@JsonSerializable()
class SimpleResponse extends Equatable {
  final Map<String, dynamic> data;

  const SimpleResponse({
    required this.data,
  });

  factory SimpleResponse.fromJson(Map<String, dynamic> json) =>
      _$SimpleResponseFromJson(json);

  Map<String, dynamic> toJson() => _$SimpleResponseToJson(this);

  @override
  List<Object?> get props => [data];
}