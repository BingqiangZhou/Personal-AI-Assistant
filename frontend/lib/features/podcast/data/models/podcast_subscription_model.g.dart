// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'podcast_subscription_model.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

PodcastSubscriptionModel _$PodcastSubscriptionModelFromJson(
  Map<String, dynamic> json,
) => PodcastSubscriptionModel(
  id: (json['id'] as num).toInt(),
  userId: (json['user_id'] as num).toInt(),
  title: json['title'] as String,
  description: json['description'] as String?,
  sourceUrl: json['source_url'] as String,
  status: json['status'] as String,
  lastFetchedAt: json['last_fetched_at'] == null
      ? null
      : DateTime.parse(json['last_fetched_at'] as String),
  errorMessage: json['error_message'] as String?,
  fetchInterval: (json['fetch_interval'] as num).toInt(),
  episodeCount: (json['episode_count'] as num?)?.toInt() ?? 0,
  unplayedCount: (json['unplayed_count'] as num?)?.toInt() ?? 0,
  latestEpisode: json['latest_episode'] as Map<String, dynamic>?,
  categories: (json['categories'] as List<dynamic>?)
      ?.map((e) => Category.fromJson(e as Map<String, dynamic>))
      .toList(),
  createdAt: DateTime.parse(json['created_at'] as String),
  updatedAt: json['updated_at'] == null
      ? null
      : DateTime.parse(json['updated_at'] as String),
);

Map<String, dynamic> _$PodcastSubscriptionModelToJson(
  PodcastSubscriptionModel instance,
) => <String, dynamic>{
  'id': instance.id,
  'user_id': instance.userId,
  'title': instance.title,
  'description': instance.description,
  'source_url': instance.sourceUrl,
  'status': instance.status,
  'last_fetched_at': instance.lastFetchedAt?.toIso8601String(),
  'error_message': instance.errorMessage,
  'fetch_interval': instance.fetchInterval,
  'episode_count': instance.episodeCount,
  'unplayed_count': instance.unplayedCount,
  'latest_episode': instance.latestEpisode,
  'categories': instance.categories,
  'created_at': instance.createdAt.toIso8601String(),
  'updated_at': instance.updatedAt?.toIso8601String(),
};

Category _$CategoryFromJson(Map<String, dynamic> json) => Category(
  id: (json['id'] as num).toInt(),
  userId: (json['user_id'] as num).toInt(),
  name: json['name'] as String,
  description: json['description'] as String?,
  color: json['color'] as String?,
  subscriptionCount: (json['subscription_count'] as num?)?.toInt() ?? 0,
  createdAt: DateTime.parse(json['created_at'] as String),
  updatedAt: json['updated_at'] == null
      ? null
      : DateTime.parse(json['updated_at'] as String),
);

Map<String, dynamic> _$CategoryToJson(Category instance) => <String, dynamic>{
  'id': instance.id,
  'user_id': instance.userId,
  'name': instance.name,
  'description': instance.description,
  'color': instance.color,
  'subscription_count': instance.subscriptionCount,
  'created_at': instance.createdAt.toIso8601String(),
  'updated_at': instance.updatedAt?.toIso8601String(),
};

PodcastSubscriptionListResponse _$PodcastSubscriptionListResponseFromJson(
  Map<String, dynamic> json,
) => PodcastSubscriptionListResponse(
  subscriptions: (json['subscriptions'] as List<dynamic>)
      .map((e) => PodcastSubscriptionModel.fromJson(e as Map<String, dynamic>))
      .toList(),
  total: (json['total'] as num).toInt(),
  page: (json['page'] as num).toInt(),
  size: (json['size'] as num).toInt(),
  pages: (json['pages'] as num).toInt(),
);

Map<String, dynamic> _$PodcastSubscriptionListResponseToJson(
  PodcastSubscriptionListResponse instance,
) => <String, dynamic>{
  'subscriptions': instance.subscriptions,
  'total': instance.total,
  'page': instance.page,
  'size': instance.size,
  'pages': instance.pages,
};

PodcastSubscriptionCreateRequest _$PodcastSubscriptionCreateRequestFromJson(
  Map<String, dynamic> json,
) => PodcastSubscriptionCreateRequest(
  feedUrl: json['feed_url'] as String,
  customName: json['custom_name'] as String?,
  categoryIds: (json['category_ids'] as List<dynamic>?)
      ?.map((e) => (e as num).toInt())
      .toList(),
);

Map<String, dynamic> _$PodcastSubscriptionCreateRequestToJson(
  PodcastSubscriptionCreateRequest instance,
) => <String, dynamic>{
  'feed_url': instance.feedUrl,
  'custom_name': instance.customName,
  'category_ids': instance.categoryIds,
};
