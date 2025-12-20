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
  imageUrl: json['image_url'] as String?,
  author: json['author'] as String?,
  platform: json['platform'] as String?,
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
  'image_url': instance.imageUrl,
  'author': instance.author,
  'platform': instance.platform,
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

ReparseResponse _$ReparseResponseFromJson(Map<String, dynamic> json) =>
    ReparseResponse(
      success: json['success'] as bool? ?? false,
      result: json['result'] as Map<String, dynamic>,
    );

Map<String, dynamic> _$ReparseResponseToJson(ReparseResponse instance) =>
    <String, dynamic>{'success': instance.success, 'result': instance.result};

SimpleResponse _$SimpleResponseFromJson(Map<String, dynamic> json) =>
    SimpleResponse(data: json['data'] as Map<String, dynamic>);

Map<String, dynamic> _$SimpleResponseToJson(SimpleResponse instance) =>
    <String, dynamic>{'data': instance.data};
