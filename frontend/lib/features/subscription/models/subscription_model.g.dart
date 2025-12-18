// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'subscription_model.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

SubscriptionModel _$SubscriptionModelFromJson(Map<String, dynamic> json) =>
    SubscriptionModel(
      id: json['id'] as String,
      name: json['name'] as String,
      description: json['description'] as String?,
      url: json['url'] as String,
      type: $enumDecode(_$SubscriptionTypeEnumMap, json['type']),
      status: $enumDecode(_$SubscriptionStatusEnumMap, json['status']),
      config: SubscriptionConfig.fromJson(
        json['config'] as Map<String, dynamic>,
      ),
      itemCount: (json['itemCount'] as num?)?.toInt() ?? 0,
      lastFetchedAt: json['lastFetchedAt'] == null
          ? null
          : DateTime.parse(json['lastFetchedAt'] as String),
      createdAt: DateTime.parse(json['createdAt'] as String),
      updatedAt: DateTime.parse(json['updatedAt'] as String),
      nextFetchAt: json['nextFetchAt'] == null
          ? null
          : DateTime.parse(json['nextFetchAt'] as String),
      metadata: json['metadata'] as Map<String, dynamic>?,
      tags: (json['tags'] as List<dynamic>?)?.map((e) => e as String).toList(),
      category: json['category'] as String?,
    );

Map<String, dynamic> _$SubscriptionModelToJson(SubscriptionModel instance) =>
    <String, dynamic>{
      'id': instance.id,
      'name': instance.name,
      'description': instance.description,
      'url': instance.url,
      'type': _$SubscriptionTypeEnumMap[instance.type]!,
      'status': _$SubscriptionStatusEnumMap[instance.status]!,
      'config': instance.config,
      'itemCount': instance.itemCount,
      'lastFetchedAt': instance.lastFetchedAt?.toIso8601String(),
      'createdAt': instance.createdAt.toIso8601String(),
      'updatedAt': instance.updatedAt.toIso8601String(),
      'nextFetchAt': instance.nextFetchAt?.toIso8601String(),
      'metadata': instance.metadata,
      'tags': instance.tags,
      'category': instance.category,
    };

const _$SubscriptionTypeEnumMap = {
  SubscriptionType.rss: 'rss',
  SubscriptionType.atom: 'atom',
  SubscriptionType.jsonFeed: 'json_feed',
  SubscriptionType.webhook: 'webhook',
  SubscriptionType.api: 'api',
  SubscriptionType.reddit: 'reddit',
  SubscriptionType.twitter: 'twitter',
  SubscriptionType.youtube: 'youtube',
};

const _$SubscriptionStatusEnumMap = {
  SubscriptionStatus.active: 'active',
  SubscriptionStatus.inactive: 'inactive',
  SubscriptionStatus.error: 'error',
  SubscriptionStatus.paused: 'paused',
};

SubscriptionConfig _$SubscriptionConfigFromJson(Map<String, dynamic> json) =>
    SubscriptionConfig(
      fetchInterval: (json['fetchInterval'] as num?)?.toInt() ?? 60,
      maxItems: (json['maxItems'] as num?)?.toInt() ?? 100,
      includeImages: json['includeImages'] as bool? ?? true,
      includeVideos: json['includeVideos'] as bool? ?? false,
      includeAudio: json['includeAudio'] as bool? ?? false,
      allowedCategories: (json['allowedCategories'] as List<dynamic>?)
          ?.map((e) => e as String)
          .toList(),
      blockedCategories: (json['blockedCategories'] as List<dynamic>?)
          ?.map((e) => e as String)
          .toList(),
      customHeaders: json['customHeaders'] as Map<String, dynamic>?,
      filters: json['filters'] as Map<String, dynamic>?,
    );

Map<String, dynamic> _$SubscriptionConfigToJson(SubscriptionConfig instance) =>
    <String, dynamic>{
      'fetchInterval': instance.fetchInterval,
      'maxItems': instance.maxItems,
      'includeImages': instance.includeImages,
      'includeVideos': instance.includeVideos,
      'includeAudio': instance.includeAudio,
      'allowedCategories': instance.allowedCategories,
      'blockedCategories': instance.blockedCategories,
      'customHeaders': instance.customHeaders,
      'filters': instance.filters,
    };

CreateSubscriptionRequest _$CreateSubscriptionRequestFromJson(
  Map<String, dynamic> json,
) => CreateSubscriptionRequest(
  name: json['name'] as String,
  description: json['description'] as String?,
  url: json['url'] as String,
  type: $enumDecode(_$SubscriptionTypeEnumMap, json['type']),
  config: json['config'] == null
      ? null
      : SubscriptionConfig.fromJson(json['config'] as Map<String, dynamic>),
  tags: (json['tags'] as List<dynamic>?)?.map((e) => e as String).toList(),
  category: json['category'] as String?,
);

Map<String, dynamic> _$CreateSubscriptionRequestToJson(
  CreateSubscriptionRequest instance,
) => <String, dynamic>{
  'name': instance.name,
  'description': instance.description,
  'url': instance.url,
  'type': _$SubscriptionTypeEnumMap[instance.type]!,
  'config': instance.config,
  'tags': instance.tags,
  'category': instance.category,
};

UpdateSubscriptionRequest _$UpdateSubscriptionRequestFromJson(
  Map<String, dynamic> json,
) => UpdateSubscriptionRequest(
  name: json['name'] as String?,
  description: json['description'] as String?,
  url: json['url'] as String?,
  status: $enumDecodeNullable(_$SubscriptionStatusEnumMap, json['status']),
  config: json['config'] == null
      ? null
      : SubscriptionConfig.fromJson(json['config'] as Map<String, dynamic>),
  tags: (json['tags'] as List<dynamic>?)?.map((e) => e as String).toList(),
  category: json['category'] as String?,
);

Map<String, dynamic> _$UpdateSubscriptionRequestToJson(
  UpdateSubscriptionRequest instance,
) => <String, dynamic>{
  'name': instance.name,
  'description': instance.description,
  'url': instance.url,
  'status': _$SubscriptionStatusEnumMap[instance.status],
  'config': instance.config,
  'tags': instance.tags,
  'category': instance.category,
};

SubscriptionItemModel _$SubscriptionItemModelFromJson(
  Map<String, dynamic> json,
) => SubscriptionItemModel(
  id: json['id'] as String,
  subscriptionId: json['subscriptionId'] as String,
  title: json['title'] as String,
  description: json['description'] as String?,
  content: json['content'] as String?,
  link: json['link'] as String?,
  author: json['author'] as String?,
  publishedAt: json['publishedAt'] == null
      ? null
      : DateTime.parse(json['publishedAt'] as String),
  createdAt: DateTime.parse(json['createdAt'] as String),
  isRead: json['isRead'] as bool? ?? false,
  isBookmarked: json['isBookmarked'] as bool? ?? false,
  attachmentIds: (json['attachmentIds'] as List<dynamic>?)
      ?.map((e) => e as String)
      .toList(),
  metadata: json['metadata'] as Map<String, dynamic>?,
);

Map<String, dynamic> _$SubscriptionItemModelToJson(
  SubscriptionItemModel instance,
) => <String, dynamic>{
  'id': instance.id,
  'subscriptionId': instance.subscriptionId,
  'title': instance.title,
  'description': instance.description,
  'content': instance.content,
  'link': instance.link,
  'author': instance.author,
  'publishedAt': instance.publishedAt?.toIso8601String(),
  'createdAt': instance.createdAt.toIso8601String(),
  'isRead': instance.isRead,
  'isBookmarked': instance.isBookmarked,
  'attachmentIds': instance.attachmentIds,
  'metadata': instance.metadata,
};
