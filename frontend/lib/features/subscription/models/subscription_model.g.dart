// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'subscription_model.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

CategoryModel _$CategoryModelFromJson(Map<String, dynamic> json) =>
    CategoryModel(
      id: (json['id'] as num).toInt(),
      name: json['name'] as String,
      description: json['description'] as String?,
      color: json['color'] as String?,
      createdAt: json['createdAt'] == null
          ? null
          : DateTime.parse(json['createdAt'] as String),
    );

Map<String, dynamic> _$CategoryModelToJson(CategoryModel instance) =>
    <String, dynamic>{
      'id': instance.id,
      'name': instance.name,
      'description': instance.description,
      'color': instance.color,
      'createdAt': instance.createdAt?.toIso8601String(),
    };

SubscriptionModel _$SubscriptionModelFromJson(Map<String, dynamic> json) =>
    SubscriptionModel(
      id: (json['id'] as num).toInt(),
      name: json['title'] as String,
      description: json['description'] as String?,
      url: json['source_url'] as String,
      sourceType: json['source_type'] as String,
      status: $enumDecode(_$SubscriptionStatusEnumMap, json['status']),
      config: json['config'] as Map<String, dynamic>?,
      itemCount: (json['item_count'] as num?)?.toInt() ?? 0,
      lastFetchedAt: json['last_fetched_at'] == null
          ? null
          : DateTime.parse(json['last_fetched_at'] as String),
      latestItemPublishedAt: json['latest_item_published_at'] == null
          ? null
          : DateTime.parse(json['latest_item_published_at'] as String),
      nextUpdateAt: json['next_update_at'] == null
          ? null
          : DateTime.parse(json['next_update_at'] as String),
      errorMessage: json['error_message'] as String?,
      createdAt: DateTime.parse(json['created_at'] as String),
      updatedAt: DateTime.parse(json['updated_at'] as String),
      categories: (json['categories'] as List<dynamic>?)
          ?.map((e) => CategoryModel.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$SubscriptionModelToJson(
  SubscriptionModel instance,
) => <String, dynamic>{
  'id': instance.id,
  'title': instance.name,
  'description': instance.description,
  'source_url': instance.url,
  'source_type': instance.sourceType,
  'status': _$SubscriptionStatusEnumMap[instance.status]!,
  'config': instance.config,
  'item_count': instance.itemCount,
  'last_fetched_at': instance.lastFetchedAt?.toIso8601String(),
  'latest_item_published_at': instance.latestItemPublishedAt?.toIso8601String(),
  'next_update_at': instance.nextUpdateAt?.toIso8601String(),
  'error_message': instance.errorMessage,
  'created_at': instance.createdAt.toIso8601String(),
  'updated_at': instance.updatedAt.toIso8601String(),
  'categories': instance.categories,
};

const _$SubscriptionStatusEnumMap = {
  SubscriptionStatus.active: 'active',
  SubscriptionStatus.inactive: 'inactive',
  SubscriptionStatus.error: 'error',
  SubscriptionStatus.paused: 'paused',
  SubscriptionStatus.pending: 'pending',
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
  title: json['title'] as String,
  description: json['description'] as String?,
  url: json['source_url'] as String,
  sourceType: json['source_type'] as String,
  config: json['config'] as Map<String, dynamic>?,
  categoryIds: (json['categoryIds'] as List<dynamic>?)
      ?.map((e) => (e as num).toInt())
      .toList(),
);

Map<String, dynamic> _$CreateSubscriptionRequestToJson(
  CreateSubscriptionRequest instance,
) => <String, dynamic>{
  'title': instance.title,
  'description': instance.description,
  'source_url': instance.url,
  'source_type': instance.sourceType,
  'config': instance.config,
  'categoryIds': instance.categoryIds,
};

UpdateSubscriptionRequest _$UpdateSubscriptionRequestFromJson(
  Map<String, dynamic> json,
) => UpdateSubscriptionRequest(
  title: json['title'] as String?,
  description: json['description'] as String?,
  config: json['config'] as Map<String, dynamic>?,
  fetchInterval: (json['fetchInterval'] as num?)?.toInt(),
  isActive: json['isActive'] as bool?,
);

Map<String, dynamic> _$UpdateSubscriptionRequestToJson(
  UpdateSubscriptionRequest instance,
) => <String, dynamic>{
  'title': instance.title,
  'description': instance.description,
  'config': instance.config,
  'fetchInterval': instance.fetchInterval,
  'isActive': instance.isActive,
};

SubscriptionItemModel _$SubscriptionItemModelFromJson(
  Map<String, dynamic> json,
) => SubscriptionItemModel(
  id: json['id'] as String,
  subscriptionId: (json['subscription_id'] as num).toInt(),
  externalId: json['external_id'] as String?,
  title: json['title'] as String,
  content: json['content'] as String?,
  summary: json['summary'] as String?,
  author: json['author'] as String?,
  sourceUrl: json['source_url'] as String?,
  imageUrl: json['image_url'] as String?,
  tags: (json['tags'] as List<dynamic>?)?.map((e) => e as String).toList(),
  metadataJson: json['metadata_json'] as Map<String, dynamic>?,
  publishedAt: json['published_at'] == null
      ? null
      : DateTime.parse(json['published_at'] as String),
  readAt: json['read_at'] == null
      ? null
      : DateTime.parse(json['read_at'] as String),
  bookmarked: json['bookmarked'] as bool?,
  createdAt: DateTime.parse(json['created_at'] as String),
);

Map<String, dynamic> _$SubscriptionItemModelToJson(
  SubscriptionItemModel instance,
) => <String, dynamic>{
  'id': instance.id,
  'subscription_id': instance.subscriptionId,
  'external_id': instance.externalId,
  'title': instance.title,
  'content': instance.content,
  'summary': instance.summary,
  'author': instance.author,
  'source_url': instance.sourceUrl,
  'image_url': instance.imageUrl,
  'tags': instance.tags,
  'metadata_json': instance.metadataJson,
  'published_at': instance.publishedAt?.toIso8601String(),
  'read_at': instance.readAt?.toIso8601String(),
  'bookmarked': instance.bookmarked,
  'created_at': instance.createdAt.toIso8601String(),
};
