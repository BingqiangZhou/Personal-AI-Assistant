import 'package:json_annotation/json_annotation.dart';

part 'subscription_model.g.dart';

@JsonSerializable()
class CategoryModel {
  final int id;
  final String name;
  final String? description;
  final String? color;
  final DateTime? createdAt;

  const CategoryModel({
    required this.id,
    required this.name,
    this.description,
    this.color,
    this.createdAt,
  });

  factory CategoryModel.fromJson(Map<String, dynamic> json) =>
      _$CategoryModelFromJson(json);

  Map<String, dynamic> toJson() => _$CategoryModelToJson(this);
}

@JsonSerializable()
class SubscriptionModel {
  final int id;

  @JsonKey(name: 'title')
  final String name;

  final String? description;

  @JsonKey(name: 'source_url')
  final String url;

  @JsonKey(name: 'source_type')
  final String sourceType;

  final SubscriptionStatus status;
  final Map<String, dynamic>? config;

  @JsonKey(name: 'item_count')
  final int itemCount;

  @JsonKey(name: 'last_fetched_at')
  final DateTime? lastFetchedAt;

  @JsonKey(name: 'latest_item_published_at')
  final DateTime? latestItemPublishedAt;

  @JsonKey(name: 'next_update_at')
  final DateTime? nextUpdateAt;

  @JsonKey(name: 'error_message')
  final String? errorMessage;

  @JsonKey(name: 'created_at')
  final DateTime createdAt;

  @JsonKey(name: 'updated_at')
  final DateTime updatedAt;

  final List<CategoryModel>? categories;

  const SubscriptionModel({
    required this.id,
    required this.name,
    this.description,
    required this.url,
    required this.sourceType,
    required this.status,
    this.config,
    this.itemCount = 0,
    this.lastFetchedAt,
    this.latestItemPublishedAt,
    this.nextUpdateAt,
    this.errorMessage,
    required this.createdAt,
    required this.updatedAt,
    this.categories,
  });

  factory SubscriptionModel.fromJson(Map<String, dynamic> json) =>
      _$SubscriptionModelFromJson(json);

  Map<String, dynamic> toJson() => _$SubscriptionModelToJson(this);

  SubscriptionModel copyWith({
    int? id,
    String? name,
    String? description,
    String? url,
    String? sourceType,
    SubscriptionStatus? status,
    Map<String, dynamic>? config,
    int? itemCount,
    DateTime? lastFetchedAt,
    DateTime? latestItemPublishedAt,
    DateTime? nextUpdateAt,
    String? errorMessage,
    DateTime? createdAt,
    DateTime? updatedAt,
    List<CategoryModel>? categories,
  }) {
    return SubscriptionModel(
      id: id ?? this.id,
      name: name ?? this.name,
      description: description ?? this.description,
      url: url ?? this.url,
      sourceType: sourceType ?? this.sourceType,
      status: status ?? this.status,
      config: config ?? this.config,
      itemCount: itemCount ?? this.itemCount,
      lastFetchedAt: lastFetchedAt ?? this.lastFetchedAt,
      latestItemPublishedAt: latestItemPublishedAt ?? this.latestItemPublishedAt,
      nextUpdateAt: nextUpdateAt ?? this.nextUpdateAt,
      errorMessage: errorMessage ?? this.errorMessage,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      categories: categories ?? this.categories,
    );
  }

  String get formattedLastFetchedAt {
    if (lastFetchedAt == null) return 'Never';
    return '${lastFetchedAt!.day}/${lastFetchedAt!.month}/${lastFetchedAt!.year}';
  }

  bool get isActive => status == SubscriptionStatus.active;
  bool get isHealthy => status == SubscriptionStatus.active &&
                      lastFetchedAt != null &&
                      DateTime.now().difference(lastFetchedAt!).inDays < 7;
}

enum SubscriptionType {
  @JsonValue('rss')
  rss,
  @JsonValue('atom')
  atom,
  @JsonValue('json_feed')
  jsonFeed,
  @JsonValue('webhook')
  webhook,
  @JsonValue('api')
  api,
  @JsonValue('reddit')
  reddit,
  @JsonValue('twitter')
  twitter,
  @JsonValue('youtube')
  youtube,
}

enum SubscriptionStatus {
  @JsonValue('active')
  active,
  @JsonValue('inactive')
  inactive,
  @JsonValue('error')
  error,
  @JsonValue('paused')
  paused,
  @JsonValue('pending')
  pending,
}

@JsonSerializable()
class SubscriptionConfig {
  final int fetchInterval; // in minutes
  final int maxItems;
  final bool includeImages;
  final bool includeVideos;
  final bool includeAudio;
  final List<String>? allowedCategories;
  final List<String>? blockedCategories;
  final Map<String, dynamic>? customHeaders;
  final Map<String, dynamic>? filters;

  const SubscriptionConfig({
    this.fetchInterval = 60,
    this.maxItems = 100,
    this.includeImages = true,
    this.includeVideos = false,
    this.includeAudio = false,
    this.allowedCategories,
    this.blockedCategories,
    this.customHeaders,
    this.filters,
  });

  factory SubscriptionConfig.fromJson(Map<String, dynamic> json) =>
      _$SubscriptionConfigFromJson(json);

  Map<String, dynamic> toJson() => _$SubscriptionConfigToJson(this);
}

@JsonSerializable()
class CreateSubscriptionRequest {
  final String title;
  final String? description;
  @JsonKey(name: 'source_url')
  final String url;
  @JsonKey(name: 'source_type')
  final String sourceType;
  final Map<String, dynamic>? config;
  final List<int>? categoryIds;

  const CreateSubscriptionRequest({
    required this.title,
    this.description,
    required this.url,
    required this.sourceType,
    this.config,
    this.categoryIds,
  });

  factory CreateSubscriptionRequest.fromJson(Map<String, dynamic> json) =>
      _$CreateSubscriptionRequestFromJson(json);

  Map<String, dynamic> toJson() => _$CreateSubscriptionRequestToJson(this);
}

@JsonSerializable()
class UpdateSubscriptionRequest {
  final String? title;
  final String? description;
  final Map<String, dynamic>? config;
  final int? fetchInterval;
  final bool? isActive;

  const UpdateSubscriptionRequest({
    this.title,
    this.description,
    this.config,
    this.fetchInterval,
    this.isActive,
  });

  factory UpdateSubscriptionRequest.fromJson(Map<String, dynamic> json) =>
      _$UpdateSubscriptionRequestFromJson(json);

  Map<String, dynamic> toJson() => _$UpdateSubscriptionRequestToJson(this);
}

@JsonSerializable()
class SubscriptionItemModel {
  final String id;

  @JsonKey(name: 'subscription_id')
  final int subscriptionId;

  @JsonKey(name: 'external_id')
  final String? externalId;

  final String title;
  final String? content;
  final String? summary;
  final String? author;

  @JsonKey(name: 'source_url')
  final String? sourceUrl;

  @JsonKey(name: 'image_url')
  final String? imageUrl;

  final List<String>? tags;

  @JsonKey(name: 'metadata_json')
  final Map<String, dynamic>? metadataJson;

  @JsonKey(name: 'published_at')
  final DateTime? publishedAt;

  @JsonKey(name: 'read_at')
  final DateTime? readAt;

  final bool? bookmarked;

  @JsonKey(name: 'created_at')
  final DateTime createdAt;

  const SubscriptionItemModel({
    required this.id,
    required this.subscriptionId,
    this.externalId,
    required this.title,
    this.content,
    this.summary,
    this.author,
    this.sourceUrl,
    this.imageUrl,
    this.tags,
    this.metadataJson,
    this.publishedAt,
    this.readAt,
    this.bookmarked,
    required this.createdAt,
  });

  factory SubscriptionItemModel.fromJson(Map<String, dynamic> json) =>
      _$SubscriptionItemModelFromJson(json);

  Map<String, dynamic> toJson() => _$SubscriptionItemModelToJson(this);

  bool get isRead => readAt != null;

  String get shortDescription {
    if (summary != null && summary!.isNotEmpty) {
      return summary!.length > 150
          ? '${summary!.substring(0, 150)}...'
          : summary!;
    }
    if (content != null && content!.isNotEmpty) {
      return content!.length > 150
          ? '${content!.substring(0, 150)}...'
          : content!;
    }
    return '';
  }

  String get formattedPublishedAt {
    if (publishedAt == null) return 'Unknown';
    return '${publishedAt!.day}/${publishedAt!.month}/${publishedAt!.year}';
  }
}