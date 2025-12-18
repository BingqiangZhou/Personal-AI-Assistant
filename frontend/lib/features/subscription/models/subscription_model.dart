import 'package:json_annotation/json_annotation.dart';

part 'subscription_model.g.dart';

@JsonSerializable()
class SubscriptionModel {
  final String id;
  final String name;
  final String? description;
  final String url;
  final SubscriptionType type;
  final SubscriptionStatus status;
  final SubscriptionConfig config;
  final int itemCount;
  final DateTime? lastFetchedAt;
  final DateTime createdAt;
  final DateTime updatedAt;
  final DateTime? nextFetchAt;
  final Map<String, dynamic>? metadata;
  final List<String>? tags;
  final String? category;

  const SubscriptionModel({
    required this.id,
    required this.name,
    this.description,
    required this.url,
    required this.type,
    required this.status,
    required this.config,
    this.itemCount = 0,
    this.lastFetchedAt,
    required this.createdAt,
    required this.updatedAt,
    this.nextFetchAt,
    this.metadata,
    this.tags,
    this.category,
  });

  factory SubscriptionModel.fromJson(Map<String, dynamic> json) =>
      _$SubscriptionModelFromJson(json);

  Map<String, dynamic> toJson() => _$SubscriptionModelToJson(this);

  SubscriptionModel copyWith({
    String? id,
    String? name,
    String? description,
    String? url,
    SubscriptionType? type,
    SubscriptionStatus? status,
    SubscriptionConfig? config,
    int? itemCount,
    DateTime? lastFetchedAt,
    DateTime? createdAt,
    DateTime? updatedAt,
    DateTime? nextFetchAt,
    Map<String, dynamic>? metadata,
    List<String>? tags,
    String? category,
  }) {
    return SubscriptionModel(
      id: id ?? this.id,
      name: name ?? this.name,
      description: description ?? this.description,
      url: url ?? this.url,
      type: type ?? this.type,
      status: status ?? this.status,
      config: config ?? this.config,
      itemCount: itemCount ?? this.itemCount,
      lastFetchedAt: lastFetchedAt ?? this.lastFetchedAt,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      nextFetchAt: nextFetchAt ?? this.nextFetchAt,
      metadata: metadata ?? this.metadata,
      tags: tags ?? this.tags,
      category: category ?? this.category,
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
  final String name;
  final String? description;
  final String url;
  final SubscriptionType type;
  final SubscriptionConfig? config;
  final List<String>? tags;
  final String? category;

  const CreateSubscriptionRequest({
    required this.name,
    this.description,
    required this.url,
    required this.type,
    this.config,
    this.tags,
    this.category,
  });

  factory CreateSubscriptionRequest.fromJson(Map<String, dynamic> json) =>
      _$CreateSubscriptionRequestFromJson(json);

  Map<String, dynamic> toJson() => _$CreateSubscriptionRequestToJson(this);
}

@JsonSerializable()
class UpdateSubscriptionRequest {
  final String? name;
  final String? description;
  final String? url;
  final SubscriptionStatus? status;
  final SubscriptionConfig? config;
  final List<String>? tags;
  final String? category;

  const UpdateSubscriptionRequest({
    this.name,
    this.description,
    this.url,
    this.status,
    this.config,
    this.tags,
    this.category,
  });

  factory UpdateSubscriptionRequest.fromJson(Map<String, dynamic> json) =>
      _$UpdateSubscriptionRequestFromJson(json);

  Map<String, dynamic> toJson() => _$UpdateSubscriptionRequestToJson(this);
}

@JsonSerializable()
class SubscriptionItemModel {
  final String id;
  final String subscriptionId;
  final String title;
  final String? description;
  final String? content;
  final String? link;
  final String? author;
  final DateTime? publishedAt;
  final DateTime createdAt;
  final bool isRead;
  final bool isBookmarked;
  final List<String>? attachmentIds;
  final Map<String, dynamic>? metadata;

  const SubscriptionItemModel({
    required this.id,
    required this.subscriptionId,
    required this.title,
    this.description,
    this.content,
    this.link,
    this.author,
    this.publishedAt,
    required this.createdAt,
    this.isRead = false,
    this.isBookmarked = false,
    this.attachmentIds,
    this.metadata,
  });

  factory SubscriptionItemModel.fromJson(Map<String, dynamic> json) =>
      _$SubscriptionItemModelFromJson(json);

  Map<String, dynamic> toJson() => _$SubscriptionItemModelToJson(this);

  String get shortDescription {
    if (description != null && description!.isNotEmpty) {
      return description!.length > 150
          ? '${description!.substring(0, 150)}...'
          : description!;
    }
    return '';
  }

  String get formattedPublishedAt {
    if (publishedAt == null) return 'Unknown';
    return '${publishedAt!.day}/${publishedAt!.month}/${publishedAt!.year}';
  }
}