import 'package:json_annotation/json_annotation.dart';

part 'knowledge_item_model.g.dart';

@JsonSerializable()
class KnowledgeItemModel {
  final String id;
  final String title;
  final String? description;
  final String content;
  final String? summary;
  final String category;
  final List<String> tags;
  final String? author;
  final String? source;
  final String? sourceUrl;
  final List<String> attachmentIds;
  final KnowledgeItemType type;
  final KnowledgeItemStatus status;
  final Map<String, dynamic>? metadata;
  final DateTime createdAt;
  final DateTime updatedAt;
  final DateTime? accessedAt;
  final int accessCount;
  final Map<String, dynamic>? vectorData;

  const KnowledgeItemModel({
    required this.id,
    required this.title,
    this.description,
    required this.content,
    this.summary,
    required this.category,
    required this.tags,
    this.author,
    this.source,
    this.sourceUrl,
    required this.attachmentIds,
    required this.type,
    required this.status,
    this.metadata,
    required this.createdAt,
    required this.updatedAt,
    this.accessedAt,
    this.accessCount = 0,
    this.vectorData,
  });

  factory KnowledgeItemModel.fromJson(Map<String, dynamic> json) =>
      _$KnowledgeItemModelFromJson(json);

  Map<String, dynamic> toJson() => _$KnowledgeItemModelToJson(this);

  KnowledgeItemModel copyWith({
    String? id,
    String? title,
    String? description,
    String? content,
    String? summary,
    String? category,
    List<String>? tags,
    String? author,
    String? source,
    String? sourceUrl,
    List<String>? attachmentIds,
    KnowledgeItemType? type,
    KnowledgeItemStatus? status,
    Map<String, dynamic>? metadata,
    DateTime? createdAt,
    DateTime? updatedAt,
    DateTime? accessedAt,
    int? accessCount,
    Map<String, dynamic>? vectorData,
  }) {
    return KnowledgeItemModel(
      id: id ?? this.id,
      title: title ?? this.title,
      description: description ?? this.description,
      content: content ?? this.content,
      summary: summary ?? this.summary,
      category: category ?? this.category,
      tags: tags ?? this.tags,
      author: author ?? this.author,
      source: source ?? this.source,
      sourceUrl: sourceUrl ?? this.sourceUrl,
      attachmentIds: attachmentIds ?? this.attachmentIds,
      type: type ?? this.type,
      status: status ?? this.status,
      metadata: metadata ?? this.metadata,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      accessedAt: accessedAt ?? this.accessedAt,
      accessCount: accessCount ?? this.accessCount,
      vectorData: vectorData ?? this.vectorData,
    );
  }

  String get shortDescription {
    if (description != null && description!.isNotEmpty) {
      return description!.length > 100
          ? '${description!.substring(0, 100)}...'
          : description!;
    }
    return content.length > 100
        ? '${content.substring(0, 100)}...'
        : content;
  }

  String get formattedCreatedAt {
    return '${createdAt.day}/${createdAt.month}/${createdAt.year}';
  }

  bool get hasAttachments => attachmentIds.isNotEmpty;
}

enum KnowledgeItemType {
  @JsonValue('document')
  document,
  @JsonValue('article')
  article,
  @JsonValue('note')
  note,
  @JsonValue('bookmark')
  bookmark,
  @JsonValue('code_snippet')
  codeSnippet,
  @JsonValue('image')
  image,
  @JsonValue('video')
  video,
  @JsonValue('audio')
  audio,
  @JsonValue('link')
  link,
}

enum KnowledgeItemStatus {
  @JsonValue('draft')
  draft,
  @JsonValue('published')
  published,
  @JsonValue('archived')
  archived,
  @JsonValue('processing')
  processing,
  @JsonValue('error')
  error,
}

@JsonSerializable()
class CreateKnowledgeItemRequest {
  final String title;
  final String? description;
  final String content;
  final String? summary;
  final String category;
  final List<String>? tags;
  final String? author;
  final String? source;
  final String? sourceUrl;
  final KnowledgeItemType type;
  final Map<String, dynamic>? metadata;

  const CreateKnowledgeItemRequest({
    required this.title,
    this.description,
    required this.content,
    this.summary,
    required this.category,
    this.tags,
    this.author,
    this.source,
    this.sourceUrl,
    required this.type,
    this.metadata,
  });

  factory CreateKnowledgeItemRequest.fromJson(Map<String, dynamic> json) =>
      _$CreateKnowledgeItemRequestFromJson(json);

  Map<String, dynamic> toJson() => _$CreateKnowledgeItemRequestToJson(this);
}

@JsonSerializable()
class UpdateKnowledgeItemRequest {
  final String? title;
  final String? description;
  final String? content;
  final String? summary;
  final String? category;
  final List<String>? tags;
  final String? author;
  final String? source;
  final String? sourceUrl;
  final KnowledgeItemType? type;
  final KnowledgeItemStatus? status;
  final Map<String, dynamic>? metadata;

  const UpdateKnowledgeItemRequest({
    this.title,
    this.description,
    this.content,
    this.summary,
    this.category,
    this.tags,
    this.author,
    this.source,
    this.sourceUrl,
    this.type,
    this.status,
    this.metadata,
  });

  factory UpdateKnowledgeItemRequest.fromJson(Map<String, dynamic> json) =>
      _$UpdateKnowledgeItemRequestFromJson(json);

  Map<String, dynamic> toJson() => _$UpdateKnowledgeItemRequestToJson(this);
}

@JsonSerializable()
class KnowledgeSearchRequest {
  final String query;
  final List<String>? categories;
  final List<String>? tags;
  final KnowledgeItemType? type;
  final List<String>? fields;
  final int? limit;
  final int? offset;
  final Map<String, dynamic>? filters;
  final bool useSemanticSearch;

  const KnowledgeSearchRequest({
    required this.query,
    this.categories,
    this.tags,
    this.type,
    this.fields,
    this.limit,
    this.offset,
    this.filters,
    this.useSemanticSearch = true,
  });

  factory KnowledgeSearchRequest.fromJson(Map<String, dynamic> json) =>
      _$KnowledgeSearchRequestFromJson(json);

  Map<String, dynamic> toJson() => _$KnowledgeSearchRequestToJson(this);
}

@JsonSerializable()
class KnowledgeCategoryModel {
  final String id;
  final String name;
  final String? description;
  final String? parentId;
  final int itemCount;
  final Map<String, dynamic>? metadata;

  const KnowledgeCategoryModel({
    required this.id,
    required this.name,
    this.description,
    this.parentId,
    this.itemCount = 0,
    this.metadata,
  });

  factory KnowledgeCategoryModel.fromJson(Map<String, dynamic> json) =>
      _$KnowledgeCategoryModelFromJson(json);

  Map<String, dynamic> toJson() => _$KnowledgeCategoryModelToJson(this);
}