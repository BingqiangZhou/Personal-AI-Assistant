// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'knowledge_item_model.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

KnowledgeItemModel _$KnowledgeItemModelFromJson(Map<String, dynamic> json) =>
    KnowledgeItemModel(
      id: json['id'] as String,
      title: json['title'] as String,
      description: json['description'] as String?,
      content: json['content'] as String,
      summary: json['summary'] as String?,
      category: json['category'] as String,
      tags: (json['tags'] as List<dynamic>).map((e) => e as String).toList(),
      author: json['author'] as String?,
      source: json['source'] as String?,
      sourceUrl: json['sourceUrl'] as String?,
      attachmentIds: (json['attachmentIds'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      type: $enumDecode(_$KnowledgeItemTypeEnumMap, json['type']),
      status: $enumDecode(_$KnowledgeItemStatusEnumMap, json['status']),
      metadata: json['metadata'] as Map<String, dynamic>?,
      createdAt: DateTime.parse(json['createdAt'] as String),
      updatedAt: DateTime.parse(json['updatedAt'] as String),
      accessedAt: json['accessedAt'] == null
          ? null
          : DateTime.parse(json['accessedAt'] as String),
      accessCount: (json['accessCount'] as num?)?.toInt() ?? 0,
      vectorData: json['vectorData'] as Map<String, dynamic>?,
    );

Map<String, dynamic> _$KnowledgeItemModelToJson(KnowledgeItemModel instance) =>
    <String, dynamic>{
      'id': instance.id,
      'title': instance.title,
      'description': instance.description,
      'content': instance.content,
      'summary': instance.summary,
      'category': instance.category,
      'tags': instance.tags,
      'author': instance.author,
      'source': instance.source,
      'sourceUrl': instance.sourceUrl,
      'attachmentIds': instance.attachmentIds,
      'type': _$KnowledgeItemTypeEnumMap[instance.type]!,
      'status': _$KnowledgeItemStatusEnumMap[instance.status]!,
      'metadata': instance.metadata,
      'createdAt': instance.createdAt.toIso8601String(),
      'updatedAt': instance.updatedAt.toIso8601String(),
      'accessedAt': instance.accessedAt?.toIso8601String(),
      'accessCount': instance.accessCount,
      'vectorData': instance.vectorData,
    };

const _$KnowledgeItemTypeEnumMap = {
  KnowledgeItemType.document: 'document',
  KnowledgeItemType.article: 'article',
  KnowledgeItemType.note: 'note',
  KnowledgeItemType.bookmark: 'bookmark',
  KnowledgeItemType.codeSnippet: 'code_snippet',
  KnowledgeItemType.image: 'image',
  KnowledgeItemType.video: 'video',
  KnowledgeItemType.audio: 'audio',
  KnowledgeItemType.link: 'link',
};

const _$KnowledgeItemStatusEnumMap = {
  KnowledgeItemStatus.draft: 'draft',
  KnowledgeItemStatus.published: 'published',
  KnowledgeItemStatus.archived: 'archived',
  KnowledgeItemStatus.processing: 'processing',
  KnowledgeItemStatus.error: 'error',
};

CreateKnowledgeItemRequest _$CreateKnowledgeItemRequestFromJson(
  Map<String, dynamic> json,
) => CreateKnowledgeItemRequest(
  title: json['title'] as String,
  description: json['description'] as String?,
  content: json['content'] as String,
  summary: json['summary'] as String?,
  category: json['category'] as String,
  tags: (json['tags'] as List<dynamic>?)?.map((e) => e as String).toList(),
  author: json['author'] as String?,
  source: json['source'] as String?,
  sourceUrl: json['sourceUrl'] as String?,
  type: $enumDecode(_$KnowledgeItemTypeEnumMap, json['type']),
  metadata: json['metadata'] as Map<String, dynamic>?,
);

Map<String, dynamic> _$CreateKnowledgeItemRequestToJson(
  CreateKnowledgeItemRequest instance,
) => <String, dynamic>{
  'title': instance.title,
  'description': instance.description,
  'content': instance.content,
  'summary': instance.summary,
  'category': instance.category,
  'tags': instance.tags,
  'author': instance.author,
  'source': instance.source,
  'sourceUrl': instance.sourceUrl,
  'type': _$KnowledgeItemTypeEnumMap[instance.type]!,
  'metadata': instance.metadata,
};

UpdateKnowledgeItemRequest _$UpdateKnowledgeItemRequestFromJson(
  Map<String, dynamic> json,
) => UpdateKnowledgeItemRequest(
  title: json['title'] as String?,
  description: json['description'] as String?,
  content: json['content'] as String?,
  summary: json['summary'] as String?,
  category: json['category'] as String?,
  tags: (json['tags'] as List<dynamic>?)?.map((e) => e as String).toList(),
  author: json['author'] as String?,
  source: json['source'] as String?,
  sourceUrl: json['sourceUrl'] as String?,
  type: $enumDecodeNullable(_$KnowledgeItemTypeEnumMap, json['type']),
  status: $enumDecodeNullable(_$KnowledgeItemStatusEnumMap, json['status']),
  metadata: json['metadata'] as Map<String, dynamic>?,
);

Map<String, dynamic> _$UpdateKnowledgeItemRequestToJson(
  UpdateKnowledgeItemRequest instance,
) => <String, dynamic>{
  'title': instance.title,
  'description': instance.description,
  'content': instance.content,
  'summary': instance.summary,
  'category': instance.category,
  'tags': instance.tags,
  'author': instance.author,
  'source': instance.source,
  'sourceUrl': instance.sourceUrl,
  'type': _$KnowledgeItemTypeEnumMap[instance.type],
  'status': _$KnowledgeItemStatusEnumMap[instance.status],
  'metadata': instance.metadata,
};

KnowledgeSearchRequest _$KnowledgeSearchRequestFromJson(
  Map<String, dynamic> json,
) => KnowledgeSearchRequest(
  query: json['query'] as String,
  categories: (json['categories'] as List<dynamic>?)
      ?.map((e) => e as String)
      .toList(),
  tags: (json['tags'] as List<dynamic>?)?.map((e) => e as String).toList(),
  type: $enumDecodeNullable(_$KnowledgeItemTypeEnumMap, json['type']),
  fields: (json['fields'] as List<dynamic>?)?.map((e) => e as String).toList(),
  limit: (json['limit'] as num?)?.toInt(),
  offset: (json['offset'] as num?)?.toInt(),
  filters: json['filters'] as Map<String, dynamic>?,
  useSemanticSearch: json['useSemanticSearch'] as bool? ?? true,
);

Map<String, dynamic> _$KnowledgeSearchRequestToJson(
  KnowledgeSearchRequest instance,
) => <String, dynamic>{
  'query': instance.query,
  'categories': instance.categories,
  'tags': instance.tags,
  'type': _$KnowledgeItemTypeEnumMap[instance.type],
  'fields': instance.fields,
  'limit': instance.limit,
  'offset': instance.offset,
  'filters': instance.filters,
  'useSemanticSearch': instance.useSemanticSearch,
};

KnowledgeCategoryModel _$KnowledgeCategoryModelFromJson(
  Map<String, dynamic> json,
) => KnowledgeCategoryModel(
  id: json['id'] as String,
  name: json['name'] as String,
  description: json['description'] as String?,
  parentId: json['parentId'] as String?,
  itemCount: (json['itemCount'] as num?)?.toInt() ?? 0,
  metadata: json['metadata'] as Map<String, dynamic>?,
);

Map<String, dynamic> _$KnowledgeCategoryModelToJson(
  KnowledgeCategoryModel instance,
) => <String, dynamic>{
  'id': instance.id,
  'name': instance.name,
  'description': instance.description,
  'parentId': instance.parentId,
  'itemCount': instance.itemCount,
  'metadata': instance.metadata,
};
